#!/usr/bin/env python3
"""
detect.py
Real-time DDoS detection using the trained Random Forest model (5-class).
Captures live traffic in 1-second windows (same logic as feature_monitor.py),
builds the feature vector, and predicts the traffic type for each window.
"""

import os
import time
import joblib
import pandas as pd
from collections import Counter
from scapy.all import sniff, IP, TCP, UDP, ICMP

MODEL_PATH = "models/random_forest_multiclass.pkl"
LOG_PATH   = "data/detection_log_multiclass.csv"

# Label names — must match the labels used during training
LABEL_MAP = {
    0: "Normal",
    1: "SYN Flood",
    2: "UDP Flood",
    3: "ICMP Flood",
    4: "Port Scan",
    5: "TCP ACK Flood",
    6: "TCP RST Flood",
    7: "DNS Flood",
    8: "ARP Flood"
}

# Exact feature order the model was trained on
FEATURE_COLS = ['pps', 'bytes', 'tcp', 'udp', 'icmp', 'tcp_ratio', 'udp_ratio',
                'unique_ips', 'unique_ports', 'syn', 'ack', 'rst', 'fin', 'top_port']

print(f"[*] Loading model from {MODEL_PATH} ...")
model = joblib.load(MODEL_PATH)
print("[*] Model loaded. Starting live capture (Ctrl+C to stop)...\n")

# ── Per-second counters (mirrors feature_monitor.py) ───────────────────
packet_count = 0
bytes_count  = 0
tcp_count    = 0
udp_count    = 0
icmp_count   = 0
syn_count    = 0
ack_count    = 0
rst_count    = 0
fin_count    = 0
source_ips        = set()
destination_ports = set()
port_counter      = Counter()
last_time = time.time()

# ── Detection log (separate from training CSV) ──────────────────────────
def init_log():
    if not os.path.exists(LOG_PATH) or os.path.getsize(LOG_PATH) == 0:
        with open(LOG_PATH, "w") as f:
            f.write("timestamp,prediction,label_name,confidence,pps,unique_ports,rst,icmp,top_port\n")

def log_detection(ts, pred, label_name, conf, pps, unique_ports, rst, icmp, top_port):
    with open(LOG_PATH, "a") as f:
        f.write(f"{ts},{pred},{label_name},{conf:.4f},{pps},{unique_ports},{rst},{icmp},{top_port}\n")

init_log()

# ── Sustained-attack tracking ────────────────────────────────────────
# A single noisy second (misclassified or low-confidence) should not
# trigger a full alert. We only confirm an attack after this many
# consecutive high-confidence attack seconds in a row.
SUSTAIN_THRESHOLD   = 3
consecutive_streak  = 0
streak_labels       = []

def process(packet):
    global packet_count, bytes_count
    global tcp_count, udp_count, icmp_count
    global syn_count, ack_count, rst_count, fin_count
    global last_time
    global consecutive_streak, streak_labels

    packet_count += 1
    bytes_count  += len(packet)

    if TCP in packet:
        tcp_count += 1
        port_counter[packet[TCP].dport] += 1
        destination_ports.add(packet[TCP].dport)
        flags = packet[TCP].flags
        if flags & 0x02:  syn_count += 1
        if flags & 0x10:  ack_count += 1
        if flags & 0x04:  rst_count += 1
        if flags & 0x01:  fin_count += 1
    elif UDP in packet:
        udp_count += 1
        port_counter[packet[UDP].dport] += 1
        destination_ports.add(packet[UDP].dport)
    elif ICMP in packet:
        icmp_count += 1

    if IP in packet:
        source_ips.add(packet[IP].src)

    current_time = time.time()
    if current_time - last_time >= 1:
        total     = packet_count if packet_count > 0 else 1
        tcp_ratio = round(tcp_count / total, 4)
        udp_ratio = round(udp_count / total, 4)

        top_port_num = 0
        if port_counter:
            top_port_num = port_counter.most_common(1)[0][0]

        # ── Build feature row in exact training column order ────────
        features = pd.DataFrame([{
            "pps"          : packet_count,
            "bytes"        : bytes_count,
            "tcp"          : tcp_count,
            "udp"          : udp_count,
            "icmp"         : icmp_count,
            "tcp_ratio"    : tcp_ratio,
            "udp_ratio"    : udp_ratio,
            "unique_ips"   : len(source_ips),
            "unique_ports" : len(destination_ports),
            "syn"          : syn_count,
            "ack"          : ack_count,
            "rst"          : rst_count,
            "fin"          : fin_count,
            "top_port"     : top_port_num
        }])[FEATURE_COLS]

        prediction = model.predict(features)[0]
        confidence = model.predict_proba(features)[0].max()

        verdict = LABEL_MAP.get(prediction, f"Unknown({prediction})")

        # ── Confidence + sustained-attack alert level ───────────────
        # Never hides an attack prediction — only changes how urgent
        # the on-screen marker looks.
        #   Normal                          -> no marker
        #   Attack, confidence < threshold   -> Uncertain (streak resets)
        #   Attack, confidence >= threshold,
        #     but not enough in a row yet    -> Building (x/N)
        #   Attack, confidence >= threshold,
        #     N in a row reached             -> CONFIRMED ATTACK
        CONFIDENCE_THRESHOLD = 0.75

        if prediction == 0:
            consecutive_streak = 0
            streak_labels = []
            marker = ""
        elif confidence < CONFIDENCE_THRESHOLD:
            consecutive_streak = 0
            streak_labels = []
            marker = "  <<<< Uncertain"
        else:
            consecutive_streak += 1
            streak_labels.append(prediction)
            if consecutive_streak >= SUSTAIN_THRESHOLD:
                dominant_label = Counter(streak_labels).most_common(1)[0][0]
                dominant_name  = LABEL_MAP.get(dominant_label, str(dominant_label))
                marker = f"  <<<< CONFIRMED ATTACK ({dominant_name}, {consecutive_streak}s straight)"
            else:
                marker = f"  <<<< Building ({consecutive_streak}/{SUSTAIN_THRESHOLD})"

        print(
            f"PPS={packet_count:<5} UNIQUE_PORTS={len(destination_ports):<4} "
            f"SYN={syn_count:<4} RST={rst_count:<4} ICMP={icmp_count:<4} TOP_PORT={top_port_num:<6} "
            f"-> {verdict} ({confidence*100:.1f}%){marker}"
        )

        log_detection(round(current_time, 3), prediction, verdict, confidence,
                      packet_count, len(destination_ports), rst_count, icmp_count, top_port_num)

        # ── Reset counters for next window ────────────────────────────
        packet_count = 0
        bytes_count  = 0
        tcp_count    = 0
        udp_count    = 0
        icmp_count   = 0
        syn_count    = 0
        ack_count    = 0
        rst_count    = 0
        fin_count    = 0
        source_ips.clear()
        destination_ports.clear()
        port_counter.clear()
        last_time = current_time

try:
    sniff(prn=process, store=False, iface="eth0")
except KeyboardInterrupt:
    print("\n[*] Stopped.")
