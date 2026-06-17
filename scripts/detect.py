#!/usr/bin/env python3
"""
detect.py
Real-time DDoS detection using the trained Random Forest model.
Captures live traffic in 1-second windows (same logic as feature_monitor.py),
builds the feature vector, and predicts Normal/Attack for each window.
"""

import os
import time
import joblib
import pandas as pd
from collections import Counter
from scapy.all import sniff, IP, TCP, UDP

MODEL_PATH = "models/random_forest.pkl"
LOG_PATH   = "data/detection_log.csv"

# Exact feature order the model was trained on
FEATURE_COLS = ['pps', 'bytes', 'tcp', 'udp', 'tcp_ratio', 'udp_ratio',
                'unique_ips', 'unique_ports', 'ack', 'rst', 'fin', 'top_port']

print(f"[*] Loading model from {MODEL_PATH} ...")
model = joblib.load(MODEL_PATH)
print("[*] Model loaded. Starting live capture (Ctrl+C to stop)...\n")

# ── Per-second counters (mirrors feature_monitor.py) ───────────────────
packet_count = 0
bytes_count  = 0
tcp_count    = 0
udp_count    = 0
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
            f.write("timestamp,prediction,confidence,pps,unique_ports,rst,top_port\n")

def log_detection(ts, pred, conf, pps, unique_ports, rst, top_port):
    with open(LOG_PATH, "a") as f:
        f.write(f"{ts},{pred},{conf:.4f},{pps},{unique_ports},{rst},{top_port}\n")

init_log()

def process(packet):
    global packet_count, bytes_count
    global tcp_count, udp_count
    global syn_count, ack_count, rst_count, fin_count
    global last_time

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
            "tcp_ratio"    : tcp_ratio,
            "udp_ratio"    : udp_ratio,
            "unique_ips"   : len(source_ips),
            "unique_ports" : len(destination_ports),
            "ack"          : ack_count,
            "rst"          : rst_count,
            "fin"          : fin_count,
            "top_port"     : top_port_num
        }])[FEATURE_COLS]

        prediction = model.predict(features)[0]
        confidence = model.predict_proba(features)[0].max()

        verdict = "ATTACK" if prediction == 1 else "Normal"
        marker  = "  <<<< ALERT" if prediction == 1 else ""

        print(
            f"PPS={packet_count:<5} UNIQUE_PORTS={len(destination_ports):<4} "
            f"RST={rst_count:<4} TOP_PORT={top_port_num:<6} "
            f"-> {verdict} ({confidence*100:.1f}%){marker}"
        )

        log_detection(round(current_time, 3), prediction, confidence,
                      packet_count, len(destination_ports), rst_count, top_port_num)

        # ── Reset counters for next window ────────────────────────────
        packet_count = 0
        bytes_count  = 0
        tcp_count    = 0
        udp_count    = 0
        syn_count    = 0
        ack_count    = 0
        rst_count    = 0
        fin_count    = 0
        source_ips.clear()
        destination_ports.clear()
        port_counter.clear()
        last_time = current_time

try:
    sniff(prn=process, store=False, iface="lo")
except KeyboardInterrupt:
    print("\n[*] Stopped.")
