from scapy.all import *
from collections import Counter
from csv_logger import init_csv, log_row
import sys
import time

# ── Get label from command line ────────────────────────────────────
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

if len(sys.argv) != 2 or not sys.argv[1].isdigit() or int(sys.argv[1]) not in LABEL_MAP:
    print("Usage: sudo python3 feature_monitor.py <label>")
    print("Labels:")
    for k, v in LABEL_MAP.items():
        print(f"  {k} = {v}")
    sys.exit(1)

LABEL = int(sys.argv[1])
print(f"\n>>> Capturing with LABEL = {LABEL} ({LABEL_MAP[LABEL]}) <<<\n")

# ── Init CSV on startup ─────────────────────────────────────────────
init_csv()

# ── Counters ────────────────────────────────────────────────────────
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


def process(packet):

    global packet_count, bytes_count
    global tcp_count, udp_count, icmp_count
    global syn_count, ack_count, rst_count, fin_count
    global last_time

    packet_count += 1
    bytes_count  += len(packet)

    # ── TCP block ───────────────────────────────────────────────────
    if TCP in packet:

        tcp_count += 1
        port_counter[packet[TCP].dport] += 1
        destination_ports.add(packet[TCP].dport)

        flags = packet[TCP].flags

        if flags & 0x02:  syn_count += 1
        if flags & 0x10:  ack_count += 1
        if flags & 0x04:  rst_count += 1
        if flags & 0x01:  fin_count += 1

    # ── UDP block ───────────────────────────────────────────────────
    elif UDP in packet:

        udp_count += 1
        port_counter[packet[UDP].dport] += 1
        destination_ports.add(packet[UDP].dport)

    # ── ICMP block ──────────────────────────────────────────────────
    elif ICMP in packet:

        icmp_count += 1

    # ── Unique source IP tracking ───────────────────────────────────
    if IP in packet:
        source_ips.add(packet[IP].src)

    # ── 1-second reporting window ───────────────────────────────────
    current_time = time.time()

    if current_time - last_time >= 1:

        # ── Derived features (silent — CSV only) ───────────────────
        total     = packet_count if packet_count > 0 else 1
        tcp_ratio = round(tcp_count / total, 4)
        udp_ratio = round(udp_count / total, 4)

        top_port_str = "N/A"
        top_port_num = 0
        if port_counter:
            top_port     = port_counter.most_common(1)[0]
            top_port_num = top_port[0]
            top_port_str = f"{top_port[0]} ({top_port[1]})"

        # ── Terminal output (human readable) ───────────────────────
        print(
            f"PPS={packet_count} | "
            f"BYTES={bytes_count} | "
            f"TCP={tcp_count} | "
            f"UDP={udp_count} | "
            f"ICMP={icmp_count} | "
            f"UNIQUE_IPS={len(source_ips)} | "
            f"UNIQUE_PORTS={len(destination_ports)} | "
            f"SYN={syn_count} | "
            f"ACK={ack_count} | "
            f"RST={rst_count} | "
            f"FIN={fin_count} | "
            f"TOP_PORT={top_port_str} | "
            f"LABEL={LABEL}"
        )

        # ── Log to CSV (machine readable) ──────────────────────────
        log_row({
            "timestamp"    : round(current_time, 3),
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
            "top_port"     : top_port_num,
            "label"        : LABEL
        })

        # ── Reset all counters ──────────────────────────────────────
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


sniff(prn=process, iface="eth0")
