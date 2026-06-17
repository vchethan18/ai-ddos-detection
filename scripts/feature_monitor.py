from scapy.all import *
from collections import Counter
from csv_logger import init_csv, log_row
import time

# ── Init CSV on startup ─────────────────────────────────────────────
init_csv()

# ── Counters ────────────────────────────────────────────────────────
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


def process(packet):

    global packet_count, bytes_count
    global tcp_count, udp_count
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
            f"UNIQUE_IPS={len(source_ips)} | "
            f"UNIQUE_PORTS={len(destination_ports)} | "
            f"SYN={syn_count} | "
            f"ACK={ack_count} | "
            f"RST={rst_count} | "
            f"FIN={fin_count} | "
            f"TOP_PORT={top_port_str}"
        )

        # ── Log to CSV (machine readable) ──────────────────────────
        log_row({
            "timestamp"    : round(current_time, 3),
            "pps"          : packet_count,
            "bytes"        : bytes_count,
            "tcp"          : tcp_count,
            "udp"          : udp_count,
            "tcp_ratio"    : tcp_ratio,
            "udp_ratio"    : udp_ratio,
            "unique_ips"   : len(source_ips),
            "unique_ports" : len(destination_ports),
            "syn"          : syn_count,
            "ack"          : ack_count,
            "rst"          : rst_count,
            "fin"          : fin_count,
            "top_port"     : top_port_num,
            "label"        : 1              # default normal — change to 1 during attack capture
        })

        # ── Reset all counters ──────────────────────────────────────
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


sniff(prn=process)
