import csv
import os

CSV_PATH = "data/network_data.csv"

HEADERS = [
    "timestamp",
    "pps",
    "bytes",
    "tcp",
    "udp",
    "tcp_ratio",
    "udp_ratio",
    "unique_ips",
    "unique_ports",
    "syn",
    "ack",
    "rst",
    "fin",
    "top_port",
    "label"          # 0 = normal  |  1 = attack
]


def init_csv():
    """Create the CSV and write headers only if the file doesn't exist yet."""
    if not os.path.exists(CSV_PATH) or os.path.getsize(CSV_PATH) == 0:
        with open(CSV_PATH, "w", newline="") as f:
            csv.writer(f).writerow(HEADERS)


def log_row(features: dict):
    """Append one row to the CSV. Call once per second from feature_monitor."""
    with open(CSV_PATH, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([features.get(h, 0) for h in HEADERS])
