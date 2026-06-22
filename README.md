# AI-Powered DDoS Detection System

A real-time network intrusion detection system that captures live traffic, classifies it using a trained Random Forest model, and displays live threat intelligence on a web dashboard. Built on Kali Linux using a two-VM victim/attacker setup for realistic network traffic generation.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [System Architecture](#2-system-architecture)
3. [Attack Types Detected](#3-attack-types-detected)
4. [Project Structure](#4-project-structure)
5. [Environment Setup](#5-environment-setup)
6. [Step 1 — Collect Training Data](#6-step-1--collect-training-data)
7. [Step 2 — Train the Model](#7-step-2--train-the-model)
8. [Step 3 — Run Real-Time Detection](#8-step-3--run-real-time-detection)
9. [Step 4 — Run the Live Dashboard](#9-step-4--run-the-live-dashboard)
10. [Step 5 — Execute Attacks from the Attacker VM](#10-step-5--execute-attacks-from-the-attacker-vm)
11. [Understanding the Dashboard](#11-understanding-the-dashboard)
12. [Model Performance](#12-model-performance)
13. [Known Limitations](#13-known-limitations)
14. [Lessons Learned](#14-lessons-learned)
15. [Future Work](#15-future-work)
16. [Tech Stack](#16-tech-stack)

---

## 1. Project Overview

This system detects DDoS and network scanning attacks in real time using machine learning. It watches live network traffic one second at a time, extracts 14 statistical features per second (such as packet rate, TCP flag counts, unique port count, protocol ratios), and feeds them into a trained 9-class Random Forest classifier that outputs the current traffic type and a confidence percentage.

A single suspicious second does not immediately trigger an alert — the system waits for 3 consecutive high-confidence attack predictions before escalating to a **CONFIRMED ATTACK**, filtering out false alarms caused by legitimate bursty traffic.

Results are shown either as live terminal output (`detect.py`) or as a full web dashboard (`dashboard.py`) that updates every second in the browser.

---

## 2. System Architecture

```
[Attacker VM]
    |
    | hping3 / Scapy flood commands
    |
    v
[Victim VM — eth0 interface]
    |
    | Scapy packet capture (1-second windows)
    | feature_monitor.py / detect.py / dashboard.py
    |
    v
14 Statistical Features extracted per second:
  pps, bytes, tcp, udp, icmp,
  tcp_ratio, udp_ratio,
  unique_ips, unique_ports,
  syn, ack, rst, fin, top_port
    |
    v
Random Forest Classifier (9-class, ~99% accuracy)
    |
    v
Confidence Threshold (>= 75%)
    |
    v
Sustained-Attack Logic (3 consecutive seconds required)
    |
    v
  Normal / Building / Uncertain / CONFIRMED ATTACK
    |
    +----------------------+
    |                      |
Terminal output      Live Web Dashboard
(detect.py)          (dashboard.py → http://<victim-ip>:5000)
```

---

## 3. Attack Types Detected

| Label | Attack Type | Protocol | Key Signature |
|---|---|---|---|
| 0 | Normal | Mixed | Low PPS, mixed traffic |
| 1 | SYN Flood | TCP | High SYN + RST, many unique ports |
| 2 | UDP Flood | UDP | High UDP ratio, few ports |
| 3 | ICMP Flood | ICMP | ICMP count ≈ total PPS |
| 4 | Port Scan | TCP | High unique ports, SYN + RST spread across many ports |
| 5 | TCP ACK Flood | TCP | High ACK, RST (kernel reply), SYN = 0 |
| 6 | TCP RST Flood | TCP | RST ≈ total TCP, SYN = 0, ACK = 0 |
| 7 | DNS Flood | UDP | top_port = 53 |
| 8 | ARP Flood | ARP | High PPS, TCP = UDP = ICMP = 0 |

---

## 4. Project Structure

```
ai-ddos-detection/
├── scripts/
│   ├── feature_monitor.py        # Captures labeled traffic for training
│   ├── csv_logger.py             # CSV schema and row-writing logic
│   ├── train_model.py            # Trains, evaluates, and saves the model
│   ├── detect.py                 # Real-time detection with terminal output
│   └── dashboard.py              # Real-time detection with live web dashboard
├── data/
│   ├── network_data_multiclass.csv   # Labeled training dataset
│   ├── detection_log_multiclass.csv  # Log from detect.py sessions
│   └── dashboard_log.csv             # Per-second log from dashboard sessions
├── models/
│   ├── random_forest_multiclass.pkl          # Trained model
│   └── feature_importance_multiclass.png     # Feature importance bar chart
└── README.md
```

---

## 5. Environment Setup

### What you need

- Two Linux VMs (Kali Linux recommended for both)
- VirtualBox with both VMs set to **Bridged Adapter** networking
- Both VMs must be able to ping each other before starting

### VM roles

| VM | Role | IP (example) |
|---|---|---|
| VM 1 — Original Kali | Victim (runs all Python scripts) | 192.168.x.x |
| VM 2 — Cloned Kali | Attacker (runs hping3 only) | 192.168.x.x |

### Clone the attacker VM in VirtualBox

1. Shut down VM 1 fully
2. Right-click VM 1 in VirtualBox → **Clone**
3. Name it `Kali-Attacker`
4. Choose **Full Clone**
5. Select **Generate new MAC addresses for all network adapters**
6. Leave both checkboxes (Keep Disk Names, Keep Hardware UUIDs) **unticked**
7. Click **Clone** and wait

### Set both VMs to Bridged network

For each VM in VirtualBox: **Settings → Network → Adapter 1 → Attached to: Bridged Adapter**

### Confirm connectivity

Boot both VMs. On the attacker VM:
```bash
ping 192.168.0.x
```
You should see replies with 0% packet loss before going any further.

### Install Python dependencies (victim VM only)

```bash
cd ~/ai-ddos-detection
python3 -m venv venv
source venv/bin/activate
pip install scapy pandas scikit-learn matplotlib joblib flask
```

> **Important:** Always run scripts using the full venv path — never just `python3`. The `sudo` requirement for packet capture bypasses venv activation, so the explicit path is the only safe way:
> ```
> sudo /home/kali/ai-ddos-detection/venv/bin/python3 scripts/<script>.py
> ```

---

## 6. Step 1 — Collect Training Data

The `feature_monitor.py` script captures live traffic and writes labeled rows to `data/network_data_multiclass.csv`. The label is passed as a command-line argument — this prevents silent mislabeling.

### Run the capture (victim VM)

```bash
sudo /home/kali/ai-ddos-detection/venv/bin/python3 scripts/feature_monitor.py <label>
```

Available labels:
```
0 = Normal
1 = SYN Flood
2 = UDP Flood
3 = ICMP Flood
4 = Port Scan
5 = TCP ACK Flood
6 = TCP RST Flood
7 = DNS Flood
8 = ARP Flood
```

### What you'll see while it runs

```
>>> Capturing with LABEL = 1 (SYN Flood) <<<

PPS=3412 | TCP=3412 | UDP=0 | ICMP=0 | SYN=2265 | ACK=1147 | RST=1147 | LABEL=1
PPS=1882 | TCP=1876 | UDP=2  | ICMP=0 | SYN=938  | ACK=938  | RST=938  | LABEL=1
```

### Capture schedule

Run each label separately. Recommended duration: **60–90 seconds per type**, with the matching attack running on the attacker VM at the same time.

| Label | Type | Victim command | Attacker command |
|---|---|---|---|
| 0 | Normal | `feature_monitor.py 0` | — (nothing, just idle traffic) |
| 1 | SYN Flood | `feature_monitor.py 1` | see Step 5 |
| 2 | UDP Flood | `feature_monitor.py 2` | see Step 5 |
| 3 | ICMP Flood | `feature_monitor.py 3` | see Step 5 |
| 4 | Port Scan | `feature_monitor.py 4` | see Step 5 |
| 5 | TCP ACK Flood | `feature_monitor.py 5` | see Step 5 |
| 6 | TCP RST Flood | `feature_monitor.py 6` | see Step 5 |
| 7 | DNS Flood | `feature_monitor.py 7` | see Step 5 |
| 8 | ARP Flood | `feature_monitor.py 8` | see Step 5 |

### Check your dataset after collecting all classes

```bash
sudo chown kali:kali data/network_data_multiclass.csv
python3 -c "
import pandas as pd
df = pd.read_csv('data/network_data_multiclass.csv')
print(df['label'].value_counts().sort_index())
"
```

Aim for at least **70+ rows per class** before training.

---

## 7. Step 2 — Train the Model

```bash
/home/kali/ai-ddos-detection/venv/bin/python3 scripts/train_model.py
```

This will:
- Load `data/network_data_multiclass.csv`
- Print row counts per class
- Split 80% train / 20% test (stratified)
- Train a Random Forest (100 trees, class-balanced)
- Print accuracy, full confusion matrix, and classification report
- Print feature importance rankings with a bar chart
- Save the model to `models/random_forest_multiclass.pkl`

### Example output

```
[1] Loading dataset...
    Total rows : 1417
    Normal        (0) : 130
    SYN Flood     (1) : 124
    ...
    ARP Flood     (8) : 148

[4] Evaluating...
    Accuracy : 98.94%

[5] Feature Importance:
    top_port        0.1673  ████████
    syn             0.1160  █████
    pps             0.1031  █████
    ...
```

---

## 8. Step 3 — Run Real-Time Detection

For terminal-based detection (no browser needed):

```bash
sudo /home/kali/ai-ddos-detection/venv/bin/python3 scripts/detect.py
```

### What you'll see

```
PPS=3301  UNIQUE_PORTS=926   SYN=2376  RST=925   ICMP=0  -> SYN Flood (81.0%)  <<<< Building (1/3)
PPS=3352  UNIQUE_PORTS=936   SYN=2417  RST=935   ICMP=0  -> SYN Flood (82.0%)  <<<< Building (2/3)
PPS=2841  UNIQUE_PORTS=775   SYN=2066  RST=774   ICMP=0  -> SYN Flood (80.0%)  <<<< CONFIRMED ATTACK (SYN Flood, 3s straight)
PPS=1545  UNIQUE_PORTS=614   SYN=932   RST=613   ICMP=0  -> SYN Flood (90.0%)  <<<< CONFIRMED ATTACK (SYN Flood, 4s straight)
```

### Alert levels explained

| Marker | Meaning |
|---|---|
| *(none)* | Normal traffic |
| `<<<< Uncertain` | Attack predicted but confidence < 75% — possible, not confirmed |
| `<<<< Building (x/3)` | Attack predicted at ≥ 75% confidence — waiting for 3 in a row |
| `<<<< CONFIRMED ATTACK` | 3+ consecutive high-confidence attack seconds — real threat |

All detections are logged to `data/detection_log_multiclass.csv`.

Stop at any time with `Ctrl+C`.

---

## 10. Step 5 — Execute Attacks from the Attacker VM

Run these on the **attacker VM** while `feature_monitor.py` or `detect.py` or `dashboard.py` is running on the victim. Replace `192.168.x.x` with your actual victim IP.

### SYN Flood
```bash
sudo hping3 -S 192.168.x.x -p 80 --flood
```

### UDP Flood
```bash
sudo hping3 --udp 192.168.x.x -p 80 --flood
```

### ICMP Flood
```bash
sudo hping3 --icmp 192.168.x.x --flood
```

### Port Scan
```bash
sudo hping3 --scan 1-65535 -S 192.168.x.x
```
*(Finishes on its own — no need to Ctrl+C. Run 2–3 times to build up enough rows.)*

### TCP ACK Flood
```bash
sudo hping3 -A 192.168.x.x -p 80 --flood
```

### TCP RST Flood
```bash
sudo hping3 -R 192.168.x.x -p 80 --flood
```

### DNS Flood
```bash
sudo hping3 --udp 192.168.x.x -p 53 --flood
```

### ARP Flood
ARP is not an IP-based protocol — `hping3` cannot generate it. Use Scapy instead (already installed as part of this project):

```bash
sudo /home/kali/ai-ddos-detection/venv/bin/python3 -c "
from scapy.all import ARP, Ether, sendp
pkt = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst='192.168.x.x')
sendp(pkt, iface='eth0', loop=1, inter=0.0001, verbose=False)
"
```
Press `Ctrl+C` to stop.

---

## 9. Step 4 — Run the Live Dashboard

The dashboard runs the exact same detection logic as `detect.py` in the background, but instead of printing to the terminal, it serves a live webpage that updates every second.

```bash
sudo /home/kali/ai-ddos-detection/venv/bin/python3 scripts/dashboard.py
```

Then open in any browser (from the victim VM itself, or from another machine on the same network):

```
http://192.168.x.x:5000
```

---

## 11. Understanding the Dashboard

### Status card (top-left, large)

Changes color based on what's currently happening:

| Color | Meaning |
|---|---|
| 🟢 Green | Normal traffic |
| 🟡 Yellow | Building — attack detected, waiting for confirmation |
| 🟠 Orange | Uncertain — low-confidence prediction, not enough to alert |
| 🔴 Red | CONFIRMED ATTACK — 3+ consecutive seconds, sustained threat |

When an attack is confirmed, the card **flashes red and plays a beep** through the browser. This happens once per new attack episode, not every second.

### Metric cards

| Card | What it shows |
|---|---|
| Packets / sec | Raw packet count received in the last second |
| Confidence | How certain the model is about its current prediction (0–100%) |
| Severity | Low / Medium / High based on packet rate (< 800 / 800–3000 / 3000+ pps) |
| Threat Score | Composite 0–100 gauge combining confidence + severity + streak duration |
| Attacker IP | Source IP sending the most packets this second |
| Distinct Attacker IPs | How many unique source IPs contributed during the current confirmed attack (> 1 means distributed) |
| Top Port | The destination port receiving the most traffic this second |
| Confirmed Attacks | Total number of distinct confirmed attack episodes since the dashboard started |

### Live traffic chart

A line chart showing the last 30 seconds of packets/sec. Each dot on the chart is color-coded by attack type:

| Color | Attack type |
|---|---|
| 🟢 Green | Normal |
| 🔵 Blue | SYN Flood |
| 🟣 Purple | UDP Flood |
| 🟠 Orange | ICMP Flood |
| 🩷 Pink | Port Scan |
| 🩵 Teal | TCP ACK Flood |
| 🔴 Red | TCP RST Flood |
| 💠 Cyan | DNS Flood |
| 🟡 Amber | ARP Flood |

**Hover over any point** on the chart to see a tooltip showing that second's attack type, PPS, severity, and attacker IP.

### Attack Type Breakdown panel

Shows how many seconds of each traffic type have been seen in this session, as a color-coded bar chart. Builds up live as the session progresses.

### Alert History panel

Lists every confirmed attack episode that has ended, in reverse chronological order:

```
SYN Flood          from 192.168.0.105  · 1 source
                   High    14:32:07   · 6.2s
```

Each entry shows: attack type, attacker IP, severity badge, time it started, and how long it lasted.

### Live Network Map

An animated SVG diagram showing the victim node in the centre and any active attacker IP nodes orbiting around it. Lines pulse in the color of the current attack type when an attack is confirmed, and go dark/quiet when traffic returns to normal.

### Download Session Log

A button at the bottom downloads `data/dashboard_log.csv` directly from the browser — a complete per-second record of every classification since the dashboard started, including label, status, confidence, severity, threat score, attacker IP, and all traffic counters.

---

## 12. Model Performance

Trained on 1,417 labeled samples (9 classes). Tested on held-out 20% split:

```
Accuracy: 98.94%

               precision  recall  f1-score
Normal           0.96      0.96      0.96
SYN Flood        0.96      0.96      0.96
UDP Flood        1.00      0.93      0.96
ICMP Flood       1.00      1.00      1.00
Port Scan        1.00      1.00      1.00
TCP ACK Flood    1.00      1.00      1.00
TCP RST Flood    1.00      1.00      1.00
DNS Flood        0.97      1.00      0.98
ARP Flood        1.00      1.00      1.00
```

**Top features by importance:**
1. `top_port` — 0.1673
2. `syn` — 0.1160
3. `pps` — 0.1031

> Note: `fin` has 0.0 importance across all runs — included in the feature set for completeness but contributes nothing to classification.

---

## 13. Known Limitations

- **Single-source testing.** All attacks were generated from one attacker VM, so all captured data reflects a single-source DoS, not a true multi-source DDoS. The distributed-attack indicator is built in but has not been validated against genuinely multi-source traffic.
- **DNS Flood vs UDP Flood** overlap slightly since both are UDP floods differentiated mainly by destination port. A real attacker using non-standard ports could blur this.
- **Geolocation not implemented.** All attacker IPs are private LAN addresses (`192.168.x.x`), which have no meaningful public geolocation database entry.
- **Not implemented (out of scope):** DNS/NTP amplification (requires open resolver VM + IP spoofing), Slowloris (application-layer, low-and-slow, requires completely different features), Smurf Attack (broadcast ping amplification, blocked by default on all modern OS stacks since the late 1990s).

---

## 14. Lessons Learned

**Loopback produces misleading training data.** Early testing sent attacks to `127.0.0.1`. The kernel replies to its own SYN packets immediately, generating RST/ACK responses that suppress the raw `syn` count. Switching to a real two-VM bridged network restored `syn` as the second most important feature in the final model.

**Label contamination is silent and dangerous.** An early version had `label=1` hardcoded in the capture script. Idle traffic during idle periods was quietly labeled as "attack," creating data where Normal-looking rows were marked as SYN Flood. Fixed by requiring an explicit CLI argument, rejecting any call without one.

**Test-set accuracy doesn't prove generalization.** After adding TCP ACK Flood, the model scored 100% on the test set. But live testing on port 22 — a port never used during training — revealed confidence had dropped to 59–70%, effectively making the class undetectable on any realistic attacker who chose a different port. The fix was recapturing ACK Flood traffic across multiple ports (80, 443, 8080), after which confidence on the never-seen port 22 jumped to 94–98%.

**Wrong CSV path is a silent, painful bug.** The capture script writes rows only to the file name in `csv_logger.py`. An old copy of the file with the wrong path caused multiple complete capture sessions to land in a different file with mismatched column headers — total loss, not partially salvageable.

---

## 15. Future Work

- **Automatic mitigation** — `iptables`-based auto-blocking of confirmed attacker IPs when an attack is sustained
- **Multi-source DDoS validation** — test the distributed-attack indicator against traffic from multiple attacker VMs simultaneously
- **Persistent alert storage** — save the alert history to SQLite instead of in-memory storage, so it survives dashboard restarts
- **HTTP Flood detection** — requires application-layer features (request rate, URL patterns) that don't fit the current network-layer feature set

---

## 16. Tech Stack

| Component | Tool |
|---|---|
| Packet capture | Scapy |
| ML model | scikit-learn (Random Forest) |
| Data handling | pandas |
| Web dashboard | Flask |
| Attack generation | hping3 / Scapy |
| Platform | Kali Linux |
| Virtualisation | VirtualBox (bridged networking) |
| Version control | Git + GitHub |

---

*Project developed for academic purposes. Attack commands should only be run in a controlled private lab environment against machines you own.*
