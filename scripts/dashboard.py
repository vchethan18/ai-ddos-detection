#!/usr/bin/env python3
"""
dashboard.py
Live web dashboard for the DDoS detection system.
Same capture + prediction + sustained-attack logic as detect.py,
but serves results on a live-updating webpage instead of the terminal.

Features:
  - Real-time status, PPS, confidence, top port
  - Severity levels (Low / Medium / High) based on traffic volume
  - Composite Threat Score (0-100) combining confidence, severity, and streak
  - Attacker IP tracking, with a distinct-IP count to flag distributed attacks
  - Distinct colors per attack type, separate from urgency colors
  - Hover over the chart to see details for that exact second
  - Live mini network map (Victim <-> Attacker nodes)
  - Every second is permanently logged to data/dashboard_log.csv
  - Downloadable session log button
  - Alert history of past confirmed attacks (type, time, duration, IP, severity)

Run:
    sudo /home/kali/ai-ddos-detection/venv/bin/python3 scripts/dashboard.py

Then open in a browser:
    http://<victim-ip>:5000
"""

import os
import time
import threading
import joblib
import pandas as pd
from collections import Counter, deque
from scapy.all import sniff, IP, TCP, UDP, ICMP
from flask import Flask, jsonify, render_template_string, send_file

MODEL_PATH = "models/random_forest_multiclass.pkl"
LOG_PATH   = "data/dashboard_log.csv"
IFACE      = "eth0"

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

FEATURE_COLS = ['pps', 'bytes', 'tcp', 'udp', 'icmp', 'tcp_ratio', 'udp_ratio',
                'unique_ips', 'unique_ports', 'syn', 'ack', 'rst', 'fin', 'top_port']

CONFIDENCE_THRESHOLD = 0.75
SUSTAIN_THRESHOLD    = 3

print(f"[*] Loading model from {MODEL_PATH} ...")
model = joblib.load(MODEL_PATH)
print("[*] Model loaded.")


# ── Persistent log — every second, not just confirmed attacks ──────────
def init_log():
    if not os.path.exists(LOG_PATH) or os.path.getsize(LOG_PATH) == 0:
        with open(LOG_PATH, "w") as f:
            f.write("timestamp,label,status,confidence,severity,threat_score,pps,"
                     "unique_ports,syn,rst,icmp,top_port,top_ip\n")

def log_row(ts, label, status, confidence, severity, threat_score, pps, unique_ports,
            syn, rst, icmp, top_port, top_ip):
    with open(LOG_PATH, "a") as f:
        f.write(f"{ts},{label},{status},{confidence:.1f},{severity},{threat_score},{pps},"
                f"{unique_ports},{syn},{rst},{icmp},{top_port},{top_ip}\n")

init_log()


def get_severity(pps, status):
    """Simple volume-based severity. Only meaningful once traffic isn't Normal."""
    if status == "Normal":
        return "—"
    if pps >= 3000:
        return "High"
    elif pps >= 800:
        return "Medium"
    else:
        return "Low"


def get_threat_score(status, severity, confidence_pct, streak):
    """Composite 0-100 score combining how confident, how severe, and how
    sustained the current traffic looks. Modeled loosely on how real
    SOC tools collapse multiple signals into one number."""
    if status == "Normal":
        return 0
    severity_weight = {"Low": 30, "Medium": 60, "High": 90, "—": 0}.get(severity, 0)
    conf_factor  = confidence_pct / 100.0
    streak_bonus = min(streak * 4, 20) if status == "Confirmed" else 0
    score = severity_weight * conf_factor + streak_bonus
    if status == "Uncertain":
        score *= 0.5
    return min(round(score), 100)


# ── Shared state between sniff thread and Flask thread ─────────────────
state_lock = threading.Lock()
state = {
    "status"             : "Starting...",   # Normal | Uncertain | Building | Confirmed
    "label"              : "Normal",
    "confidence"         : 0.0,
    "severity"           : "—",
    "threat_score"       : 0,
    "pps"                : 0,
    "unique_ports"       : 0,
    "syn"                : 0,
    "rst"                : 0,
    "icmp"               : 0,
    "top_port"           : 0,
    "top_ip"             : "—",
    "streak"             : 0,
    "attack_events"      : 0,     # number of distinct sustained attacks seen
    "distinct_attackers" : 0,     # unique source IPs seen during the active confirmed episode
    "attacker_ips"       : [],    # those IPs, for the network map (capped to 6)
    "history"            : deque(maxlen=30),
    "alert_log"          : deque(maxlen=20),
    "class_counts"       : {name: 0 for name in LABEL_MAP.values()},
}

# ── Per-second counters (mirrors detect.py) ─────────────────────────────
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
source_ip_counter = Counter()
last_time = time.time()

consecutive_streak = 0
streak_labels       = []
prev_confirmed       = False
episode_start_time   = None
episode_type         = None
episode_ip_counter   = Counter()   # source IPs seen during the current confirmed episode
episode_peak_pps     = 0


def finalize_episode(end_time):
    """Called when a confirmed attack episode ends. Logs it to the alert history."""
    global episode_start_time, episode_type, episode_ip_counter, episode_peak_pps
    if episode_start_time is None:
        return
    duration = round(end_time - episode_start_time, 1)
    attacker_ip = episode_ip_counter.most_common(1)[0][0] if episode_ip_counter else "N/A"
    severity    = get_severity(episode_peak_pps, "Confirmed")
    entry = {
        "type"         : episode_type,
        "time"         : time.strftime("%H:%M:%S", time.localtime(episode_start_time)),
        "duration"     : duration,
        "ip"           : attacker_ip,
        "severity"     : severity,
        "distinct_ips" : len(episode_ip_counter),
    }
    with state_lock:
        state["alert_log"].appendleft(entry)
    episode_start_time = None
    episode_type = None
    episode_ip_counter = Counter()
    episode_peak_pps = 0


def process(packet):
    global packet_count, bytes_count
    global tcp_count, udp_count, icmp_count
    global syn_count, ack_count, rst_count, fin_count
    global last_time
    global consecutive_streak, streak_labels, prev_confirmed
    global episode_start_time, episode_type, episode_ip_counter, episode_peak_pps

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
        source_ip_counter[packet[IP].src] += 1

    current_time = time.time()
    if current_time - last_time >= 1:
        total     = packet_count if packet_count > 0 else 1
        tcp_ratio = round(tcp_count / total, 4)
        udp_ratio = round(udp_count / total, 4)

        top_port_num = 0
        if port_counter:
            top_port_num = port_counter.most_common(1)[0][0]

        top_ip = "—"
        if source_ip_counter:
            top_ip = source_ip_counter.most_common(1)[0][0]

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
        verdict    = LABEL_MAP.get(prediction, f"Unknown({prediction})")

        # ── Sustained-attack logic (same as detect.py) ──────────────
        if prediction == 0:
            if prev_confirmed:
                finalize_episode(current_time)
            consecutive_streak = 0
            streak_labels = []
            status = "Normal"
            prev_confirmed = False
        elif confidence < CONFIDENCE_THRESHOLD:
            if prev_confirmed:
                finalize_episode(current_time)
            consecutive_streak = 0
            streak_labels = []
            status = "Uncertain"
            prev_confirmed = False
        else:
            consecutive_streak += 1
            streak_labels.append(prediction)
            if consecutive_streak >= SUSTAIN_THRESHOLD:
                dominant_label = Counter(streak_labels).most_common(1)[0][0]
                verdict = LABEL_MAP.get(dominant_label, str(dominant_label))
                status  = "Confirmed"
                if not prev_confirmed:
                    episode_start_time = current_time
                    episode_type = verdict
                    with state_lock:
                        state["attack_events"] += 1
                    prev_confirmed = True
            else:
                status = "Building"

        # ── Track attacker IPs + peak volume for the active episode ─
        distinct_attackers = 0
        attacker_ips_list  = []
        if status == "Confirmed":
            episode_ip_counter.update(source_ip_counter)
            episode_peak_pps = max(episode_peak_pps, packet_count)
            distinct_attackers = len(episode_ip_counter)
            attacker_ips_list  = list(episode_ip_counter.keys())[:6]

        severity     = get_severity(packet_count, status)
        threat_score = get_threat_score(status, severity, confidence * 100, consecutive_streak)

        with state_lock:
            state["status"]             = status
            state["label"]              = verdict
            state["confidence"]         = round(confidence * 100, 1)
            state["severity"]           = severity
            state["threat_score"]       = threat_score
            state["pps"]                = packet_count
            state["unique_ports"]       = len(destination_ports)
            state["syn"]                = syn_count
            state["rst"]                = rst_count
            state["icmp"]               = icmp_count
            state["top_port"]           = top_port_num
            state["top_ip"]             = top_ip
            state["streak"]             = consecutive_streak
            state["distinct_attackers"] = distinct_attackers
            state["attacker_ips"]       = attacker_ips_list
            state["history"].append({
                "pps": packet_count, "label": verdict, "status": status,
                "severity": severity, "top_ip": top_ip
            })
            state["class_counts"][verdict] = state["class_counts"].get(verdict, 0) + 1

        log_row(round(current_time, 3), verdict, status, confidence * 100, severity,
                threat_score, packet_count, len(destination_ports), syn_count, rst_count,
                icmp_count, top_port_num, top_ip)

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
        source_ip_counter.clear()
        last_time = current_time


def start_sniffing():
    sniff(prn=process, store=False, iface=IFACE)


# ── Flask app ────────────────────────────────────────────────────────
app = Flask(__name__)

PAGE = """
<!DOCTYPE html>
<html>
<head>
<title>DDoS Detection Dashboard</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root { --normal:#16a34a; --building:#eab308; --uncertain:#f97316; --confirmed:#dc2626; }
  body { background:#0f172a; color:#e2e8f0; font-family:'Segoe UI',Arial,sans-serif; margin:0; padding:24px; }
  h1 { font-size:20px; font-weight:600; margin-bottom:4px; }
  .sub { color:#94a3b8; font-size:13px; margin-bottom:24px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:14px; margin-bottom:20px; }
  .card { background:#1e293b; border-radius:10px; padding:16px 18px; border:1px solid #334155; }
  .card .label { font-size:12px; color:#94a3b8; text-transform:uppercase; letter-spacing:0.5px; }
  .card .value { font-size:24px; font-weight:700; margin-top:6px; }
  #statusCard { grid-column:span 2; transition:background 0.3s; }
  #statusCard .value { font-size:28px; }
  .gauge-wrap { display:flex; align-items:center; justify-content:center; margin-top:4px; }
  canvas { background:#1e293b; border-radius:10px; border:1px solid #334155; width:100%; height:160px; cursor:crosshair; }
  .footer { color:#475569; font-size:12px; margin-top:16px; }
  .panels { display:grid; grid-template-columns:1fr 1fr; gap:14px; margin-top:20px; }
  @media (max-width:700px) { .panels { grid-template-columns:1fr; } }
  .panel { background:#1e293b; border-radius:10px; padding:16px 18px; border:1px solid #334155; }
  .panel h2 { font-size:12px; color:#94a3b8; text-transform:uppercase; letter-spacing:0.5px; margin:0 0 12px 0; }
  .bar-row { display:flex; align-items:center; gap:8px; margin-bottom:8px; font-size:13px; }
  .bar-row .bar-label { width:80px; flex-shrink:0; color:#cbd5e1; }
  .bar-row .bar-track { flex:1; background:#0f172a; border-radius:4px; height:10px; overflow:hidden; }
  .bar-row .bar-fill { height:100%; }
  .bar-row .bar-count { width:36px; text-align:right; color:#94a3b8; }
  .alert-row { display:flex; justify-content:space-between; align-items:center; font-size:13px; padding:8px 0; border-bottom:1px solid #334155; gap:8px; }
  .alert-row:last-child { border-bottom:none; }
  .alert-type { font-weight:600; }
  .alert-meta { color:#64748b; font-size:12px; }
  .severity-badge { font-size:11px; font-weight:600; padding:2px 7px; border-radius:4px; color:#0f172a; margin-right:6px; }
  .empty-note { color:#64748b; font-size:13px; }
  .tooltip { position:fixed; display:none; background:#0f172a; border:1px solid #475569; border-radius:6px;
             padding:8px 10px; font-size:12px; line-height:1.5; pointer-events:none; z-index:50; box-shadow:0 4px 12px rgba(0,0,0,0.4); }
  .map-panel { margin-top:14px; }
  .pulse-line { stroke-dasharray:6 4; animation:dashmove 1s linear infinite; }
  @keyframes dashmove { to { stroke-dashoffset:-20; } }
  .node-label { font-size:10px; fill:#94a3b8; }
  .dl-button { display:inline-block; margin-top:14px; background:#1e293b; border:1px solid #334155; color:#38bdf8;
               padding:9px 16px; border-radius:8px; font-size:13px; text-decoration:none; }
  .dl-button:hover { border-color:#38bdf8; }
  @keyframes pulseFlash {
    0%   { box-shadow:0 0 0 0 rgba(220,38,38,0.7); }
    70%  { box-shadow:0 0 0 18px rgba(220,38,38,0); }
    100% { box-shadow:0 0 0 0 rgba(220,38,38,0); }
  }
  .flash { animation:pulseFlash 0.8s ease-out 2; }
</style>
</head>
<body>
  <h1>DDoS Detection — Live Dashboard</h1>
  <div class="sub">Real-time traffic classification (5-class Random Forest) &middot; hover the chart for second-by-second detail</div>

  <div class="grid">
    <div class="card" id="statusCard">
      <div class="label">Current Status</div>
      <div class="value" id="status">--</div>
    </div>
    <div class="card">
      <div class="label">Packets / sec</div>
      <div class="value" id="pps">0</div>
    </div>
    <div class="card">
      <div class="label">Confidence</div>
      <div class="value" id="confidence">0%</div>
    </div>
    <div class="card">
      <div class="label">Severity</div>
      <div class="value" id="severity">--</div>
    </div>
    <div class="card">
      <div class="label">Threat Score</div>
      <div class="gauge-wrap">
        <svg width="90" height="90" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r="50" stroke="#334155" stroke-width="10" fill="none"/>
          <circle id="threatArc" cx="60" cy="60" r="50" stroke="#16a34a" stroke-width="10" fill="none"
                  stroke-dasharray="314.16" stroke-dashoffset="314.16" stroke-linecap="round" transform="rotate(-90 60 60)"/>
          <text id="threatText" x="60" y="68" text-anchor="middle" font-size="26" fill="#e2e8f0" font-weight="700">0</text>
        </svg>
      </div>
    </div>
    <div class="card">
      <div class="label">Attacker IP</div>
      <div class="value" id="attackerIp" style="font-size:18px;">--</div>
    </div>
    <div class="card">
      <div class="label">Distinct Attacker IPs</div>
      <div class="value" id="distinctIps">--</div>
    </div>
    <div class="card">
      <div class="label">Top Port</div>
      <div class="value" id="topPort">--</div>
    </div>
    <div class="card">
      <div class="label">Confirmed Attacks</div>
      <div class="value" id="attackEvents">0</div>
    </div>
  </div>

  <canvas id="chart" width="900" height="160"></canvas>

  <div class="panels">
    <div class="panel">
      <h2>Attack Type Breakdown (this session)</h2>
      <div id="breakdown"></div>
    </div>
    <div class="panel">
      <h2>Alert History</h2>
      <div id="alertLog"><div class="empty-note">No confirmed attacks yet.</div></div>
    </div>
  </div>

  <div class="panel map-panel">
    <h2>Live Network Map</h2>
    <svg id="networkMap" width="100%" height="220" viewBox="0 0 600 220"></svg>
  </div>

  <a href="/download-log" class="dl-button" download>⬇ Download Full Session Log (CSV)</a>
  <div class="footer">Auto-refreshing every second &middot; eth0 &middot; full per-second log saved to data/dashboard_log.csv</div>

  <div id="tooltip" class="tooltip"></div>

<script>
const STATUS_COLORS = { Normal:"#16a34a", Building:"#eab308", Uncertain:"#f97316", Confirmed:"#dc2626" };
const TYPE_COLORS = {
  "Normal"        : "#16a34a",
  "SYN Flood"     : "#3b82f6",
  "UDP Flood"     : "#a855f7",
  "ICMP Flood"    : "#f97316",
  "Port Scan"     : "#ec4899",
  "TCP ACK Flood" : "#14b8a6",
  "TCP RST Flood" : "#f43f5e",
  "DNS Flood"     : "#06b6d4",
  "ARP Flood"     : "#f59e0b"
};
const SEVERITY_COLORS = { "Low":"#84cc16", "Medium":"#f59e0b", "High":"#dc2626", "—":"#64748b" };

let lastAttackEvents = null;
let currentHistory = [];

function beep() {
  const ctx = new (window.AudioContext || window.webkitAudioContext)();
  [880, 1040].forEach((freq, i) => {
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.frequency.value = freq;
    osc.connect(gain);
    gain.connect(ctx.destination);
    gain.gain.setValueAtTime(0.15, ctx.currentTime);
    const startAt = ctx.currentTime + i * 0.18;
    osc.start(startAt);
    osc.stop(startAt + 0.15);
  });
}

async function refresh() {
  const res = await fetch('/api/status');
  const d = await res.json();

  document.getElementById('status').textContent =
    d.status === 'Confirmed' ? d.label + ' (' + d.streak + 's straight)' :
    d.status === 'Building'  ? d.label + ' — building (' + d.streak + '/3)' :
    d.status === 'Uncertain' ? d.label + ' — uncertain' : 'Normal';

  document.getElementById('pps').textContent = d.pps;
  document.getElementById('confidence').textContent = d.confidence + '%';
  document.getElementById('severity').textContent = d.severity;
  document.getElementById('attackerIp').textContent = d.status === 'Normal' ? '--' : d.top_ip;
  document.getElementById('distinctIps').textContent = d.status === 'Confirmed' ? d.distinct_attackers : '--';
  document.getElementById('topPort').textContent = d.top_port || '--';
  document.getElementById('attackEvents').textContent = d.attack_events;

  const statusCard = document.getElementById('statusCard');
  statusCard.style.background = STATUS_COLORS[d.status] || '#1e293b';

  if (lastAttackEvents !== null && d.attack_events > lastAttackEvents) {
    statusCard.classList.remove('flash');
    void statusCard.offsetWidth;
    statusCard.classList.add('flash');
    beep();
  }
  lastAttackEvents = d.attack_events;

  currentHistory = d.history;
  drawChart(currentHistory);
  renderBreakdown(d.class_counts);
  renderAlertLog(d.alert_log);
  updateThreatGauge(d.threat_score);
  renderNetworkMap(d.attacker_ips, d.status, d.label);
}

function updateThreatGauge(score) {
  const circumference = 314.16;
  const offset = circumference - (score / 100) * circumference;
  const arc = document.getElementById('threatArc');
  arc.style.strokeDashoffset = offset;
  let color = '#16a34a';
  if (score >= 80) color = '#dc2626';
  else if (score >= 60) color = '#f97316';
  else if (score >= 30) color = '#eab308';
  arc.style.stroke = color;
  document.getElementById('threatText').textContent = score;
}

function renderBreakdown(counts) {
  const el = document.getElementById('breakdown');
  const total = Object.values(counts).reduce((a, b) => a + b, 0) || 1;
  el.innerHTML = Object.entries(counts).map(([name, count]) => {
    const pct = Math.round((count / total) * 100);
    return `<div class="bar-row">
      <div class="bar-label">${name}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${pct}%; background:${TYPE_COLORS[name] || '#38bdf8'}"></div></div>
      <div class="bar-count">${count}</div>
    </div>`;
  }).join('');
}

function renderAlertLog(log) {
  const el = document.getElementById('alertLog');
  if (!log.length) {
    el.innerHTML = '<div class="empty-note">No confirmed attacks yet.</div>';
    return;
  }
  el.innerHTML = log.map(a => {
    const distTag = a.distinct_ips > 1
      ? `<span class="alert-meta">&middot; ${a.distinct_ips} sources (distributed)</span>`
      : `<span class="alert-meta">&middot; 1 source</span>`;
    return `<div class="alert-row">
      <div>
        <span class="alert-type" style="color:${TYPE_COLORS[a.type] || '#f87171'}">${a.type}</span><br>
        <span class="alert-meta">from ${a.ip}</span> ${distTag}
      </div>
      <div style="text-align:right">
        <span class="severity-badge" style="background:${SEVERITY_COLORS[a.severity] || '#64748b'}">${a.severity}</span><br>
        <span class="alert-meta">${a.time} &middot; ${a.duration}s</span>
      </div>
    </div>`;
  }).join('');
}

function renderNetworkMap(ips, status, label) {
  const svg = document.getElementById('networkMap');
  const cx = 300, cy = 110, radius = 80;
  const victimColor = (status === 'Normal') ? '#475569' : (TYPE_COLORS[label] || '#475569');

  let html = `<circle cx="${cx}" cy="${cy}" r="22" fill="#0f172a" stroke="${victimColor}" stroke-width="3"/>
              <text x="${cx}" y="${cy+4}" text-anchor="middle" font-size="11" fill="#e2e8f0">Victim</text>`;

  if (!ips.length) {
    html += `<text x="${cx}" y="${cy+50}" text-anchor="middle" font-size="12" fill="#64748b">No active attackers</text>`;
    svg.innerHTML = html;
    return;
  }

  const lineColor = TYPE_COLORS[label] || '#38bdf8';
  ips.forEach((ip, i) => {
    const angle = (i / ips.length) * 2 * Math.PI - Math.PI / 2;
    const ax = cx + radius * Math.cos(angle);
    const ay = cy + radius * Math.sin(angle);
    html += `<line x1="${ax}" y1="${ay}" x2="${cx}" y2="${cy}" stroke="${lineColor}" stroke-width="2" class="pulse-line"/>
             <circle cx="${ax}" cy="${ay}" r="14" fill="#0f172a" stroke="${lineColor}" stroke-width="2"/>
             <text x="${ax}" y="${ay+4}" text-anchor="middle" font-size="10" fill="#e2e8f0">⚠</text>
             <text x="${ax}" y="${ay+26}" text-anchor="middle" class="node-label">${ip}</text>`;
  });

  svg.innerHTML = html;
}

function drawChart(history) {
  const canvas = document.getElementById('chart');
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  if (!history.length) return;

  const maxPps = Math.max(...history.map(h => h.pps), 10);
  const stepX = canvas.width / Math.max(history.length - 1, 1);

  ctx.beginPath();
  history.forEach((h, i) => {
    const x = i * stepX;
    const y = canvas.height - (h.pps / maxPps) * (canvas.height - 20) - 10;
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = "#475569";
  ctx.lineWidth = 2;
  ctx.stroke();

  history.forEach((h, i) => {
    const x = i * stepX;
    const y = canvas.height - (h.pps / maxPps) * (canvas.height - 20) - 10;
    ctx.fillStyle = TYPE_COLORS[h.label] || "#38bdf8";
    ctx.beginPath();
    ctx.arc(x, y, 4, 0, Math.PI * 2);
    ctx.fill();
  });
}

const chartCanvas = document.getElementById('chart');
const tooltip = document.getElementById('tooltip');

chartCanvas.addEventListener('mousemove', (e) => {
  if (!currentHistory.length) return;
  const rect = chartCanvas.getBoundingClientRect();
  const scaleX = chartCanvas.width / rect.width;
  const mouseX = (e.clientX - rect.left) * scaleX;
  const stepX = chartCanvas.width / Math.max(currentHistory.length - 1, 1);
  let idx = Math.round(mouseX / stepX);
  idx = Math.max(0, Math.min(currentHistory.length - 1, idx));
  const h = currentHistory[idx];

  tooltip.innerHTML =
    `<strong style="color:${TYPE_COLORS[h.label] || '#38bdf8'}">${h.label}</strong><br>` +
    `PPS: ${h.pps}<br>` +
    `Severity: ${h.severity}<br>` +
    `Attacker IP: ${h.top_ip}`;
  tooltip.style.left = (e.clientX + 14) + 'px';
  tooltip.style.top  = (e.clientY + 14) + 'px';
  tooltip.style.display = 'block';
});

chartCanvas.addEventListener('mouseleave', () => {
  tooltip.style.display = 'none';
});

setInterval(refresh, 1000);
refresh();
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(PAGE)


@app.route("/api/status")
def api_status():
    with state_lock:
        return jsonify({
            "status"             : state["status"],
            "label"              : state["label"],
            "confidence"         : state["confidence"],
            "severity"           : state["severity"],
            "threat_score"       : state["threat_score"],
            "pps"                : state["pps"],
            "unique_ports"       : state["unique_ports"],
            "syn"                : state["syn"],
            "rst"                : state["rst"],
            "icmp"               : state["icmp"],
            "top_port"           : state["top_port"],
            "top_ip"             : state["top_ip"],
            "streak"             : state["streak"],
            "attack_events"      : state["attack_events"],
            "distinct_attackers" : state["distinct_attackers"],
            "attacker_ips"       : state["attacker_ips"],
            "history"            : list(state["history"]),
            "alert_log"          : list(state["alert_log"]),
            "class_counts"       : state["class_counts"],
        })


@app.route("/download-log")
def download_log():
    return send_file(LOG_PATH, as_attachment=True, download_name="dashboard_log.csv")


if __name__ == "__main__":
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()
    print("[*] Sniffing started in background.")
    print(f"[*] Logging every second to {LOG_PATH}")
    print("[*] Dashboard live at http://<this-machine-ip>:5000\n")
    app.run(host="0.0.0.0", port=5000, threaded=True)
