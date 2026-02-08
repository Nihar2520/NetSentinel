# NetSentinel - Visual Workflow & Command Reference

## 📊 Complete System Workflow

```
┌─────────────────────────────────────────────────────────────────────┐
│                         INSTALLATION PHASE                           │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
                    ┌──────────────────────────┐
                    │  Run: sudo bash setup.sh │
                    └──────────────────────────┘
                                  │
                                  ▼
                    ┌──────────────────────────┐
                    │   Dependencies Installed  │
                    │   ✓ Python packages      │
                    │   ✓ System packages      │
                    │   ✓ Permissions set      │
                    └──────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       QUICK TEST PHASE                               │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
                ┌────────────────────────────────────┐
                │  Run: sudo bash quick_start.sh     │
                └────────────────────────────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
        ┌──────────────────┐        ┌──────────────────┐
        │  NetSentinel     │        │  Traffic         │
        │  starts in       │        │  Generator       │
        │  background      │        │  runs attacks    │
        └──────────────────┘        └──────────────────┘
                    │                           │
                    └─────────────┬─────────────┘
                                  ▼
                    ┌──────────────────────────┐
                    │   Alerts Generated       │
                    │   Reports Created        │
                    │   Plots Generated        │
                    └──────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       MANUAL OPERATION PHASE                         │
└─────────────────────────────────────────────────────────────────────┘
                                  │
            ┌─────────────────────┴─────────────────────┐
            │                     │                      │
            ▼                     ▼                      ▼
    ┌──────────────┐    ┌──────────────┐      ┌──────────────┐
    │  Terminal 1  │    │  Terminal 2  │      │  Terminal 3  │
    │              │    │              │      │              │
    │ sudo python3 │    │   python3    │      │ sudo python3 │
    │ netsentinel  │    │  dashboard   │      │   traffic_   │
    │     .py      │    │     .py      │      │  generator   │
    └──────────────┘    └──────────────┘      └──────────────┘
            │                     │                      │
            └─────────────────────┴──────────────────────┘
                                  │
                                  ▼
                    ┌──────────────────────────┐
                    │   Real-time Monitoring   │
                    │   ✓ Packet capture       │
                    │   ✓ Alert generation     │
                    │   ✓ ML training          │
                    │   ✓ Visualization        │
                    └──────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         ANALYSIS PHASE                               │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
                ┌────────────────────────────────────┐
                │  python3 alert_analyzer.py -a all  │
                └────────────────────────────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
        ┌──────────────────┐        ┌──────────────────┐
        │  Text Reports    │        │  Visualizations  │
        │  - Summary       │        │  - Timelines     │
        │  - Details       │        │  - Heatmaps      │
        │  - CSV export    │        │  - Charts        │
        └──────────────────┘        └──────────────────┘
```

---

## 🎯 Command Decision Tree

```
START: What do you want to do?
│
├─ Install NetSentinel
│  └─> sudo bash setup.sh
│
├─ Test if it works
│  └─> sudo bash quick_start.sh
│
├─ Check for problems
│  └─> sudo bash troubleshoot.sh
│
├─ Monitor network (production)
│  ├─> Terminal 1: sudo python3 netsentinel.py -i eth0 -m ids
│  ├─> Terminal 2: python3 dashboard.py
│  └─> (Let it run)
│
├─ Test attack detection
│  └─> sudo python3 traffic_generator.py -t 127.0.0.1 -a [attack_type]
│     Options: port_scan, syn_flood, icmp_flood, mixed
│
├─ Analyze collected alerts
│  └─> python3 alert_analyzer.py -a all
│
└─ View results
   ├─> cat netsentinel.log
   ├─> cat alerts.json | python3 -m json.tool
   ├─> cat alert_report.txt
   └─> ls plots/
```

---

## 📋 Quick Command Reference Card

### Installation & Setup
```bash
# One-time setup
sudo bash setup.sh                    # Install everything

# Quick demo
sudo bash quick_start.sh              # Automated test

# Troubleshooting
sudo bash troubleshoot.sh             # Diagnose issues
```

### Running NetSentinel
```bash
# IDS mode (detect only)
sudo python3 netsentinel.py -i eth0 -m ids

# IPS mode (detect + block)
sudo python3 netsentinel.py -i eth0 -m ips

# Using loopback for testing
sudo python3 netsentinel.py -i lo -m ids

# Find your interface
ip link show
```

### Dashboard & Visualization
```bash
# Start dashboard
python3 dashboard.py

# Dashboard updates every 5 seconds automatically
```

### Traffic Generation (Testing)
```bash
# Port scan
sudo python3 traffic_generator.py -t 127.0.0.1 -a port_scan

# SYN flood (20 seconds)
sudo python3 traffic_generator.py -t 127.0.0.1 -a syn_flood -d 20

# ICMP flood
sudo python3 traffic_generator.py -t 127.0.0.1 -a icmp_flood -d 15

# Mixed attacks (60 seconds)
sudo python3 traffic_generator.py -t 127.0.0.1 -a mixed -d 60

# All attack types:
# normal, port_scan, syn_flood, udp_flood, icmp_flood,
# suspicious_ports, dns_amp, slowloris, mixed
```

### Analysis & Reporting
```bash
# Full analysis (recommended)
python3 alert_analyzer.py -a all

# Summary only
python3 alert_analyzer.py -a summary

# Generate visualizations
python3 alert_analyzer.py -a visualize

# Export to CSV
python3 alert_analyzer.py -a export

# Custom alert file
python3 alert_analyzer.py -f custom_alerts.json -a all
```

### Viewing Results
```bash
# View logs (real-time)
tail -f netsentinel.log

# View logs (last 100 lines)
tail -100 netsentinel.log

# Search for specific alerts
grep "PORT_SCAN" netsentinel.log
grep "CRITICAL" netsentinel.log

# View alerts (formatted)
cat alerts.json | python3 -m json.tool | less

# Count alerts
cat alerts.json | python3 -c "import json, sys; print(len(json.load(sys.stdin)))"

# View report
cat alert_report.txt | less

# View CSV
column -t -s, alerts.csv | less

# View plots
ls -lh plots/
# Open .png files with image viewer
```

---

## 🔄 Typical Workflow Sessions

### Session 1: First Time Setup
```bash
cd ~/netsentinel
sudo bash setup.sh                     # 1-2 minutes
sudo bash quick_start.sh               # 2-3 minutes
cat alert_report.txt                   # View results
```

### Session 2: Testing Attack Detection
```bash
# Terminal 1
sudo python3 netsentinel.py -i lo -m ids

# Terminal 2
python3 dashboard.py

# Terminal 3
sudo python3 traffic_generator.py -t 127.0.0.1 -a port_scan
# Wait, observe alerts
sudo python3 traffic_generator.py -t 127.0.0.1 -a syn_flood -d 20
# Wait, observe alerts

# Terminal 1: Ctrl+C to stop
# Terminal 3: Analysis
python3 alert_analyzer.py -a all
cat alert_report.txt
```

### Session 3: Real Network Monitoring
```bash
# Terminal 1: Start monitoring
sudo python3 netsentinel.py -i eth0 -m ids

# Terminal 2: Dashboard
python3 dashboard.py

# Let it run for hours/days...
# Browse web, download files, normal activity

# Later: Stop and analyze
# Terminal 1: Ctrl+C
python3 alert_analyzer.py -a all
```

### Session 4: Troubleshooting
```bash
sudo bash troubleshoot.sh              # Diagnose
# Read output, follow suggestions
pip3 install -r requirements.txt --break-system-packages
sudo bash quick_start.sh               # Retest
```

---

## 🎨 File Output Guide

After running NetSentinel, you'll have:

```
netsentinel/
│
├── netsentinel.log          ← Runtime logs (text)
├── alerts.json              ← Alert database (JSON)
├── ml_model.pkl             ← Trained ML model (binary)
├── alert_report.txt         ← Analysis report (text)
├── alerts.csv               ← Alerts spreadsheet (CSV)
│
└── plots/                   ← Visualizations (PNG)
    ├── timeline.png         ← Alert timeline
    ├── attack_types.png     ← Type distribution
    ├── heatmap.png          ← Time-based heatmap
    ├── top_attackers.png    ← Top IPs
    └── severity.png         ← Severity pie chart
```

**How to use them:**

| File | View With | Purpose |
|------|-----------|---------|
| netsentinel.log | `less`, `tail -f` | Real-time monitoring |
| alerts.json | `python3 -m json.tool` | Raw alert data |
| alert_report.txt | `less`, text editor | Human-readable report |
| alerts.csv | Excel, LibreOffice | Spreadsheet analysis |
| plots/*.png | Image viewer | Visual analysis |

---

## 🚨 Common Issues Quick Fix

| Issue | Quick Fix |
|-------|-----------|
| Permission denied | Add `sudo` before command |
| Module not found | `pip3 install -r requirements.txt --break-system-packages` |
| No such device | Run `ip link show`, use correct interface name |
| No alerts generated | Run `traffic_generator.py` to create test traffic |
| Dashboard empty | Make sure `alerts.json` exists with data |
| High CPU | Normal during packet capture |

---

## 📖 Documentation Reference

| Document | Use When |
|----------|----------|
| QUICK_START.md | First time, want fastest path |
| DEPLOYMENT_GUIDE.md | Step-by-step detailed instructions |
| README.md | Feature overview and capabilities |
| TECHNICAL_DOCS.md | Understanding internals |
| This file | Quick command reference |

---

## ⚡ Power User Tips

```bash
# Run NetSentinel as a service (persistent)
sudo python3 netsentinel.py -i eth0 -m ids > /dev/null 2>&1 &
echo $! > netsentinel.pid

# Stop NetSentinel service
kill $(cat netsentinel.pid)

# Monitor multiple interfaces (run multiple instances)
sudo python3 netsentinel.py -i eth0 -m ids &
sudo python3 netsentinel.py -i wlan0 -m ids &

# Filter logs by severity
grep "CRITICAL" netsentinel.log
grep "HIGH" netsentinel.log

# Count alerts by type
cat alerts.json | python3 -c "
import json, sys
from collections import Counter
alerts = json.load(sys.stdin)
types = Counter(a['type'] for a in alerts)
for t, c in types.most_common():
    print(f'{t}: {c}')
"

# Export specific alert types
cat alerts.json | python3 -c "
import json, sys
alerts = json.load(sys.stdin)
port_scans = [a for a in alerts if a['type'] == 'PORT_SCAN']
json.dump(port_scans, sys.stdout, indent=2)
" > port_scans.json

# Continuous monitoring with auto-restart
while true; do
    sudo python3 netsentinel.py -i eth0 -m ids
    echo "NetSentinel stopped, restarting in 5 seconds..."
    sleep 5
done
```

---

**Last Updated:** February 2025  
**Version:** 1.0.0  
**Print this card and keep it handy!** 📋
