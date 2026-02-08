# 🚀 NetSentinel - Getting Started (5-Minute Guide)

## The Absolute Fastest Way to Get NetSentinel Working

### Step 1: Download and Setup (2 minutes)

```bash
# 1. Create directory and navigate to it
mkdir ~/netsentinel && cd ~/netsentinel

# 2. Place all NetSentinel files in this directory
# (netsentinel.py, dashboard.py, etc.)

# 3. Run automated setup
chmod +x setup.sh
sudo bash setup.sh
```

**Expected:** Setup completes successfully ✓

---

### Step 2: Run the Automated Demo (2 minutes)

```bash
# This runs everything automatically
chmod +x quick_start.sh
sudo bash quick_start.sh
```

**What this does:**
- Starts NetSentinel
- Generates test attacks
- Creates alerts
- Generates reports
- Shows you the results

**Expected:** You see attack alerts and generated reports ✓

---

### Step 3: View the Results (1 minute)

```bash
# View summary
cat alert_report.txt | less

# View alerts
cat alerts.json | python3 -m json.tool | less

# View visualizations
ls plots/
# Open the .png files
```

**Expected:** You see detailed analysis and visualizations ✓

---

## 🎯 That's It! You're Done!

NetSentinel is now working. The quick demo showed you:
- ✅ Port scan detection
- ✅ DDoS attack detection  
- ✅ ML anomaly detection
- ✅ Alert generation
- ✅ Report creation

---

## 📊 Next: Run It Manually

### Terminal 1: Start NetSentinel
```bash
sudo python3 netsentinel.py -i eth0 -m ids
```

### Terminal 2: Start Dashboard
```bash
python3 dashboard.py
```

### Terminal 3: Generate Attacks
```bash
# Port scan
sudo python3 traffic_generator.py -t 127.0.0.1 -a port_scan

# DDoS
sudo python3 traffic_generator.py -t 127.0.0.1 -a syn_flood -d 20

# Mixed attacks
sudo python3 traffic_generator.py -t 127.0.0.1 -a mixed -d 60
```

---

## 🔍 If Something Goes Wrong

```bash
# Run diagnostics
chmod +x troubleshoot.sh
sudo bash troubleshoot.sh
```

This will tell you exactly what's wrong and how to fix it.

---

## 📚 Full Documentation

- **DEPLOYMENT_GUIDE.md** - Complete step-by-step instructions
- **README.md** - Full feature documentation  
- **TECHNICAL_DOCS.md** - Architecture and design details

---

## ✅ Success Checklist

You'll know it's working when you see:

1. ✅ NetSentinel starts with "Monitoring started..." message
2. ✅ Dashboard window opens with charts
3. ✅ Alerts appear in netsentinel.log
4. ✅ alerts.json file is created
5. ✅ Alert analyzer creates reports and plots

---

## 🎓 What Each File Does

| File | Purpose | When to Run |
|------|---------|-------------|
| `netsentinel.py` | Main IDS/IPS engine | Always (for monitoring) |
| `dashboard.py` | Real-time visualization | Optional (to see live data) |
| `traffic_generator.py` | Testing tool | For testing only |
| `alert_analyzer.py` | Post-analysis | After collecting alerts |
| `setup.sh` | Install dependencies | Once (initial setup) |
| `quick_start.sh` | Automated demo | Once (to verify it works) |
| `troubleshoot.sh` | Diagnostics | When you have problems |

---

## 💡 Key Commands to Remember

```bash
# Installation
sudo bash setup.sh

# Quick demo
sudo bash quick_start.sh

# Start monitoring
sudo python3 netsentinel.py -i eth0 -m ids

# Troubleshooting
sudo bash troubleshoot.sh

# Analysis
python3 alert_analyzer.py -a all
```

---

## 🎉 You're Ready!

NetSentinel is now protecting your network. Happy monitoring! 🛡️

**Questions?** Read DEPLOYMENT_GUIDE.md for detailed instructions.
