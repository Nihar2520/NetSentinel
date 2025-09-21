# NetSentinel
Here’s a clean **README.md** you can use directly on GitHub. I’ll also suggest a solid project name.

---

# 🚨 NetSentinel – Lightweight IDS/IPS with Machine Learning

## 📌 Overview

**NetSentinel** is a lightweight, Python-based Intrusion Detection & Prevention System (IDS/IPS).
It leverages **machine learning (Isolation Forest)** to detect anomalous network traffic in real-time.
The system exposes a **Flask REST API**, making it easy to integrate with SIEM, SOAR, or XDR platforms.

---

## ✨ Features

* 🔎 **Anomaly Detection**: Detects unusual traffic patterns using ML.
* ⚡ **Real-time Analysis**: Processes live network packets.
* 📡 **REST API**: Predicts anomalies from external tools (Postman, Python client, SIEM).
* ⚙ **Extensible**: Easily add features like deep packet inspection, user-defined thresholds, or Wazuh integration.
* 🖥 Works on **Windows, Linux, macOS**.

---

## 📂 Project Structure

```
NetSentinel/
│── main.py          # Flask API for IDS
│── ids_model.py     # IsolationForest ML model
│── test_client.py   # Python test script for API
│── requirements.txt # Dependencies
│── README.md        # Documentation
```

---

## 🔧 Installation

### 1. Clone Repository

```bash
git clone https://github.com/Nihar2520/NetSentinel.git
cd NetSentinel
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## ▶️ Usage

### Run the IDS API

```bash
python main.py
```

Server starts at:

```
http://127.0.0.1:5000
```

### Test the API

#### Option A: PowerShell (Windows)

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/predict" -Method Post -ContentType "application/json" -Body '{"packet_size":500,"packet_time":0.02}'
```

#### Option B: Postman (GUI)

* URL: `http://127.0.0.1:5000/predict`
* Method: `POST`
* Body (raw → JSON):

```json
{
  "packet_size": 500,
  "packet_time": 0.02
}
```

#### Option C: Python Client

```bash
python test_client.py
```

Output Example:

```json
{
  "prediction": "anomaly",
  "score": -0.34
}
```

---

## 📈 Roadmap

* [ ] Add more packet features (protocol, flags, entropy).
* [ ] Train supervised models for higher accuracy.
* [ ] Add auto-block (IPS mode) with firewall integration.
* [ ] Integrate with **Wazuh / SIEM** for correlation.

---

## 🛡 Disclaimer

This tool is for **educational and research purposes only**.
It is not production-hardened and should not replace enterprise-grade IDS/IPS solutions.
