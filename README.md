# NetSentinel - Lightweight IDS/IPS with Machine Learning

A comprehensive network intrusion detection and prevention system that combines signature-based detection with machine learning for anomaly detection.

## 🎯 Features

### Core Capabilities
- **Real-time Packet Analysis**: Captures and analyzes network traffic in real-time using Scapy
- **Machine Learning Anomaly Detection**: Uses Isolation Forest algorithm to detect unusual traffic patterns
- **Signature-based Detection**: Rule engine for detecting known attack patterns
- **Dual Mode Operation**: Supports both IDS (detection) and IPS (prevention) modes
- **Real-time Alerting**: Immediate notifications for detected threats
- **Comprehensive Logging**: Detailed logs of all network activity and alerts

### Attack Detection

#### Signature-based Detection
1. **Port Scanning**: Detects reconnaissance attempts via port scanning
2. **SYN Flood**: Identifies SYN flood DDoS attacks
3. **ICMP Flood**: Detects ping flood attacks
4. **Suspicious Ports**: Alerts on connections to commonly malicious ports
5. **DNS Amplification**: Recognizes DNS amplification attack patterns

#### ML-based Detection
- Anomaly detection using Isolation Forest
- Learns normal traffic patterns automatically
- Detects zero-day attacks and unknown threats
- Continuous model training with new data

### Visualization & Monitoring
- Real-time dashboard with multiple visualizations
- Alert timeline and distribution charts
- Traffic intensity heatmaps
- Top attacker IP tracking
- Severity-based alert classification

## 📋 Requirements

### System Requirements
- Linux-based operating system (Ubuntu, Debian, CentOS, etc.)
- Python 3.8 or higher
- Root/sudo privileges (for packet capture)
- Network interface accessible to Python

### Python Dependencies
```
scapy==2.5.0
numpy==1.24.3
scikit-learn==1.3.0
pandas==2.0.3
matplotlib==3.7.2
seaborn==0.12.2
```

## 🚀 Installation

### 1. Clone or Download the Project
```bash
cd /path/to/netsentinel
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Install System Dependencies (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install tcpdump libpcap-dev python3-dev
```

### 4. Set Permissions
```bash
chmod +x netsentinel.py
chmod +x traffic_generator.py
chmod +x dashboard.py
```

## 💻 Usage

### Basic IDS Mode (Detection Only)
```bash
sudo python3 netsentinel.py -i eth0 -m ids
```

### IPS Mode (Detection + Prevention)
```bash
sudo python3 netsentinel.py -i eth0 -m ips
```

### Command-line Arguments
- `-i, --interface`: Network interface to monitor (default: eth0)
- `-m, --mode`: Operation mode - 'ids' or 'ips' (default: ids)

### Finding Your Network Interface
```bash
# List all network interfaces
ip link show

# Or
ifconfig
```

Common interfaces:
- `eth0`, `eth1`: Ethernet interfaces
- `wlan0`, `wlan1`: Wireless interfaces
- `enp0s3`, `ens33`: Modern naming scheme

## 📊 Dashboard

### Running the Dashboard
```bash
python3 dashboard.py
```

The dashboard provides:
- **Alert Timeline**: Visualize when attacks occur
- **Alert Type Distribution**: Pie chart of different attack types
- **Traffic Heatmap**: 7-day traffic intensity visualization
- **Severity Distribution**: Bar chart of alert severities
- **Top Attackers**: List of most active malicious IPs

The dashboard auto-refreshes every 5 seconds.
<img width="1910" height="977" alt="image" src="https://github.com/user-attachments/assets/c8d5c4a2-b614-45c6-b662-5f06c642803f" />


## 🧪 Testing with Traffic Generator

**WARNING**: Only use on networks you own or have explicit permission to test!

### Generate Normal Traffic
```bash
sudo python3 traffic_generator.py -t 192.168.1.100 -a normal -d 30
```

### Simulate Port Scan
```bash
sudo python3 traffic_generator.py -t 192.168.1.100 -a port_scan
```

### Simulate SYN Flood
```bash
sudo python3 traffic_generator.py -t 192.168.1.100 -a syn_flood -d 20
```

### Mixed Attack Scenario
```bash
sudo python3 traffic_generator.py -t 192.168.1.100 -a mixed -d 60
```

### Available Attack Types
- `normal`: Normal HTTP/HTTPS traffic
- `port_scan`: Port scanning attack
- `syn_flood`: SYN flood DDoS
- `udp_flood`: UDP flood DDoS
- `icmp_flood`: ICMP/ping flood
- `suspicious_ports`: Access to malicious ports
- `dns_amp`: DNS amplification
- `slowloris`: Slowloris attack
- `mixed`: Random combination of attacks

## 📁 File Structure

```
netsentinel/
├── netsentinel.py          # Main IDS/IPS application
├── dashboard.py            # Real-time visualization dashboard
├── traffic_generator.py    # Attack simulation tool
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── netsentinel.log        # Runtime logs (generated)
├── alerts.json            # Alert database (generated)
└── ml_model.pkl           # Trained ML model (generated)
```

## 🔧 Configuration

### Adjusting Detection Thresholds

Edit `netsentinel.py` to modify thresholds in the `RuleEngine` class:

```python
class RuleEngine:
    def __init__(self):
        self.port_scan_threshold = 20      # Ports before alert
        self.syn_flood_threshold = 100     # SYN packets/sec
        self.icmp_flood_threshold = 50     # ICMP packets/sec
```

### ML Model Configuration

Adjust ML parameters in the `MLDetector` class:

```python
class MLDetector:
    def __init__(self, contamination=0.1):  # Expected % of anomalies
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=100  # Number of trees
        )
```

### Adding Custom Rules

Add new detection rules in the `RuleEngine` class:

```python
def check_custom_attack(self, src_ip, stats):
    """Detect custom attack pattern"""
    if <your_condition>:
        alert = {
            'type': 'CUSTOM_ATTACK',
            'src_ip': src_ip,
            'severity': 'HIGH',
            'details': 'Description',
            'timestamp': datetime.now().isoformat()
        }
        self.alerts.append(alert)
        logging.warning(f"Custom attack from {src_ip}")
        return True
    return False
```

## 📈 Understanding Alerts

### Alert Severities
- **CRITICAL**: Immediate threat requiring action (e.g., active DDoS)
- **HIGH**: Serious threat (e.g., port scanning, exploit attempts)
- **MEDIUM**: Suspicious activity (e.g., ML anomalies, unusual patterns)
- **LOW**: Minor policy violations

### Alert Types
- **PORT_SCAN**: Host scanning multiple ports
- **SYN_FLOOD**: SYN flood attack detected
- **ICMP_FLOOD**: ICMP/ping flood attack
- **UDP_FLOOD**: UDP flood attack
- **SUSPICIOUS_PORT**: Connection to known malicious port
- **ML_ANOMALY**: Machine learning detected anomaly
- **DNS_AMP**: DNS amplification attack pattern

## 🛡️ IPS Mode (Prevention)

When running in IPS mode (`-m ips`), NetSentinel will:
1. Detect malicious activity
2. Automatically block the source IP
3. Log the blocking action

**Note**: The current implementation logs blocks but doesn't actually modify iptables. To enable real blocking, uncomment this line in `netsentinel.py`:

```python
def block_ip(self, ip, threats):
    if ip not in self.blocked_ips:
        self.blocked_ips.add(ip)
        logging.critical(f"BLOCKED IP: {ip}")
        
        # Uncomment to enable real blocking:
        os.system(f"iptables -A INPUT -s {ip} -j DROP")
```

### Managing Blocked IPs

```bash
# View blocked IPs
sudo iptables -L INPUT -n

# Unblock an IP
sudo iptables -D INPUT -s <IP_ADDRESS> -j DROP

# Clear all blocks
sudo iptables -F INPUT
```

## 🔍 Analyzing Results

### View Logs
```bash
tail -f netsentinel.log
```

### View Alerts
```bash
cat alerts.json | python3 -m json.tool
```

### Extract Specific Alert Types
```bash
cat alerts.json | jq '.[] | select(.type=="PORT_SCAN")'
```

## 🎓 Educational Use

This project demonstrates:
1. **Network Programming**: Packet capture and analysis
2. **Machine Learning**: Anomaly detection with Isolation Forest
3. **Cybersecurity**: IDS/IPS concepts and implementation
4. **Real-time Processing**: Streaming data analysis
5. **System Programming**: Low-level network interaction

## ⚠️ Important Notes

### Legal Considerations
- Only use on networks you own or have permission to test
- Unauthorized network scanning/testing is illegal in most jurisdictions
- Use the traffic generator responsibly

### Limitations
- Not a replacement for enterprise-grade IDS/IPS solutions
- ML model requires training data to be effective
- May generate false positives initially
- Performance depends on network load

### Performance Tips
1. Use a dedicated network interface
2. Increase ML training samples for better accuracy
3. Adjust thresholds based on your network baseline
4. Monitor system resources (CPU/Memory)

## 🐛 Troubleshooting

### "Permission denied" errors
```bash
# Run with sudo
sudo python3 netsentinel.py -i eth0
```

### "No module named 'scapy'" errors
```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

### Interface not found
```bash
# List available interfaces
ip link show

# Use correct interface name
sudo python3 netsentinel.py -i <correct_interface_name>
```

### No alerts being generated
1. Check if traffic is passing through the interface
2. Verify you're monitoring the correct interface
3. Generate test traffic using the traffic generator
4. Check thresholds aren't too high

## 📚 Further Development

### Potential Enhancements
- [ ] Web-based dashboard (Flask/Django)
- [ ] Database integration (PostgreSQL/MongoDB)
- [ ] Email/SMS notifications
- [ ] Deep packet inspection
- [ ] Protocol-specific analysis (HTTP, DNS, etc.)
- [ ] Integration with SIEM systems
- [ ] Distributed deployment support
- [ ] Advanced ML models (LSTM, Autoencoders)
- [ ] Custom rule language/parser
- [ ] Network flow analysis
- [ ] Threat intelligence feeds integration

### Contributing
Feel free to extend this project with additional features!

## 📄 License

This project is for educational purposes. Use responsibly and ethically.

## 🙏 Acknowledgments

Built using:
- Scapy for packet manipulation
- scikit-learn for machine learning
- matplotlib for visualization

---

**Created**: Feb 2026  
**Version**: 1.0.0  
**Type**: Cybersecurity / Network Security / Machine Learning
