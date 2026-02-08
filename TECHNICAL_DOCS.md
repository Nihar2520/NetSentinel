# NetSentinel - Technical Documentation

## Architecture Overview

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                     NetSentinel System                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌────────────────┐      ┌─────────────────────────────┐   │
│  │ Packet Capture │─────▶│   Network Monitor           │   │
│  │   (Scapy)      │      │   - Feature Extraction      │   │
│  └────────────────┘      │   - Traffic Statistics      │   │
│                          │   - Packet Aggregation       │   │
│                          └─────────────────────────────┘   │
│                                    │                        │
│                                    ▼                        │
│                          ┌─────────────────────────────┐   │
│                          │   Detection Engine          │   │
│                          ├─────────────────────────────┤   │
│                          │                             │   │
│  ┌───────────────────┐  │  ┌─────────────────────┐   │   │
│  │   Rule Engine     │◀─┼─▶│   ML Detector       │   │   │
│  │ - Port Scan       │  │  │ - Isolation Forest  │   │   │
│  │ - SYN Flood       │  │  │ - Anomaly Scoring   │   │   │
│  │ - ICMP Flood      │  │  │ - Online Learning   │   │   │
│  │ - Suspicious Ports│  │  └─────────────────────┘   │   │
│  └───────────────────┘  │                             │   │
│                          └─────────────────────────────┘   │
│                                    │                        │
│                                    ▼                        │
│                          ┌─────────────────────────────┐   │
│                          │   Alert Management          │   │
│                          │   - Logging                 │   │
│                          │   - JSON Export             │   │
│                          │   - Real-time Notification  │   │
│                          └─────────────────────────────┘   │
│                                    │                        │
│                                    ▼                        │
│                          ┌─────────────────────────────┐   │
│                          │   Response (IPS Mode)       │   │
│                          │   - IP Blocking             │   │
│                          │   - Rate Limiting           │   │
│                          └─────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘

    ┌─────────────────────────────────────────────┐
    │         External Components                  │
    ├─────────────────────────────────────────────┤
    │  Dashboard          Alert Analyzer           │
    │  - Real-time viz    - Statistical analysis   │
    │  - Monitoring       - Report generation      │
    └─────────────────────────────────────────────┘
```

## Machine Learning Details

### Isolation Forest Algorithm

NetSentinel uses Isolation Forest for anomaly detection because:

1. **Efficient**: O(n log n) time complexity
2. **Unsupervised**: No labeled attack data needed
3. **Online Learning**: Can update with new samples
4. **Robust**: Works well with high-dimensional data

#### How It Works

```python
# Training Phase
1. Extract features from normal traffic
2. Build ensemble of isolation trees
3. Calculate anomaly scores

# Detection Phase
1. Extract features from new traffic
2. Calculate path length in trees
3. Score < threshold → Anomaly
```

#### Feature Vector

Each IP's traffic is represented as a 9-dimensional feature vector:

```python
[
    packet_count,          # Total packets
    byte_count,            # Total bytes
    tcp_count,             # TCP packets
    udp_count,             # UDP packets
    icmp_count,            # ICMP packets
    syn_count,             # SYN flags
    unique_dst_ports,      # Port diversity
    unique_src_ports,      # Source port diversity
    packet_rate            # Packets per second
]
```

### Model Training

```python
# Initial Training
- Requires 100 minimum samples
- Retrains every 50 new samples
- Contamination factor: 0.1 (expects 10% anomalies)

# Persistence
- Model saved to ml_model.pkl
- Includes scaler and training data
- Auto-saves every 60 seconds
```

## Detection Rules

### Port Scan Detection

**Trigger**: Source IP accesses >20 unique destination ports

**Logic**:
```python
if len(unique_destination_ports) > threshold:
    alert('PORT_SCAN', severity='HIGH')
```

**Indicators**:
- Sequential port access
- High port diversity
- Short time window

### SYN Flood Detection

**Trigger**: >100 SYN packets per second from single source

**Logic**:
```python
recent_syns = count_syn_packets(last_1_second)
if recent_syns > threshold:
    alert('SYN_FLOOD', severity='CRITICAL')
```

**Indicators**:
- High SYN rate
- No corresponding ACKs
- Multiple destination IPs

### ICMP Flood Detection

**Trigger**: >50 ICMP packets per second

**Logic**:
```python
recent_icmp = count_icmp_packets(last_1_second)
if recent_icmp > threshold:
    alert('ICMP_FLOOD', severity='HIGH')
```

**Indicators**:
- High ICMP echo request rate
- Large packet sizes
- Rapid succession

### Suspicious Port Detection

**Trigger**: Connection to known malicious ports

**Malicious Ports**:
```python
31337  # Back Orifice
12345  # NetBus
6667   # IRC (potential botnet C2)
1337   # WASTE
27374  # SubSeven
```

## Performance Characteristics

### Throughput

| Metric | Value |
|--------|-------|
| Packets/sec | ~1,000 - 5,000 |
| Mbps | ~10 - 50 |
| CPU Usage | 15-30% (single core) |
| Memory | ~200-500 MB |

### Latency

| Operation | Time |
|-----------|------|
| Packet Processing | <1 ms |
| ML Prediction | <5 ms |
| Rule Check | <0.5 ms |
| Alert Generation | <1 ms |

### Scalability Limits

- **Single Interface**: Handles typical small/medium network
- **High Traffic**: May drop packets >10,000 pps
- **Memory**: Grows with unique IPs tracked
- **Solution**: Deploy multiple instances for large networks

## Data Flow

### Packet Processing Pipeline

```
1. Capture
   ↓
   [Scapy sniff()] → Raw packet
   ↓
2. Parse
   ↓
   [process_packet()] → Extract IP, ports, protocols
   ↓
3. Aggregate
   ↓
   [NetworkMonitor] → Update statistics per IP
   ↓
4. Detect
   ↓
   [RuleEngine] ← Signature matching
   [MLDetector] ← Anomaly detection
   ↓
5. Alert
   ↓
   [Alert logging, JSON export]
   ↓
6. Respond (IPS mode)
   ↓
   [IP blocking, iptables rules]
```

### State Management

```python
# Per-IP Statistics
packet_stats = {
    'src_ip': {
        'packet_count': int,
        'byte_count': int,
        'tcp_count': int,
        'udp_count': int,
        'icmp_count': int,
        'syn_count': int,
        'unique_dst_ports': set,
        'unique_src_ports': set,
        'timestamps': deque(maxlen=1000)
    }
}

# Global State
blocked_ips = set()
alerts = list()
ml_training_data = list()
```

## Security Considerations

### Bypassing Detection

**Known Limitations**:
1. **Slow Scans**: Port scans slower than threshold
2. **Distributed Attacks**: From many IPs below individual thresholds
3. **Encrypted Traffic**: Cannot inspect encrypted payloads
4. **Fragmentation**: May not detect fragmented attacks
5. **Protocol Tunneling**: Traffic hidden in legitimate protocols

### Evasion Techniques

| Technique | NetSentinel Defense |
|-----------|---------------------|
| Slow scan | Track cumulative over longer windows |
| IP spoofing | ML can detect unusual patterns |
| Fragmentation | Reassemble fragments (future enhancement) |
| Polymorphic attacks | ML anomaly detection |
| Zero-day exploits | ML catches unusual behavior |

### Hardening Recommendations

1. **Deploy in IPS mode** for active blocking
2. **Combine with firewall** rules
3. **Regular model retraining** with known good traffic
4. **Tune thresholds** to your network baseline
5. **Monitor false positives** and adjust

## Alert Format

### JSON Structure

```json
{
  "type": "PORT_SCAN",
  "src_ip": "192.168.1.100",
  "dst_ip": "192.168.1.1",
  "severity": "HIGH",
  "details": "Scanned 45 unique ports",
  "timestamp": "2025-02-07T14:30:45.123456",
  "port": null,
  "anomaly_score": null
}
```

### Severity Levels

| Level | Criteria | Response |
|-------|----------|----------|
| CRITICAL | Active DDoS, critical service attack | Immediate blocking |
| HIGH | Port scans, exploit attempts | Block in IPS mode |
| MEDIUM | ML anomalies, suspicious patterns | Log and monitor |
| LOW | Minor policy violations | Log only |

## Extension Points

### Adding Custom Detection Rules

```python
class RuleEngine:
    def check_custom_rule(self, src_ip, stats):
        """
        Example: Detect unusual DNS query rate
        """
        dns_port = 53
        if dns_port in stats['unique_dst_ports']:
            dns_packets = stats['udp_count']  # Simplified
            if dns_packets > 100:
                alert = {
                    'type': 'DNS_ABUSE',
                    'src_ip': src_ip,
                    'severity': 'MEDIUM',
                    'details': f'High DNS query rate: {dns_packets}',
                    'timestamp': datetime.now().isoformat()
                }
                self.alerts.append(alert)
                return True
        return False
```

### Custom ML Features

```python
def get_custom_features(self, src_ip):
    """Add domain-specific features"""
    stats = self.packet_stats[src_ip]
    
    # Calculate additional features
    tcp_udp_ratio = stats['tcp_count'] / (stats['udp_count'] + 1)
    avg_packet_size = stats['byte_count'] / stats['packet_count']
    port_entropy = calculate_entropy(stats['unique_dst_ports'])
    
    return [
        stats['packet_count'],
        tcp_udp_ratio,
        avg_packet_size,
        port_entropy,
        # ... other features
    ]
```

### Integration with SIEM

```python
import syslog

def send_to_siem(alert):
    """Send alerts to SIEM system"""
    syslog.openlog('NetSentinel')
    
    priority = syslog.LOG_ALERT
    if alert['severity'] == 'CRITICAL':
        priority = syslog.LOG_CRIT
    
    message = json.dumps(alert)
    syslog.syslog(priority, message)
```

## Testing Strategy

### Unit Testing

```python
# Test port scan detection
def test_port_scan_detection():
    monitor = NetworkMonitor()
    engine = RuleEngine()
    
    # Simulate port scan
    stats = {
        'unique_dst_ports': set(range(1, 30)),
        # ... other stats
    }
    
    assert engine.check_port_scan('1.2.3.4', stats) == True
```

### Integration Testing

```bash
# 1. Start NetSentinel
sudo python3 netsentinel.py -i lo -m ids &

# 2. Generate test traffic
python3 traffic_generator.py -t 127.0.0.1 -a port_scan

# 3. Verify alerts
grep "PORT_SCAN" netsentinel.log
```

### Performance Testing

```python
# Benchmark packet processing
import time

packets_to_process = 10000
start = time.time()

for _ in range(packets_to_process):
    sentinel.packet_handler(test_packet)

elapsed = time.time() - start
pps = packets_to_process / elapsed

print(f"Processed {pps:.0f} packets/second")
```

## Deployment Scenarios

### 1. Network Edge (Gateway)

```
Internet ─── [NetSentinel] ─── Internal Network
```

**Advantages**: Catches all external threats  
**Configuration**: Monitor WAN interface

### 2. Internal Monitoring

```
Internal Network ─── [NetSentinel] ─── Server Subnet
```

**Advantages**: Detects lateral movement  
**Configuration**: Monitor switch mirror port

### 3. Honeypot

```
Internet ─── [NetSentinel + Honeypot]
```

**Advantages**: Attracts and logs attackers  
**Configuration**: Standalone system, log everything

## Future Enhancements

### Phase 2: Deep Packet Inspection

- HTTP/HTTPS header analysis
- DNS query inspection
- Protocol anomaly detection
- Payload pattern matching

### Phase 3: Distributed Deployment

- Central management console
- Distributed sensors
- Aggregated alerting
- Coordinated blocking

### Phase 4: Advanced ML

- LSTM for sequence analysis
- Autoencoders for feature learning
- Ensemble methods
- Reinforcement learning for adaptive thresholds

### Phase 5: Integration

- Threat intelligence feeds
- STIX/TAXII support
- SIEM connectors (Splunk, ELK)
- Incident response automation

---

**Last Updated**: February 2025  
**Version**: 1.0.0
