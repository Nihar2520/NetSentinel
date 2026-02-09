#!/usr/bin/env python3
"""
NetSentinel - Lightweight IDS/IPS with Machine Learning
A network intrusion detection/prevention system with ML-based anomaly detection
"""

import logging
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict, deque
from datetime import datetime, timedelta
import threading
import time
import pickle
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('netsentinel.log'),
        logging.StreamHandler()
    ]
)

class NetworkMonitor:
    """Monitors network traffic and extracts features"""
    
    def __init__(self, time_window=60):
        self.time_window = time_window
        self.packet_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'tcp_count': 0,
            'udp_count': 0,
            'icmp_count': 0,
            'syn_count': 0,
            'unique_dst_ports': set(),
            'unique_src_ports': set(),
            'timestamps': deque(maxlen=1000)
        })
        
    def process_packet(self, packet):
        """Extract features from individual packet"""
        features = {}
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Update statistics
            stats = self.packet_stats[src_ip]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            stats['timestamps'].append(time.time())
            
            # Protocol counts
            if TCP in packet:
                stats['tcp_count'] += 1
                stats['unique_dst_ports'].add(packet[TCP].dport)
                stats['unique_src_ports'].add(packet[TCP].sport)
                
                # SYN flag detection
                if packet[TCP].flags & 0x02:
                    stats['syn_count'] += 1
                    
            elif UDP in packet:
                stats['udp_count'] += 1
                stats['unique_dst_ports'].add(packet[UDP].dport)
                stats['unique_src_ports'].add(packet[UDP].sport)
                
            elif ICMP in packet:
                stats['icmp_count'] += 1
            
            # Extract features for ML
            features = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'packet_size': len(packet),
                'protocol': packet[IP].proto,
                'ttl': packet[IP].ttl if hasattr(packet[IP], 'ttl') else 0,
            }
            
            if TCP in packet:
                features.update({
                    'src_port': packet[TCP].sport,
                    'dst_port': packet[TCP].dport,
                    'tcp_flags': int(packet[TCP].flags),
                })
            elif UDP in packet:
                features.update({
                    'src_port': packet[UDP].sport,
                    'dst_port': packet[UDP].dport,
                    'tcp_flags': 0,
                })
            else:
                features.update({
                    'src_port': 0,
                    'dst_port': 0,
                    'tcp_flags': 0,
                })
                
        return features
    
    def get_aggregated_features(self, src_ip):
        """Get aggregated features for ML model"""
        stats = self.packet_stats[src_ip]
        
        # Calculate packet rate
        recent_packets = len([t for t in stats['timestamps'] 
                            if time.time() - t < self.time_window])
        packet_rate = recent_packets / self.time_window
        
        return [
            stats['packet_count'],
            stats['byte_count'],
            stats['tcp_count'],
            stats['udp_count'],
            stats['icmp_count'],
            stats['syn_count'],
            len(stats['unique_dst_ports']),
            len(stats['unique_src_ports']),
            packet_rate,
        ]


class RuleEngine:
    """Signature-based detection for known attack patterns"""
    
    def __init__(self):
        self.port_scan_threshold = 20  # unique ports in time window
        self.syn_flood_threshold = 100  # SYN packets per second
        self.icmp_flood_threshold = 50   # ICMP packets per second
        self.alerts = []
        
    def check_port_scan(self, src_ip, stats):
        """Detect port scanning activity"""
        unique_ports = len(stats['unique_dst_ports'])
        if unique_ports > self.port_scan_threshold:
            alert = {
                'type': 'PORT_SCAN',
                'src_ip': src_ip,
                'severity': 'HIGH',
                'details': f'Scanned {unique_ports} unique ports',
                'timestamp': datetime.now().isoformat()
            }
            self.alerts.append(alert)
            logging.warning(f"PORT SCAN detected from {src_ip}: {unique_ports} ports")
            return True
        return False
    
    def check_syn_flood(self, src_ip, stats):
        """Detect SYN flood attacks"""
        recent_time = time.time() - 1  # Last second
        recent_syns = len([t for t in stats['timestamps'] 
                          if t > recent_time and stats['syn_count'] > 0])
        
        if recent_syns > self.syn_flood_threshold:
            alert = {
                'type': 'SYN_FLOOD',
                'src_ip': src_ip,
                'severity': 'CRITICAL',
                'details': f'{recent_syns} SYN packets in 1 second',
                'timestamp': datetime.now().isoformat()
            }
            self.alerts.append(alert)
            logging.critical(f"SYN FLOOD detected from {src_ip}")
            return True
        return False
    
    def check_icmp_flood(self, src_ip, stats):
        """Detect ICMP flood attacks"""
        recent_time = time.time() - 1
        recent_icmp = stats['icmp_count'] if time.time() - list(stats['timestamps'])[-1] < 1 else 0
        
        if recent_icmp > self.icmp_flood_threshold:
            alert = {
                'type': 'ICMP_FLOOD',
                'src_ip': src_ip,
                'severity': 'HIGH',
                'details': f'{recent_icmp} ICMP packets in 1 second',
                'timestamp': datetime.now().isoformat()
            }
            self.alerts.append(alert)
            logging.warning(f"ICMP FLOOD detected from {src_ip}")
            return True
        return False
    
    def check_suspicious_ports(self, packet):
        """Check for connections to suspicious ports"""
        suspicious_ports = [31337, 12345, 6667, 1337, 27374]  # Common backdoor ports
        
        if TCP in packet or UDP in packet:
            layer = TCP if TCP in packet else UDP
            if layer.dport in suspicious_ports or layer.sport in suspicious_ports:
                alert = {
                    'type': 'SUSPICIOUS_PORT',
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'port': layer.dport if layer.dport in suspicious_ports else layer.sport,
                    'severity': 'MEDIUM',
                    'timestamp': datetime.now().isoformat()
                }
                self.alerts.append(alert)
                logging.warning(f"Suspicious port activity: {alert}")
                return True
        return False


class MLDetector:
    """Machine Learning based anomaly detection"""
    
    def __init__(self, contamination=0.1):
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.training_data = []
        self.min_samples = 100
        
    def add_training_sample(self, features):
        """Add sample to training dataset"""
        self.training_data.append(features)
        
        # Retrain periodically
        if len(self.training_data) >= self.min_samples and len(self.training_data) % 50 == 0:
            self.train()
    
    def train(self):
        """Train the ML model"""
        if len(self.training_data) < self.min_samples:
            logging.info(f"Need {self.min_samples - len(self.training_data)} more samples to train")
            return
        
        X = np.array(self.training_data)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_trained = True
        logging.info(f"ML model trained on {len(self.training_data)} samples")
    
    def predict(self, features):
        """Predict if traffic is anomalous"""
        if not self.is_trained:
            return 0, 0.0
        
        X = np.array([features])
        X_scaled = self.scaler.transform(X)
        prediction = self.model.predict(X_scaled)[0]
        anomaly_score = self.model.score_samples(X_scaled)[0]
        
        return prediction, anomaly_score
    
    def save_model(self, filepath='ml_model.pkl'):
        """Save trained model"""
        if self.is_trained:
            with open(filepath, 'wb') as f:
                pickle.dump({
                    'model': self.model,
                    'scaler': self.scaler,
                    'training_data': self.training_data
                }, f)
            logging.info(f"Model saved to {filepath}")
    
    def load_model(self, filepath='ml_model.pkl'):
        """Load trained model"""
        try:
            with open(filepath, 'rb') as f:
                data = pickle.load(f)
                self.model = data['model']
                self.scaler = data['scaler']
                self.training_data = data['training_data']
                self.is_trained = True
            logging.info(f"Model loaded from {filepath}")
        except FileNotFoundError:
            logging.info("No saved model found")


class NetSentinel:
    """Main IDS/IPS system"""
    
    def __init__(self, interface='eth0', mode='ids'):
        self.interface = interface
        self.mode = mode  # 'ids' or 'ips'
        self.monitor = NetworkMonitor()
        self.rule_engine = RuleEngine()
        self.ml_detector = MLDetector()
        self.blocked_ips = set()
        self.running = False
        
        # Load existing model if available
        self.ml_detector.load_model()
        
    def packet_handler(self, packet):
        """Process each captured packet"""
        try:
            # Extract features
            features = self.monitor.process_packet(packet)
            
            if not features:
                return
            
            src_ip = features['src_ip']
            
            # Check if IP is already blocked
            if src_ip in self.blocked_ips:
                return
            
            # Rule-based detection
            stats = self.monitor.packet_stats[src_ip]
            
            # Check for various attacks
            threats = []
            if self.rule_engine.check_port_scan(src_ip, stats):
                threats.append('PORT_SCAN')
            if self.rule_engine.check_syn_flood(src_ip, stats):
                threats.append('SYN_FLOOD')
            if self.rule_engine.check_icmp_flood(src_ip, stats):
                threats.append('ICMP_FLOOD')
            if self.rule_engine.check_suspicious_ports(packet):
                threats.append('SUSPICIOUS_PORT')
            
            # ML-based detection
            agg_features = self.monitor.get_aggregated_features(src_ip)
            self.ml_detector.add_training_sample(agg_features)
            
            prediction, score = self.ml_detector.predict(agg_features)
            
            if prediction == -1:  # Anomaly detected
                alert = {
                    'type': 'ML_ANOMALY',
                    'src_ip': src_ip,
                    'severity': 'MEDIUM',
                    'anomaly_score': float(score),
                    'timestamp': datetime.now().isoformat()
                }
                self.rule_engine.alerts.append(alert)
                logging.warning(f"ML Anomaly detected from {src_ip}: score={score:.3f}")
                threats.append('ML_ANOMALY')
            
            # IPS mode: Block malicious IPs
            if self.mode == 'ips' and threats:
                self.block_ip(src_ip, threats)
            
            # Export alerts in real-time if any threats were detected
            if threats:
                self.export_alerts()
                
        except Exception as e:
            logging.error(f"Error processing packet: {e}")
    
    def block_ip(self, ip, threats):
        """Block an IP address (IPS mode)"""
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            logging.critical(f"BLOCKED IP: {ip} - Threats: {', '.join(threats)}")
            
            # In a real implementation, you would add iptables rules here
            # os.system(f"iptables -A INPUT -s {ip} -j DROP")
    
    def start(self):
        """Start the IDS/IPS"""
        self.running = True
        logging.info(f"NetSentinel starting in {self.mode.upper()} mode on {self.interface}")
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=self.status_monitor)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Start packet capture
        try:
            sniff(iface=self.interface, prn=self.packet_handler, store=False)
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            logging.error(f"Error during packet capture: {e}")
            logging.info("Note: You may need to run with sudo/administrator privileges")
    
    def status_monitor(self):
        """Periodic status reporting"""
        while self.running:
            time.sleep(60)
            
            total_ips = len(self.monitor.packet_stats)
            total_alerts = len(self.rule_engine.alerts)
            blocked = len(self.blocked_ips)
            
            logging.info(f"Status: {total_ips} IPs monitored, {total_alerts} alerts, {blocked} blocked")
            
            # Save ML model periodically
            self.ml_detector.save_model()
            
            # Export alerts periodically (so dashboard can read them)
            self.export_alerts()
    
    def stop(self):
        """Stop the IDS/IPS"""
        self.running = False
        logging.info("NetSentinel stopping...")
        
        # Save final model
        self.ml_detector.save_model()
        
        # Export alerts
        self.export_alerts()
    
    def export_alerts(self, filepath='alerts.json'):
        """Export alerts to JSON file"""
        with open(filepath, 'w') as f:
            json.dump(self.rule_engine.alerts, f, indent=2)
        logging.info(f"Alerts exported to {filepath}")


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='NetSentinel - Lightweight IDS/IPS')
    parser.add_argument('-i', '--interface', default='eth0', help='Network interface to monitor')
    parser.add_argument('-m', '--mode', choices=['ids', 'ips'], default='ids',
                       help='Operation mode: ids (detection) or ips (prevention)')
    
    args = parser.parse_args()
    
    sentinel = NetSentinel(interface=args.interface, mode=args.mode)
    sentinel.start()
