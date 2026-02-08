#!/usr/bin/env python3
"""
Alert Analyzer - Advanced analysis and reporting for NetSentinel alerts
"""

import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import argparse

class AlertAnalyzer:
    """Analyze and generate reports from NetSentinel alerts"""
    
    def __init__(self, alert_file='alerts.json'):
        self.alert_file = alert_file
        self.alerts = self.load_alerts()
        self.df = None
        
    def load_alerts(self):
        """Load alerts from JSON file"""
        try:
            with open(self.alert_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Alert file '{self.alert_file}' not found")
            return []
    
    def to_dataframe(self):
        """Convert alerts to pandas DataFrame"""
        if not self.alerts:
            print("No alerts to analyze")
            return None
        
        # Flatten alerts into DataFrame
        data = []
        for alert in self.alerts:
            row = {
                'timestamp': datetime.fromisoformat(alert['timestamp']),
                'type': alert['type'],
                'severity': alert['severity'],
                'src_ip': alert.get('src_ip', 'unknown'),
                'dst_ip': alert.get('dst_ip', 'N/A'),
                'details': alert.get('details', ''),
                'port': alert.get('port', 'N/A'),
                'anomaly_score': alert.get('anomaly_score', 0.0)
            }
            data.append(row)
        
        self.df = pd.DataFrame(data)
        self.df['hour'] = self.df['timestamp'].dt.hour
        self.df['day'] = self.df['timestamp'].dt.day_name()
        self.df['date'] = self.df['timestamp'].dt.date
        
        return self.df
    
    def summary_stats(self):
        """Print summary statistics"""
        if self.df is None:
            self.to_dataframe()
        
        if self.df is None:
            return
        
        print("\n" + "="*60)
        print("NETSENTINEL ALERT SUMMARY")
        print("="*60)
        
        # Basic stats
        print(f"\nTotal Alerts: {len(self.df)}")
        print(f"Time Range: {self.df['timestamp'].min()} to {self.df['timestamp'].max()}")
        print(f"Duration: {self.df['timestamp'].max() - self.df['timestamp'].min()}")
        
        # Alert types
        print("\n--- Alert Type Distribution ---")
        type_counts = self.df['type'].value_counts()
        for alert_type, count in type_counts.items():
            percentage = (count / len(self.df)) * 100
            print(f"{alert_type:20s}: {count:4d} ({percentage:5.1f}%)")
        
        # Severity distribution
        print("\n--- Severity Distribution ---")
        severity_counts = self.df['severity'].value_counts()
        for severity, count in severity_counts.items():
            percentage = (count / len(self.df)) * 100
            print(f"{severity:15s}: {count:4d} ({percentage:5.1f}%)")
        
        # Top attackers
        print("\n--- Top 10 Source IPs ---")
        top_ips = self.df['src_ip'].value_counts().head(10)
        for i, (ip, count) in enumerate(top_ips.items(), 1):
            print(f"{i:2d}. {ip:15s}: {count:4d} alerts")
        
        # Hourly distribution
        print("\n--- Peak Attack Hours ---")
        hourly = self.df['hour'].value_counts().sort_index()
        top_hours = hourly.nlargest(5)
        for hour, count in top_hours.items():
            print(f"Hour {hour:02d}:00: {count:4d} alerts")
        
        print("\n" + "="*60 + "\n")
    
    def generate_report(self, output_file='alert_report.txt'):
        """Generate detailed text report"""
        if self.df is None:
            self.to_dataframe()
        
        if self.df is None:
            return
        
        with open(output_file, 'w') as f:
            f.write("="*80 + "\n")
            f.write("NETSENTINEL SECURITY ANALYSIS REPORT\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*80 + "\n\n")
            
            # Executive Summary
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-"*80 + "\n")
            f.write(f"Total Security Events: {len(self.df)}\n")
            f.write(f"Analysis Period: {self.df['timestamp'].min()} to {self.df['timestamp'].max()}\n")
            f.write(f"Unique Source IPs: {self.df['src_ip'].nunique()}\n")
            
            critical_count = len(self.df[self.df['severity'] == 'CRITICAL'])
            high_count = len(self.df[self.df['severity'] == 'HIGH'])
            f.write(f"\nCritical Threats: {critical_count}\n")
            f.write(f"High-Severity Threats: {high_count}\n\n")
            
            # Threat Breakdown
            f.write("\nTHREAT TYPE ANALYSIS\n")
            f.write("-"*80 + "\n")
            for alert_type, count in self.df['type'].value_counts().items():
                f.write(f"{alert_type}: {count}\n")
                
                # Get sample of this type
                samples = self.df[self.df['type'] == alert_type].head(3)
                for _, sample in samples.iterrows():
                    f.write(f"  [{sample['timestamp']}] {sample['src_ip']} - {sample['details']}\n")
                f.write("\n")
            
            # Top Attackers
            f.write("\nTOP 20 ATTACKING IPs\n")
            f.write("-"*80 + "\n")
            f.write(f"{'Rank':<6} {'IP Address':<16} {'Alerts':<8} {'Primary Attack Type'}\n")
            f.write("-"*80 + "\n")
            
            top_attackers = self.df['src_ip'].value_counts().head(20)
            for rank, (ip, count) in enumerate(top_attackers.items(), 1):
                primary_attack = self.df[self.df['src_ip'] == ip]['type'].mode()[0]
                f.write(f"{rank:<6} {ip:<16} {count:<8} {primary_attack}\n")
            
            # Temporal Analysis
            f.write("\n\nTEMPORAL ANALYSIS\n")
            f.write("-"*80 + "\n")
            
            daily_counts = self.df.groupby('date').size()
            f.write("\nDaily Alert Counts:\n")
            for date, count in daily_counts.items():
                f.write(f"{date}: {count}\n")
            
            f.write("\nHourly Distribution:\n")
            hourly_counts = self.df['hour'].value_counts().sort_index()
            for hour, count in hourly_counts.items():
                bar = '█' * int(count / hourly_counts.max() * 50)
                f.write(f"{hour:02d}:00 | {bar} {count}\n")
            
            # Recommendations
            f.write("\n\nRECOMMENDATIONS\n")
            f.write("-"*80 + "\n")
            
            # Check for port scans
            port_scans = len(self.df[self.df['type'] == 'PORT_SCAN'])
            if port_scans > 0:
                f.write(f"1. {port_scans} port scan attempts detected. Consider:\n")
                f.write("   - Implementing rate limiting on open ports\n")
                f.write("   - Using port knocking for sensitive services\n\n")
            
            # Check for DDoS
            ddos_types = ['SYN_FLOOD', 'UDP_FLOOD', 'ICMP_FLOOD']
            ddos_count = len(self.df[self.df['type'].isin(ddos_types)])
            if ddos_count > 0:
                f.write(f"2. {ddos_count} DDoS attack signatures detected. Consider:\n")
                f.write("   - Enabling rate limiting at the network edge\n")
                f.write("   - Implementing SYN cookies\n")
                f.write("   - Using a DDoS mitigation service\n\n")
            
            # Check for persistent attackers
            persistent = self.df['src_ip'].value_counts()
            highly_persistent = persistent[persistent > 10]
            if len(highly_persistent) > 0:
                f.write(f"3. {len(highly_persistent)} IPs with >10 alerts. Consider:\n")
                f.write("   - Implementing automatic IP blocking\n")
                f.write("   - Adding these IPs to firewall blacklist\n")
                f.write("   - Investigating if these are compromised internal hosts\n\n")
        
        print(f"Report generated: {output_file}")
    
    def visualize(self, output_dir='plots'):
        """Generate visualization plots"""
        if self.df is None:
            self.to_dataframe()
        
        if self.df is None:
            return
        
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        sns.set_style('whitegrid')
        
        # 1. Alert timeline
        plt.figure(figsize=(12, 6))
        self.df.groupby(self.df['timestamp'].dt.date).size().plot(kind='line', marker='o')
        plt.title('Alert Timeline', fontsize=14, fontweight='bold')
        plt.xlabel('Date')
        plt.ylabel('Number of Alerts')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(f'{output_dir}/timeline.png', dpi=300)
        print(f"Saved: {output_dir}/timeline.png")
        
        # 2. Attack type distribution
        plt.figure(figsize=(10, 6))
        self.df['type'].value_counts().plot(kind='barh', color='coral')
        plt.title('Attack Type Distribution', fontsize=14, fontweight='bold')
        plt.xlabel('Count')
        plt.tight_layout()
        plt.savefig(f'{output_dir}/attack_types.png', dpi=300)
        print(f"Saved: {output_dir}/attack_types.png")
        
        # 3. Severity heatmap by day and hour
        plt.figure(figsize=(12, 6))
        pivot = self.df.pivot_table(
            values='timestamp',
            index='day',
            columns='hour',
            aggfunc='count',
            fill_value=0
        )
        
        # Reorder days
        day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        pivot = pivot.reindex([d for d in day_order if d in pivot.index])
        
        sns.heatmap(pivot, cmap='YlOrRd', annot=True, fmt='g', cbar_kws={'label': 'Alert Count'})
        plt.title('Alert Heatmap by Day and Hour', fontsize=14, fontweight='bold')
        plt.tight_layout()
        plt.savefig(f'{output_dir}/heatmap.png', dpi=300)
        print(f"Saved: {output_dir}/heatmap.png")
        
        # 4. Top attackers
        plt.figure(figsize=(10, 6))
        self.df['src_ip'].value_counts().head(15).plot(kind='barh', color='darkred')
        plt.title('Top 15 Attacking IPs', fontsize=14, fontweight='bold')
        plt.xlabel('Alert Count')
        plt.tight_layout()
        plt.savefig(f'{output_dir}/top_attackers.png', dpi=300)
        print(f"Saved: {output_dir}/top_attackers.png")
        
        # 5. Severity distribution pie chart
        plt.figure(figsize=(8, 8))
        colors = {'CRITICAL': '#d32f2f', 'HIGH': '#f57c00', 'MEDIUM': '#fbc02d', 'LOW': '#388e3c'}
        severity_counts = self.df['severity'].value_counts()
        plot_colors = [colors.get(s, 'gray') for s in severity_counts.index]
        
        plt.pie(severity_counts.values, labels=severity_counts.index, autopct='%1.1f%%',
                colors=plot_colors, startangle=90)
        plt.title('Alert Severity Distribution', fontsize=14, fontweight='bold')
        plt.tight_layout()
        plt.savefig(f'{output_dir}/severity.png', dpi=300)
        print(f"Saved: {output_dir}/severity.png")
        
        plt.close('all')
        print(f"\nAll plots saved to '{output_dir}/' directory")
    
    def export_csv(self, output_file='alerts.csv'):
        """Export alerts to CSV"""
        if self.df is None:
            self.to_dataframe()
        
        if self.df is None:
            return
        
        self.df.to_csv(output_file, index=False)
        print(f"Alerts exported to: {output_file}")


def main():
    parser = argparse.ArgumentParser(description='NetSentinel Alert Analyzer')
    parser.add_argument('-f', '--file', default='alerts.json', help='Alert JSON file')
    parser.add_argument('-a', '--action', 
                       choices=['summary', 'report', 'visualize', 'export', 'all'],
                       default='all',
                       help='Analysis action to perform')
    parser.add_argument('-o', '--output', default='alert_report.txt',
                       help='Output file for report')
    
    args = parser.parse_args()
    
    analyzer = AlertAnalyzer(args.file)
    
    if not analyzer.alerts:
        print("No alerts found. Run NetSentinel to generate alerts first.")
        return
    
    print(f"\nLoaded {len(analyzer.alerts)} alerts from {args.file}\n")
    
    if args.action in ['summary', 'all']:
        analyzer.summary_stats()
    
    if args.action in ['report', 'all']:
        analyzer.generate_report(args.output)
    
    if args.action in ['visualize', 'all']:
        analyzer.visualize()
    
    if args.action in ['export', 'all']:
        analyzer.export_csv()
    
    print("\nAnalysis complete!")


if __name__ == '__main__':
    main()
