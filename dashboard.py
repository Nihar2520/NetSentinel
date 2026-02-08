#!/usr/bin/env python3
"""
NetSentinel Dashboard - Clean & Adaptive Real-time Visualization
Redesigned for better layout and readability
"""

import json
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from matplotlib.gridspec import GridSpec
import pandas as pd
from datetime import datetime
from collections import defaultdict, Counter
import numpy as np

# Set modern style
plt.style.use('seaborn-v0_8-darkgrid')

class NetSentinelDashboard:
    """Clean and adaptive real-time dashboard for NetSentinel"""
    
    def __init__(self, log_file='netsentinel.log', alert_file='alerts.json'):
        self.log_file = log_file
        self.alert_file = alert_file
        
        # Data structures
        self.alert_counts = defaultdict(int)
        self.timeline_data = []
        self.severity_counts = defaultdict(int)
        self.top_attackers = defaultdict(int)
        
        # Create figure with better layout
        self.fig = plt.figure(figsize=(16, 10), facecolor='#f5f5f5')
        self.fig.canvas.manager.set_window_title('NetSentinel Security Dashboard')
        
        # Add main title
        self.fig.suptitle('NetSentinel - Real-time Security Dashboard', 
                         fontsize=18, fontweight='bold', color='#2c3e50', y=0.98)
        
        # Create adaptive grid layout
        gs = GridSpec(3, 3, figure=self.fig, hspace=0.4, wspace=0.3,
                     left=0.08, right=0.95, top=0.93, bottom=0.08)
        
        # Define subplots with better spacing
        self.ax1 = self.fig.add_subplot(gs[0, :2])  # Alert timeline (wide)
        self.ax2 = self.fig.add_subplot(gs[0, 2])   # Alert type pie
        self.ax3 = self.fig.add_subplot(gs[1, :2])  # Severity over time
        self.ax4 = self.fig.add_subplot(gs[1, 2])   # Severity distribution
        self.ax5 = self.fig.add_subplot(gs[2, :])   # Top attackers
        
        # Status text
        self.status_text = self.fig.text(0.5, 0.02, '', ha='center', 
                                         fontsize=11, style='italic', color='#34495e')
        
    def load_alerts(self):
        """Load alerts from JSON file"""
        try:
            with open(self.alert_file, 'r') as f:
                alerts = json.load(f)
            return alerts if alerts else []
        except (FileNotFoundError, json.JSONDecodeError):
            return []
    
    def process_alerts(self, alerts):
        """Process alerts for visualization"""
        self.alert_counts.clear()
        self.severity_counts.clear()
        self.top_attackers.clear()
        self.timeline_data = []
        
        if not alerts:
            return
        
        for alert in alerts:
            # Count by type
            alert_type = alert.get('type', 'UNKNOWN')
            self.alert_counts[alert_type] += 1
            
            # Count by severity
            severity = alert.get('severity', 'UNKNOWN')
            self.severity_counts[severity] += 1
            
            # Track attackers
            src_ip = alert.get('src_ip', 'unknown')
            if src_ip != 'unknown':
                self.top_attackers[src_ip] += 1
            
            # Timeline
            timestamp = alert.get('timestamp', '')
            if timestamp:
                try:
                    self.timeline_data.append({
                        'time': datetime.fromisoformat(timestamp),
                        'type': alert_type,
                        'severity': severity
                    })
                except:
                    pass
        
        # Sort timeline by time
        self.timeline_data.sort(key=lambda x: x['time'])
    
    def update_plot(self, frame):
        """Update all plots with clean, adaptive design"""
        # Load and process latest alerts
        alerts = self.load_alerts()
        self.process_alerts(alerts)
        
        # Clear all axes
        for ax in [self.ax1, self.ax2, self.ax3, self.ax4, self.ax5]:
            ax.clear()
        
        # Color schemes
        severity_colors = {
            'CRITICAL': '#e74c3c',
            'HIGH': '#e67e22',
            'MEDIUM': '#f39c12',
            'LOW': '#27ae60'
        }
        
        # ==================== PLOT 1: Alert Timeline ====================
        if self.timeline_data:
            df = pd.DataFrame(self.timeline_data)
            df['time_rounded'] = pd.to_datetime(df['time']).dt.floor('1min')
            
            # Count alerts per minute
            timeline_counts = df.groupby('time_rounded').size()
            
            # Plot with clean styling
            self.ax1.plot(timeline_counts.index, timeline_counts.values, 
                         color='#3498db', linewidth=2.5, marker='o', 
                         markersize=6, markerfacecolor='#2980b9', 
                         markeredgewidth=0, alpha=0.8)
            
            self.ax1.fill_between(timeline_counts.index, timeline_counts.values, 
                                 alpha=0.2, color='#3498db')
            
            self.ax1.set_title('Alert Timeline', fontsize=13, fontweight='bold', 
                              pad=10, color='#2c3e50')
            self.ax1.set_xlabel('Time', fontsize=10, color='#34495e')
            self.ax1.set_ylabel('Alerts per Minute', fontsize=10, color='#34495e')
            self.ax1.grid(True, alpha=0.3, linestyle='--', linewidth=0.5)
            self.ax1.tick_params(labelsize=9)
            
            # Format x-axis dates
            self.fig.autofmt_xdate(rotation=30, ha='right')
        else:
            self.ax1.text(0.5, 0.5, 'No alerts yet\nWaiting for data...', 
                         ha='center', va='center', fontsize=12, 
                         color='#7f8c8d', style='italic',
                         transform=self.ax1.transAxes)
            self.ax1.set_title('Alert Timeline', fontsize=13, fontweight='bold', 
                              pad=10, color='#2c3e50')
        
        # ==================== PLOT 2: Alert Type Distribution ====================
        if self.alert_counts:
            colors = plt.cm.Set3(range(len(self.alert_counts)))
            
            wedges, texts, autotexts = self.ax2.pie(
                self.alert_counts.values(),
                labels=self.alert_counts.keys(),
                autopct='%1.1f%%',
                colors=colors,
                startangle=90,
                textprops={'fontsize': 9, 'weight': 'bold'},
                pctdistance=0.75
            )
            
            # Style the percentages
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_fontsize(9)
                autotext.set_weight('bold')
            
            # Style the labels
            for text in texts:
                text.set_fontsize(8)
                text.set_color('#2c3e50')
            
            self.ax2.set_title('Attack Types', fontsize=13, fontweight='bold', 
                              pad=10, color='#2c3e50')
        else:
            self.ax2.text(0.5, 0.5, 'No data', ha='center', va='center', 
                         fontsize=11, color='#7f8c8d', style='italic',
                         transform=self.ax2.transAxes)
            self.ax2.set_title('Attack Types', fontsize=13, fontweight='bold', 
                              pad=10, color='#2c3e50')
        
        # ==================== PLOT 3: Severity Timeline ====================
        if self.timeline_data:
            df = pd.DataFrame(self.timeline_data)
            df['time_rounded'] = pd.to_datetime(df['time']).dt.floor('1min')
            
            # Count by severity over time
            severity_timeline = df.groupby(['time_rounded', 'severity']).size().unstack(fill_value=0)
            
            # Plot stacked area chart
            severity_timeline.plot(kind='area', stacked=True, ax=self.ax3, 
                                  color=[severity_colors.get(s, '#95a5a6') 
                                        for s in severity_timeline.columns],
                                  alpha=0.7, linewidth=0)
            
            self.ax3.set_title('Severity Timeline', fontsize=13, fontweight='bold', 
                              pad=10, color='#2c3e50')
            self.ax3.set_xlabel('Time', fontsize=10, color='#34495e')
            self.ax3.set_ylabel('Alert Count', fontsize=10, color='#34495e')
            self.ax3.legend(loc='upper left', fontsize=8, framealpha=0.9)
            self.ax3.grid(True, alpha=0.3, linestyle='--', linewidth=0.5)
            self.ax3.tick_params(labelsize=9)
        else:
            self.ax3.text(0.5, 0.5, 'No data', ha='center', va='center', 
                         fontsize=11, color='#7f8c8d', style='italic',
                         transform=self.ax3.transAxes)
            self.ax3.set_title('Severity Timeline', fontsize=13, fontweight='bold', 
                              pad=10, color='#2c3e50')
        
        # ==================== PLOT 4: Severity Distribution ====================
        if self.severity_counts:
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            severities = [s for s in severity_order if s in self.severity_counts]
            counts = [self.severity_counts[s] for s in severities]
            bar_colors = [severity_colors.get(s, '#95a5a6') for s in severities]
            
            bars = self.ax4.barh(severities, counts, color=bar_colors, 
                                alpha=0.8, edgecolor='white', linewidth=1.5)
            
            # Add value labels
            for i, (bar, count) in enumerate(zip(bars, counts)):
                self.ax4.text(count + max(counts)*0.02, i, str(count),
                            va='center', fontsize=10, fontweight='bold', 
                            color='#2c3e50')
            
            self.ax4.set_title('Severity Levels', fontsize=13, fontweight='bold', 
                              pad=10, color='#2c3e50')
            self.ax4.set_xlabel('Count', fontsize=10, color='#34495e')
            self.ax4.tick_params(labelsize=9)
            self.ax4.grid(True, axis='x', alpha=0.3, linestyle='--', linewidth=0.5)
        else:
            self.ax4.text(0.5, 0.5, 'No data', ha='center', va='center', 
                         fontsize=11, color='#7f8c8d', style='italic',
                         transform=self.ax4.transAxes)
            self.ax4.set_title('Severity Levels', fontsize=13, fontweight='bold', 
                              pad=10, color='#2c3e50')
        
        # ==================== PLOT 5: Top Attackers ====================
        if self.top_attackers:
            top_10 = sorted(self.top_attackers.items(), 
                          key=lambda x: x[1], reverse=True)[:10]
            ips = [ip for ip, _ in top_10]
            counts = [count for _, count in top_10]
            
            # Create gradient colors
            colors_gradient = plt.cm.Reds(np.linspace(0.4, 0.9, len(ips)))
            
            bars = self.ax5.barh(ips, counts, color=colors_gradient, 
                                alpha=0.8, edgecolor='white', linewidth=1.5)
            
            # Add value labels
            for i, (bar, count) in enumerate(zip(bars, counts)):
                self.ax5.text(count + max(counts)*0.02, i, str(count),
                            va='center', fontsize=10, fontweight='bold', 
                            color='#2c3e50')
            
            self.ax5.set_title('Top 10 Attacking IPs', fontsize=13, 
                              fontweight='bold', pad=10, color='#2c3e50')
            self.ax5.set_xlabel('Alert Count', fontsize=10, color='#34495e')
            self.ax5.invert_yaxis()
            self.ax5.tick_params(labelsize=9)
            self.ax5.grid(True, axis='x', alpha=0.3, linestyle='--', linewidth=0.5)
        else:
            self.ax5.text(0.5, 0.5, 'No attackers detected yet', 
                         ha='center', va='center', fontsize=11, 
                         color='#7f8c8d', style='italic',
                         transform=self.ax5.transAxes)
            self.ax5.set_title('Top 10 Attacking IPs', fontsize=13, 
                              fontweight='bold', pad=10, color='#2c3e50')
        
        # ==================== Update Status Text ====================
        total_alerts = len(alerts)
        unique_ips = len(self.top_attackers)
        last_update = datetime.now().strftime('%H:%M:%S')
        
        if total_alerts > 0:
            critical_count = self.severity_counts.get('CRITICAL', 0)
            high_count = self.severity_counts.get('HIGH', 0)
            
            status = f"📊 Total Alerts: {total_alerts} | 👥 Unique IPs: {unique_ips} | "
            status += f"🔴 Critical: {critical_count} | 🟠 High: {high_count} | "
            status += f"🕒 Last Update: {last_update}"
        else:
            status = f"✅ No alerts detected | System monitoring active | 🕒 Last Update: {last_update}"
        
        self.status_text.set_text(status)
    
    def run(self, interval=5000):
        """Start the dashboard with auto-refresh"""
        print("╔══════════════════════════════════════════════════════════╗")
        print("║     NetSentinel Dashboard - Real-time Monitoring         ║")
        print("╚══════════════════════════════════════════════════════════╝")
        print(f"\n✓ Dashboard started")
        print(f"✓ Monitoring: {self.alert_file}")
        print(f"✓ Refresh interval: {interval/1000} seconds")
        print(f"✓ Close window to exit\n")
        
        ani = animation.FuncAnimation(
            self.fig, 
            self.update_plot, 
            interval=interval,
            cache_frame_data=False,
            blit=False
        )
        
        plt.show()


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='NetSentinel Dashboard - Clean & Adaptive')
    parser.add_argument('-f', '--file', default='alerts.json', 
                       help='Alert JSON file to monitor (default: alerts.json)')
    parser.add_argument('-i', '--interval', type=int, default=5, 
                       help='Refresh interval in seconds (default: 5)')
    
    args = parser.parse_args()
    
    dashboard = NetSentinelDashboard(alert_file=args.file)
    dashboard.run(interval=args.interval * 1000)