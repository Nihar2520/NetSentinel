#!/bin/bash

# NetSentinel Quick Start Demo
# This script runs an automated demo of the entire system

set -e

echo "======================================================================"
echo "              NetSentinel - Automated Demo Script"
echo "======================================================================"
echo ""
echo "This script will:"
echo "  1. Check prerequisites"
echo "  2. Start NetSentinel in background"
echo "  3. Generate test attacks"
echo "  4. Display results"
echo "  5. Generate analysis report"
echo ""
echo "The demo takes about 2-3 minutes to complete."
echo ""
read -p "Press ENTER to start the demo..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    print_error "Please run with sudo: sudo bash quick_start.sh"
    exit 1
fi

print_success "Running as root"

# Step 1: Check prerequisites
print_status "Step 1/5: Checking prerequisites..."

# Check Python
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    print_success "Python $PYTHON_VERSION installed"
else
    print_error "Python 3 not found. Please run setup.sh first."
    exit 1
fi

# Check if scapy is installed
if python3 -c "import scapy" 2>/dev/null; then
    print_success "Scapy installed"
else
    print_error "Scapy not found. Please run: pip3 install -r requirements.txt"
    exit 1
fi

# Check if files exist
if [ ! -f "netsentinel.py" ]; then
    print_error "netsentinel.py not found. Are you in the correct directory?"
    exit 1
fi

print_success "All prerequisites met"
echo ""

# Step 2: Determine network interface
print_status "Step 2/5: Detecting network interface..."

# Use loopback for demo (safest option)
INTERFACE="lo"

# Check if interface exists
if ip link show $INTERFACE &> /dev/null; then
    print_success "Using interface: $INTERFACE"
else
    print_warning "Loopback interface not found, trying eth0..."
    INTERFACE="eth0"
    if ip link show $INTERFACE &> /dev/null; then
        print_success "Using interface: $INTERFACE"
    else
        print_error "No suitable network interface found"
        exit 1
    fi
fi

echo ""

# Step 3: Start NetSentinel
print_status "Step 3/5: Starting NetSentinel..."

# Clean up old files
rm -f netsentinel.log alerts.json ml_model.pkl 2>/dev/null

# Start NetSentinel in background
python3 netsentinel.py -i $INTERFACE -m ids > /dev/null 2>&1 &
NETSENTINEL_PID=$!

# Wait for it to initialize
sleep 3

# Check if it's running
if ps -p $NETSENTINEL_PID > /dev/null; then
    print_success "NetSentinel started (PID: $NETSENTINEL_PID)"
else
    print_error "Failed to start NetSentinel"
    exit 1
fi

echo ""

# Step 4: Generate test traffic
print_status "Step 4/5: Generating test traffic and attacks..."

TARGET="127.0.0.1"

echo ""
print_status "  Running: Normal traffic (10s)..."
timeout 10 python3 traffic_generator.py -t $TARGET -i $INTERFACE -a normal -d 10 2>/dev/null || true
sleep 2
print_success "  Normal traffic completed"

echo ""
print_status "  Running: Port scan attack..."
python3 traffic_generator.py -t $TARGET -i $INTERFACE -a port_scan 2>/dev/null || true
sleep 2
print_success "  Port scan completed"

echo ""
print_status "  Running: SYN flood attack (10s)..."
timeout 10 python3 traffic_generator.py -t $TARGET -i $INTERFACE -a syn_flood -d 10 2>/dev/null || true
sleep 2
print_success "  SYN flood completed"

echo ""
print_status "  Running: ICMP flood attack (10s)..."
timeout 10 python3 traffic_generator.py -t $TARGET -i $INTERFACE -a icmp_flood -d 10 2>/dev/null || true
sleep 2
print_success "  ICMP flood completed"

echo ""
print_status "  Running: Suspicious port access..."
python3 traffic_generator.py -t $TARGET -i $INTERFACE -a suspicious_ports 2>/dev/null || true
sleep 2
print_success "  Suspicious port access completed"

echo ""
print_success "All attacks simulated successfully"
echo ""

# Give NetSentinel time to process
print_status "Processing alerts..."
sleep 3

# Step 5: Stop NetSentinel and show results
print_status "Step 5/5: Stopping NetSentinel and generating report..."

# Stop NetSentinel gracefully
kill -SIGINT $NETSENTINEL_PID 2>/dev/null || true
sleep 2

# Force kill if still running
if ps -p $NETSENTINEL_PID > /dev/null 2>&1; then
    kill -9 $NETSENTINEL_PID 2>/dev/null || true
fi

print_success "NetSentinel stopped"
echo ""

# Display results
echo "======================================================================"
echo "                        DEMO RESULTS"
echo "======================================================================"
echo ""

# Check if alerts were generated
if [ -f "alerts.json" ]; then
    ALERT_COUNT=$(python3 -c "import json; print(len(json.load(open('alerts.json'))))" 2>/dev/null || echo "0")
    
    if [ "$ALERT_COUNT" -gt 0 ]; then
        print_success "Generated $ALERT_COUNT security alerts"
        echo ""
        
        # Show alert summary
        print_status "Alert Summary:"
        echo ""
        python3 -c "
import json
from collections import Counter

with open('alerts.json', 'r') as f:
    alerts = json.load(f)

# Count by type
types = Counter(alert['type'] for alert in alerts)
print('  Alert Types:')
for alert_type, count in types.most_common():
    print(f'    - {alert_type}: {count}')

print('')

# Count by severity
severities = Counter(alert['severity'] for alert in alerts)
print('  Severity Levels:')
for severity, count in severities.most_common():
    print(f'    - {severity}: {count}')
" 2>/dev/null || print_warning "Could not parse alerts"
        
    else
        print_warning "No alerts generated. This might be normal for loopback interface."
    fi
else
    print_warning "alerts.json not found. NetSentinel may not have captured traffic."
fi

echo ""

# Show some log entries
if [ -f "netsentinel.log" ]; then
    print_status "Recent Log Entries:"
    echo ""
    tail -10 netsentinel.log | sed 's/^/    /'
    echo ""
fi

# Generate analysis if we have alerts
if [ -f "alerts.json" ] && [ "$ALERT_COUNT" -gt 0 ]; then
    print_status "Generating detailed analysis report..."
    python3 alert_analyzer.py -a all > /dev/null 2>&1 || print_warning "Analysis generation had issues"
    
    if [ -f "alert_report.txt" ]; then
        print_success "Analysis report created: alert_report.txt"
    fi
    
    if [ -d "plots" ]; then
        PLOT_COUNT=$(ls -1 plots/*.png 2>/dev/null | wc -l)
        if [ "$PLOT_COUNT" -gt 0 ]; then
            print_success "Generated $PLOT_COUNT visualization plots in plots/ directory"
        fi
    fi
fi

echo ""
echo "======================================================================"
echo "                     GENERATED FILES"
echo "======================================================================"
echo ""

# List all generated files
for file in netsentinel.log alerts.json ml_model.pkl alert_report.txt alerts.csv; do
    if [ -f "$file" ]; then
        SIZE=$(ls -lh "$file" | awk '{print $5}')
        print_success "$file ($SIZE)"
    fi
done

if [ -d "plots" ]; then
    for file in plots/*.png; do
        if [ -f "$file" ]; then
            SIZE=$(ls -lh "$file" | awk '{print $5}')
            FILENAME=$(basename "$file")
            print_success "plots/$FILENAME ($SIZE)"
        fi
    done
fi

echo ""
echo "======================================================================"
echo "                      NEXT STEPS"
echo "======================================================================"
echo ""
echo "1. View detailed report:"
echo "   cat alert_report.txt | less"
echo ""
echo "2. View alerts in JSON:"
echo "   cat alerts.json | python3 -m json.tool | less"
echo ""
echo "3. View visualizations:"
echo "   ls plots/"
echo "   # Open .png files with your image viewer"
echo ""
echo "4. Run dashboard (in a new terminal):"
echo "   python3 dashboard.py"
echo ""
echo "5. Start NetSentinel for real monitoring:"
echo "   sudo python3 netsentinel.py -i eth0 -m ids"
echo ""
echo "6. Read the full guide:"
echo "   cat DEPLOYMENT_GUIDE.md | less"
echo ""
echo "======================================================================"
echo "                   DEMO COMPLETE! 🎉"
echo "======================================================================"
echo ""
print_success "NetSentinel is ready for production use!"
echo ""
