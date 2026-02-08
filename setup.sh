#!/bin/bash

# NetSentinel Setup Script
# Automated installation and configuration

set -e

echo "=========================================="
echo "NetSentinel Setup Script"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run with sudo:"
    echo "sudo bash setup.sh"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
else
    echo "Cannot detect OS. Please install manually."
    exit 1
fi

echo "Detected OS: $OS"
echo ""

# Install system dependencies
echo "[1/4] Installing system dependencies..."

if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
    apt-get update
    apt-get install -y python3 python3-pip tcpdump libpcap-dev python3-dev build-essential
elif [[ "$OS" == *"CentOS"* ]] || [[ "$OS" == *"Red Hat"* ]] || [[ "$OS" == *"Fedora"* ]]; then
    yum install -y python3 python3-pip tcpdump libpcap-devel python3-devel gcc
elif [[ "$OS" == *"Arch"* ]]; then
    pacman -Sy --noconfirm python python-pip tcpdump libpcap
else
    echo "Unsupported OS. Please install dependencies manually:"
    echo "  - Python 3.8+"
    echo "  - pip"
    echo "  - tcpdump"
    echo "  - libpcap-dev"
    exit 1
fi

echo "✓ System dependencies installed"
echo ""

# Install Python dependencies
echo "[2/4] Installing Python dependencies..."

# Try with --break-system-packages flag (needed for Debian 12+, Ubuntu 23.04+)
if pip3 install -r requirements.txt --break-system-packages 2>/dev/null; then
    echo "✓ Python dependencies installed (with --break-system-packages)"
elif pip3 install -r requirements.txt 2>/dev/null; then
    echo "✓ Python dependencies installed"
else
    # If pip fails, try using apt to install system packages
    echo "Installing via apt package manager..."
    apt-get install -y python3-scapy python3-numpy python3-sklearn python3-pandas python3-matplotlib python3-seaborn 2>/dev/null || true
    
    # Some packages might not be in apt, install those with pip
    pip3 install --break-system-packages scapy scikit-learn 2>/dev/null || true
    echo "✓ Python dependencies installed via system packages"
fi

echo ""

# Set up permissions
echo "[3/4] Setting up permissions..."
chmod +x netsentinel.py
chmod +x traffic_generator.py
chmod +x dashboard.py

# Create log directory
mkdir -p /var/log/netsentinel
chmod 755 /var/log/netsentinel

echo "✓ Permissions configured"
echo ""

# Test installation
echo "[4/4] Testing installation..."

python3 -c "
import scapy.all
import sklearn
import numpy
import pandas
import matplotlib
print('All Python modules imported successfully')
" && echo "✓ All dependencies verified"

echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Find your network interface:"
echo "   ip link show"
echo ""
echo "2. Start NetSentinel in IDS mode:"
echo "   sudo python3 netsentinel.py -i <interface> -m ids"
echo ""
echo "3. Start the dashboard (in another terminal):"
echo "   python3 dashboard.py"
echo ""
echo "4. Test with traffic generator:"
echo "   sudo python3 traffic_generator.py -t <target_ip> -a mixed"
echo ""
echo "For more information, see README.md"
echo ""