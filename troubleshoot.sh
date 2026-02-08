#!/bin/bash

# NetSentinel Troubleshooting & Diagnostics Script
# Run this if you encounter problems

echo "======================================================================"
echo "          NetSentinel - Diagnostic & Troubleshooting Tool"
echo "======================================================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_check() {
    echo -e "${BLUE}[CHECK]${NC} $1"
}

print_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_fix() {
    echo -e "${GREEN}[FIX]${NC} $1"
}

ISSUES_FOUND=0

# System Information
echo "System Information:"
echo "===================="
uname -a
echo ""

# Check 1: Operating System
print_check "Checking operating system compatibility..."
if [ -f /etc/os-release ]; then
    . /etc/os-release
    print_pass "OS: $NAME $VERSION"
else
    print_fail "Cannot determine OS"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
fi
echo ""

# Check 2: Python Installation
print_check "Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)
    
    if [ "$PYTHON_MAJOR" -ge 3 ] && [ "$PYTHON_MINOR" -ge 8 ]; then
        print_pass "Python $PYTHON_VERSION (OK)"
    else
        print_fail "Python $PYTHON_VERSION (Need 3.8+)"
        print_fix "Install Python 3.8+: sudo apt-get install python3.8"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
else
    print_fail "Python 3 not found"
    print_fix "Install Python: sudo apt-get install python3"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
fi
echo ""

# Check 3: Pip Installation
print_check "Checking pip installation..."
if command -v pip3 &> /dev/null; then
    print_pass "pip3 is installed"
else
    print_fail "pip3 not found"
    print_fix "Install pip: sudo apt-get install python3-pip"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
fi
echo ""

# Check 4: Required Python Modules
print_check "Checking required Python modules..."

MODULES=("scapy" "numpy" "sklearn" "pandas" "matplotlib")
MISSING_MODULES=()

for module in "${MODULES[@]}"; do
    if python3 -c "import $module" 2>/dev/null; then
        VERSION=$(python3 -c "import $module; print($module.__version__)" 2>/dev/null || echo "unknown")
        print_pass "$module ($VERSION)"
    else
        print_fail "$module not installed"
        MISSING_MODULES+=("$module")
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
done

if [ ${#MISSING_MODULES[@]} -gt 0 ]; then
    echo ""
    print_fix "Install missing modules:"
    echo "  pip3 install -r requirements.txt --break-system-packages"
    echo "  Or: pip3 install ${MISSING_MODULES[*]}"
fi
echo ""

# Check 5: System Dependencies
print_check "Checking system dependencies..."

DEPS=("tcpdump" "libpcap")

for dep in "${DEPS[@]}"; do
    if command -v $dep &> /dev/null || ldconfig -p | grep -q $dep; then
        print_pass "$dep is installed"
    else
        print_fail "$dep not found"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
done

if ! command -v tcpdump &> /dev/null; then
    print_fix "Install tcpdump: sudo apt-get install tcpdump"
fi

if ! ldconfig -p | grep -q libpcap; then
    print_fix "Install libpcap: sudo apt-get install libpcap-dev"
fi
echo ""

# Check 6: File Permissions
print_check "Checking file permissions..."

FILES=("netsentinel.py" "dashboard.py" "traffic_generator.py" "alert_analyzer.py")

for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        if [ -r "$file" ]; then
            print_pass "$file exists and is readable"
        else
            print_fail "$file is not readable"
            print_fix "Fix permissions: chmod +r $file"
            ISSUES_FOUND=$((ISSUES_FOUND + 1))
        fi
    else
        print_fail "$file not found"
        print_warn "Make sure you're in the NetSentinel directory"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
done
echo ""

# Check 7: Network Interfaces
print_check "Checking network interfaces..."

if command -v ip &> /dev/null; then
    INTERFACES=$(ip link show | grep -E '^[0-9]+:' | awk -F': ' '{print $2}' | grep -v lo)
    if [ -n "$INTERFACES" ]; then
        print_pass "Available network interfaces:"
        echo "$INTERFACES" | while read iface; do
            STATE=$(ip link show $iface | grep -oP 'state \K\w+')
            echo "    - $iface (state: $STATE)"
        done
    else
        print_fail "No network interfaces found (other than loopback)"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
else
    print_warn "Cannot check interfaces (ip command not found)"
fi
echo ""

# Check 8: Sudo/Root Access
print_check "Checking privileges..."

if [ "$EUID" -eq 0 ]; then
    print_pass "Running as root (required for packet capture)"
else
    print_warn "Not running as root"
    echo "    Some features require root access"
    echo "    Packet capture requires: sudo python3 netsentinel.py ..."
fi
echo ""

# Check 9: Port Availability
print_check "Checking if tcpdump can capture packets..."

if [ "$EUID" -eq 0 ]; then
    if timeout 2 tcpdump -i lo -c 1 &> /dev/null; then
        print_pass "Packet capture works"
    else
        print_fail "Cannot capture packets"
        print_fix "This might be a permissions issue or no traffic on loopback"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
else
    print_warn "Skipped (requires root)"
fi
echo ""

# Check 10: Disk Space
print_check "Checking disk space..."

AVAILABLE=$(df . | tail -1 | awk '{print $4}')
if [ "$AVAILABLE" -gt 1000000 ]; then
    print_pass "Sufficient disk space available"
else
    print_warn "Low disk space ($(df -h . | tail -1 | awk '{print $4}') available)"
fi
echo ""

# Check 11: Test Python Script Execution
print_check "Testing Python script execution..."

TEST_OUTPUT=$(python3 -c "
import sys
try:
    from scapy.all import IP, TCP
    print('OK')
except Exception as e:
    print(f'ERROR: {e}')
" 2>&1)

if [ "$TEST_OUTPUT" = "OK" ]; then
    print_pass "Can import and use Scapy"
else
    print_fail "Cannot use Scapy: $TEST_OUTPUT"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
fi
echo ""

# Check 12: Previous Run Files
print_check "Checking for previous run files..."

OLD_FILES=("netsentinel.log" "alerts.json" "ml_model.pkl")
FOUND_OLD=0

for file in "${OLD_FILES[@]}"; do
    if [ -f "$file" ]; then
        SIZE=$(ls -lh "$file" | awk '{print $5}')
        print_pass "Found $file ($SIZE)"
        FOUND_OLD=1
    fi
done

if [ $FOUND_OLD -eq 0 ]; then
    print_warn "No previous run files found (this is OK for first run)"
fi
echo ""

# Summary
echo "======================================================================"
echo "                        DIAGNOSTIC SUMMARY"
echo "======================================================================"
echo ""

if [ $ISSUES_FOUND -eq 0 ]; then
    print_pass "All checks passed! NetSentinel should work correctly."
    echo ""
    echo "To start NetSentinel:"
    echo "  sudo python3 netsentinel.py -i eth0 -m ids"
    echo ""
    echo "To run the quick demo:"
    echo "  sudo bash quick_start.sh"
else
    print_fail "Found $ISSUES_FOUND issue(s)"
    echo ""
    echo "Please address the issues above before running NetSentinel."
    echo ""
    echo "Quick fixes:"
    echo "  1. Install missing packages: sudo bash setup.sh"
    echo "  2. Install Python modules: pip3 install -r requirements.txt"
    echo "  3. Make sure you're in the NetSentinel directory"
    echo "  4. Run with sudo for packet capture"
fi

echo ""
echo "======================================================================"
echo "                     COMMON ISSUES & FIXES"
echo "======================================================================"
echo ""

cat << 'EOF'
Issue 1: "Permission denied" when capturing packets
Fix: Run with sudo
  → sudo python3 netsentinel.py -i eth0 -m ids

Issue 2: "No module named 'scapy'"
Fix: Install Python dependencies
  → pip3 install -r requirements.txt --break-system-packages

Issue 3: "No such device eth0"
Fix: Use correct interface name
  → ip link show  # Find your interface
  → sudo python3 netsentinel.py -i <your_interface> -m ids

Issue 4: No alerts being generated
Fix: Generate test traffic
  → sudo python3 traffic_generator.py -t 127.0.0.1 -a mixed

Issue 5: Dashboard doesn't show anything
Fix: Make sure alerts.json exists with data
  → cat alerts.json
  → If empty, run traffic generator first

Issue 6: "Operation not permitted"
Fix: Run with sudo and check permissions
  → sudo python3 netsentinel.py -i eth0 -m ids

Issue 7: High CPU usage
Fix: This is normal during packet capture
  → Consider monitoring a specific subnet only
  → Reduce time window in code

Issue 8: Import errors on Debian/Ubuntu
Fix: Use --break-system-packages flag
  → pip3 install -r requirements.txt --break-system-packages

EOF

echo ""
echo "For more help, see:"
echo "  - DEPLOYMENT_GUIDE.md (step-by-step instructions)"
echo "  - README.md (general documentation)"
echo "  - TECHNICAL_DOCS.md (technical details)"
echo ""
echo "======================================================================"
