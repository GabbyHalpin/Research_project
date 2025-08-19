                                                         #!/bin/bash
"""
Native Host Setup for Website Fingerprinting Research
Replicates Docker environment on Ubuntu 22.04 host system

IMPORTANT: This script requires sudo privileges and will modify your system.
Only run on dedicated research machines or VMs.

Usage: ./setup_host_fingerprinting.sh
"""

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/fingerprinting"
WORK_DIR="$HOME/fingerprinting_research"
TBB_VERSION="14.0.1"

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}Website Fingerprinting Host Setup${NC}"
echo -e "${GREEN}================================${NC}"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}Error: Do not run this script as root${NC}"
   echo "Run as regular user - script will request sudo when needed"
   exit 1
fi

# Check Ubuntu version
if ! grep -q "22.04" /etc/os-release; then
    echo -e "${YELLOW}Warning: This script is designed for Ubuntu 22.04${NC}"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo -e "${YELLOW}This script will:${NC}"
echo "1. Install system dependencies"
echo "2. Install Rust and build Arti"
echo "3. Download and setup Tor Browser"
echo "4. Install Python packages"
echo "5. Configure network capabilities"
echo "6. Set up research directories"
echo

read -p "Continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
fi

# Function to print status
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Update system
print_status "Updating system packages..."
sudo apt-get update

# Install system dependencies
print_status "Installing system dependencies..."
sudo apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    wget \
    curl \
    xvfb \
    firefox \
    unzip \
    build-essential \
    pkg-config \
    libssl-dev \
    git \
    tcpdump \
    libpcap-dev \
    libsqlite3-dev \
    net-tools \
    iproute2 \
    tor \
    torsocks

# Create installation directory
print_status "Creating installation directories..."
sudo mkdir -p "$INSTALL_DIR"
sudo chown $USER:$USER "$INSTALL_DIR"
mkdir -p "$WORK_DIR"

# Install Rust for Arti
print_status "Installing Rust..."
if ! command -v rustc &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    print_status "Rust already installed"
fi

# Download and install geckodriver
print_status "Installing geckodriver..."
cd /tmp
if [ ! -f "/usr/local/bin/geckodriver" ]; then
    wget https://github.com/mozilla/geckodriver/releases/download/v0.31.0/geckodriver-v0.31.0-linux64.tar.gz
    tar -xzf geckodriver-v0.31.0-linux64.tar.gz
    sudo mv geckodriver /usr/local/bin/
    sudo chmod +x /usr/local/bin/geckodriver
    rm geckodriver-v0.31.0-linux64.tar.gz
else
    print_status "geckodriver already installed"
fi

# Clone and build Arti
print_status "Cloning and building Arti..."
cd "$INSTALL_DIR"
if [ ! -d "arti" ]; then
    git clone https://gitlab.torproject.org/tpo/core/arti.git
fi
cd arti
source "$HOME/.cargo/env"
cargo build --release

# Download Tor Browser
print_status "Downloading Tor Browser..."
cd "$INSTALL_DIR"
if [ ! -d "tor-browser" ]; then
    wget -O tor-browser.tar.xz "https://www.torproject.org/dist/torbrowser/${TBB_VERSION}/tor-browser-linux-x86_64-${TBB_VERSION}.tar.xz"
    tar -xf tor-browser.tar.xz
    rm tor-browser.tar.xz
    # Rename the extracted directory to a consistent name
    mv tor-browser* tor-browser
else
    print_status "Tor Browser already downloaded"
fi

# Create Python virtual environment
print_status "Setting up Python environment..."
cd "$WORK_DIR"
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate

# Install Python packages
print_status "Installing Python packages..."
pip install --upgrade pip
pip install \
    tbselenium \
    stem \
    selenium \
    scapy \
    numpy \
    matplotlib \
    pandas \
    scikit-learn

# Configure Tor
print_status "Configuring Tor..."
sudo tee /etc/tor/torrc.research << EOF
# Tor configuration for research
ControlPort 9051
CookieAuthentication 0
SocksPort 9050

# Enable more verbose logging for research
Log notice file /var/log/tor/notices.log
Log debug file /var/log/tor/debug.log

# Disable some client optimizations for research consistency
ClientUseIPv6 0
ClientPreferIPv6ORPort 0

# Circuit settings for research
NewCircuitPeriod 30
MaxCircuitDirtiness 600
EOF

# Set network capabilities for Python (packet capture without sudo)
print_status "Setting network capabilities..."
PYTHON_PATH=$(which python3)
sudo setcap cap_net_raw,cap_net_admin=eip "$PYTHON_PATH"

# Create research scripts directory
print_status "Setting up research environment..."
mkdir -p "$WORK_DIR/scripts"
mkdir -p "$WORK_DIR/data"
mkdir -p "$WORK_DIR/logs"

# Create environment setup script
cat > "$WORK_DIR/setup_env.sh" << 'EOF'
#!/bin/bash
# Source this script to set up the research environment

export FINGERPRINT_HOME="$(dirname $(readlink -f ${BASH_SOURCE[0]}))"
export TBB_PATH="/opt/fingerprinting/tor-browser"
export ARTI_PATH="/opt/fingerprinting/arti/target/release/arti"
export DISPLAY=:99

# Activate Python virtual environment
source "$FINGERPRINT_HOME/venv/bin/activate"

echo "Environment setup complete!"
echo "TBB_PATH: $TBB_PATH"
echo "ARTI_PATH: $ARTI_PATH"
echo "Working directory: $FINGERPRINT_HOME"

# Function to start Xvfb if needed
start_xvfb() {
    if ! pgrep -x "Xvfb" > /dev/null; then
        echo "Starting Xvfb..."
        Xvfb :99 -screen 0 1024x768x24 &
        export XVFB_PID=$!
        echo "Xvfb started with PID: $XVFB_PID"
    else
        echo "Xvfb already running"
    fi
}

# Function to start Tor with research config
start_tor_research() {
    if ! pgrep -x "tor" > /dev/null; then
        echo "Starting Tor with research configuration..."
        sudo systemctl stop tor  # Stop system tor if running
        sudo -u debian-tor tor -f /etc/tor/torrc.research &
        echo "Tor started for research"
        sleep 3
    else
        echo "Tor already running"
    fi
}

# Function to start Arti
start_arti() {
    if ! pgrep -f "arti" > /dev/null; then
        echo "Starting Arti..."
        "$ARTI_PATH" proxy -l debug -p 9150 &
        export ARTI_PID=$!
        echo "Arti started with PID: $ARTI_PID"
        sleep 5
    else
        echo "Arti already running"
    fi
}

# Export functions
export -f start_xvfb start_tor_research start_arti
EOF

chmod +x "$WORK_DIR/setup_env.sh"

# Create a test script
cat > "$WORK_DIR/test_setup.py" << 'EOF'
#!/usr/bin/env python3
"""
Test script to verify the fingerprinting setup
"""
import sys
import subprocess
import time

def test_imports():
    """Test that all required packages can be imported"""
    print("Testing Python imports...")
    try:
        import tbselenium
        import stem
        import selenium
        import scapy
        import numpy
        print("✓ All Python packages imported successfully")
        return True
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False

def test_executables():
    """Test that required executables are available"""
    print("Testing executables...")
    executables = [
        ('geckodriver', 'geckodriver --version'),
        ('tor', 'tor --version'),
        ('tcpdump', 'tcpdump --version')
    ]
    
    all_good = True
    for name, cmd in executables:
        try:
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"✓ {name} available")
            else:
                print(f"✗ {name} failed to run")
                all_good = False
        except Exception as e:
            print(f"✗ {name} not found: {e}")
            all_good = False
    
    return all_good

def test_capabilities():
    """Test network capabilities"""
    print("Testing network capabilities...")
    try:
        from scapy.all import get_if_list
        interfaces = get_if_list()
        print(f"✓ Network interfaces accessible: {interfaces}")
        return True
    except Exception as e:
        print(f"✗ Network capability error: {e}")
        return False

def main():
    print("=== Fingerprinting Setup Test ===")
    
    tests = [
        test_imports,
        test_executables,
        test_capabilities
    ]
    
    results = []
    for test in tests:
        results.append(test())
        print()
    
    if all(results):
        print("🎉 All tests passed! Setup is ready for fingerprinting research.")
    else:
        print("❌ Some tests failed. Check the errors above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
EOF

chmod +x "$WORK_DIR/test_setup.py"

# Set proper permissions
print_status "Setting permissions..."
sudo chown -R $USER:$USER "$WORK_DIR"
chmod -R 755 "$WORK_DIR"

# Create desktop shortcut for easy access
if [ -d "$HOME/Desktop" ]; then
    cat > "$HOME/Desktop/fingerprinting_research.desktop" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Fingerprinting Research
Comment=Launch fingerprinting research environment
Exec=gnome-terminal --working-directory="$WORK_DIR" --command="bash -c 'source setup_env.sh; bash'"
Icon=application-x-executable
Terminal=true
Categories=Development;
EOF
    chmod +x "$HOME/Desktop/fingerprinting_research.desktop"
fi

print_status "Installation complete!"
echo
echo -e "${GREEN}========================${NC}"
echo -e "${GREEN}Setup Summary${NC}"
echo -e "${GREEN}========================${NC}"
echo "Installation directory: $INSTALL_DIR"
echo "Working directory: $WORK_DIR"
echo "Tor Browser: $INSTALL_DIR/tor-browser"
echo "Arti binary: $INSTALL_DIR/arti/target/release/arti"
echo
echo -e "${YELLOW}Next steps:${NC}"
echo "1. cd $WORK_DIR"
echo "2. source setup_env.sh"
echo "3. python3 test_setup.py"
echo "4. start_xvfb && start_tor_research"
echo
echo -e "${YELLOW}For Arti-based collection:${NC}"
echo "start_arti  # Instead of start_tor_research"
echo
echo -e "${RED}Important:${NC}"
echo "- Only use for legitimate research with proper ethical approval"
echo "- This setup modifies system networking capabilities"
echo "- Consider using on dedicated research VMs"

# Final test
print_status "Running quick verification..."
cd "$WORK_DIR"
source venv/bin/activate
python3 test_setup.py