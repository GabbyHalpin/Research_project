#!/bin/bash

# Enhanced startup script for website fingerprinting with Arti

# Start Xvfb for headless display
echo "Starting Xvfb..."
Xvfb :99 -screen 0 1024x768x24 &
export DISPLAY=:99

# Start Arti
echo "Starting Arti..."
cd /opt/arti
./target/release/arti proxy -l debug -p 9150 &
ARTI_PID=$!

# Wait for Arti to start up
echo "Waiting for Arti to start..."
sleep 10

# Check if Arti is running on port 9150
while ! nc -z localhost 9150; do
    echo "Waiting for Arti to be ready on port 9150..."
    sleep 2
done

echo "Arti is ready!"

# Verify network interface for packet capture
echo "Available network interfaces:"
ip link show

# Run the fingerprinting collector
if [ -f "/app/arti_wf_collector.py" ]; then
    echo "Starting website fingerprinting data collection..."
    echo "WARNING: This is for research purposes only"
    echo "Ensure you have proper ethical approval"
    
    # Run with elevated privileges for packet capture
    python3 /app/arti_wf_collector.py
else
    echo "Fingerprinting script not found. Starting interactive shell..."
    echo "Arti is running on port 9150"
    echo "Tor Browser path: $TBB_PATH"
    /bin/bash
fi