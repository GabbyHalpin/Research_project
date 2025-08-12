#!/bin/bash
# Helper script to run simulations

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

if [ $# -eq 0 ]; then
    echo "Usage: $0 <network_name> [simulation_time]"
    echo "Available networks:"
    echo "  tornet-0.05 (base network)"
    for seed in 1 2 3; do
        for load in 1.5 2.0 2.5; do
            echo "  tornet-0.05-seed${seed}-load${load}"
        done
    done
    exit 1
fi

NETWORK=$1
SIM_TIME=${2:-"3600s"}  # Default 1 hour simulation

if [ ! -d "$NETWORK" ]; then
    echo "Error: Network directory $NETWORK not found"
    exit 1
fi

print_status "Running simulation for $NETWORK (duration: $SIM_TIME)"
print_status "This may take several hours and require significant RAM"

# Modify simulation time in shadow config
sed -i "s/stop_time: .*/stop_time: $SIM_TIME/" $NETWORK/shadow.config.yaml

# Run simulation
tornettools simulate $NETWORK

print_success "Simulation completed for $NETWORK"
print_status "Results saved in $NETWORK/shadow.data/"
print_status "To process results, run: tornettools parse $NETWORK"