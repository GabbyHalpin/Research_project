#!/bin/bash
# Run all network simulations for comprehensive WF research

set -e

NETWORKS=("tornet-0.05")
for seed in 1 2 3; do
    for load in 1.5 2.0 2.5; do
        NETWORKS+=("tornet-0.05-seed${seed}-load${load}")
    done
done

echo "This will run ${#NETWORKS[@]} simulations. Each may take several hours."
read -p "Continue? (y/N): " confirm

if [[ "$confirm" =~ ^[Yy]$ ]]; then
    for network in "${NETWORKS[@]}"; do
        echo "Starting simulation: $network"
        ./run_simulation.sh "$network" "1800s"  # 30 min each for testing
    done
    echo "All simulations completed!"
else
    echo "Simulation cancelled"
fi
