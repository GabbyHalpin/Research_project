#!/bin/bash
# Process WF data from simulation results

set -e

if [ $# -eq 0 ]; then
    echo "Usage: $0 <network_name>"
    echo "First run: tornettools parse <network_name>"
    echo "Then run this script to extract WF-specific data"
    exit 1
fi

NETWORK=$1

if [ ! -d "$NETWORK/shadow.data" ]; then
    echo "Error: No simulation data found for $NETWORK"
    echo "Run simulation first: ./run_simulation.sh $NETWORK"
    exit 1
fi

echo "Processing WF data for $NETWORK"

# Parse tornettools results
echo "Parsing tornettools results..."
tornettools parse $NETWORK

# Extract WF-specific data
echo "Extracting WF-specific data..."
python3 data_processor.py --shadow-data $NETWORK/shadow.data/ --output-dir ./wf_datasets/$NETWORK/

echo "WF data processing completed for $NETWORK"
echo "Results saved in: ./wf_datasets/$NETWORK/"
EOF

RUN chmod +x run_simulation.sh run_all_simulations.sh process_wf_data.sh

# 22) Create summary of what's ready
RUN cat > WF_RESEARCH_SETUP.md << 'EOF' && \
# Website Fingerprinting Research Environment

## Setup Complete ✅

This container has automatically prepared everything needed for WF research:

### Generated Networks:
- **Base network**: `tornet-0.05` (5% scale)
- **Robustness variants**: 9 additional networks with different seeds and load levels
  - Seeds: 1, 2, 3 (different relay compositions)
  - Load scales: 1.5, 2.0, 2.5 (different congestion levels)

### Modifications Applied:
- ✅ All Shadow configs modified for WF data collection
- ✅ All TGen files modified to fetch your specific URLs
- ✅ Packet capture enabled on all clients
- ✅ Tor control ports configured for cell tracing
- ✅ Web servers added for your URL sets

### URLs Processed:
- Loaded from `urls.txt`
- Split into W_α (sensitive), W_β (benign), W_∅ (unlabeled) sets
- Integrated into all network configurations

## Next Steps:

### 1. Run Simulations (Outside Container)
```bash
# Copy container output to host
docker cp <container_id>:/home/artiuser/ ./wf_research/

# Run single simulation
./run_simulation.sh tornet-0.05

# Or run all simulations for robustness testing
./run_all_simulations.sh
```

### 2. Process Results
```bash
# Process each completed simulation
./process_wf_data.sh tornet-0.05

# Results will be in ./wf_datasets/
```

### 3. Train ML Models
The processed data will be ready for ML training with formats compatible with:
- Deep Fingerprinting (DF)
- Tik-Tok attack
- CUMUL
- k-Fingerprinting

## Research Methodology

This setup implements the methodology from both papers:
1. **Tik-Tok paper**: Timing-based features and directional timing
2. **Simulation paper**: Network variations for robustness testing

You can now conduct comprehensive WF research including:
- Closed-world vs open-world evaluation
- Robustness testing across network conditions
- Timing vs direction-only comparisons
- Transfer learning between network conditions