#!/bin/bash

# Website Fingerprinting Simulation Runner
# Executes Shadow simulations and collects cell trace data for WF analysis
# Based on methodology from "Data-Explainable Website Fingerprinting with Network Simulation"

set -e  # Exit on any error

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_CONFIG="tornet-0.05-base"
SIMULATION_TIMEOUT="7200"  # 2 hours timeout for 5% scale
DATA_DIR="wf_simulation_data"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

usage() {
    echo "Usage: $0 [OPTIONS] [CONFIG_DIR]"
    echo ""
    echo "Options:"
    echo "  --config-dir DIR     Shadow configuration directory (default: $DEFAULT_CONFIG)"
    echo "  --data-dir DIR       Output data directory (default: $DATA_DIR)"
    echo "  --timeout SECONDS    Simulation timeout (default: $SIMULATION_TIMEOUT)"
    echo "  --generate-only      Only generate configurations, don't run simulation"
    echo "  --run-all-configs    Run simulations for all generated configurations"
    echo "  --collect-only       Only collect/parse existing simulation data"
    echo "  --help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Run default configuration"
    echo "  $0 --config-dir tornet-0.05-seed1-load0.4  # Run specific configuration"
    echo "  $0 --run-all-configs                 # Run all generated configurations"
    echo "  $0 --collect-only                    # Parse existing simulation results"
}

check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if required binaries exist
    local required_bins=("shadow" "tornettools" "python3")
    for bin in "${required_bins[@]}"; do
        if ! command -v "$bin" &> /dev/null; then
            print_error "$bin is not installed or not in PATH"
            exit 1
        fi
    done
    
    # Check if website lists exist (create minimal ones if missing)
    local required_files=("W_alpha_pages.txt" "W_beta_pages.txt" "W_empty_pages.txt")
    for file in "${required_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            print_warning "$file not found. Creating minimal placeholder."
            case "$file" in
                "W_alpha_pages.txt")
                    printf "sensitive_page_%d.html\n" {1..98} > "$file"
                    ;;
                "W_beta_pages.txt")
                    printf "benign_page_%d.html\n" {1..1000} > "$file"
                    ;;
                "W_empty_pages.txt")
                    printf "unlabeled_page_%d.html\n" {1..1000} > "$file"
                    ;;
            esac
        fi
    done
    
    print_success "Prerequisites check passed"
}

fix_shadow_config() {
    local config_file="$1"
    
    print_status "Fixing Shadow configuration compatibility..."
    
    # Create a backup
    cp "$config_file" "${config_file}.backup"
    
    # Remove unsupported fields and fix compatibility issues
    python3 - <<EOF
import yaml
import sys

config_file = "$config_file"

try:
    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)
    
    # Fix hosts configuration
    if 'hosts' in config:
        for host_name, host_config in config['hosts'].items():
            if 'processes' in host_config:
                for process in host_config['processes']:
                    # Remove unsupported expected_final_state
                    if 'expected_final_state' in process:
                        del process['expected_final_state']
                    
                    # Ensure required fields are present
                    if 'path' not in process:
                        process['path'] = '/bin/echo'
                    if 'start_time' not in process:
                        process['start_time'] = '0s'
    
    # Save fixed configuration
    with open(config_file, 'w') as f:
        yaml.dump(config, f, default_flow_style=False)
    
    print(f"âœ“ Fixed Shadow configuration: {config_file}")
    
except Exception as e:
    print(f"Error fixing config: {e}")
    sys.exit(1)
EOF
}

setup_simulation_environment() {
    local config_dir="$1"
    
    print_status "Setting up simulation environment for $config_dir..."
    
    # Create data directory
    mkdir -p "$DATA_DIR"
    
    # Create subdirectory for this configuration
    local sim_data_dir="$DATA_DIR/$(basename "$config_dir")"
    mkdir -p "$sim_data_dir"
    
    # Copy website lists to simulation directory
    cp W_*_pages.txt "$sim_data_dir/" 2>/dev/null || true
    
    print_success "Environment setup complete"
    echo "$sim_data_dir"
}

run_shadow_simulation() {
    local config_dir="$1" 
    local sim_data_dir="$2"
    
    print_status "Starting Shadow simulation..."
    print_status "Configuration: $config_dir"
    print_status "Data directory: $sim_data_dir"
    print_status "Timeout: ${SIMULATION_TIMEOUT}s"
    
    # Check if configuration exists
    local shadow_config="$config_dir/shadow.config.wf.yaml"
    if [[ ! -f "$shadow_config" ]]; then
        shadow_config="$config_dir/shadow.config.yaml"
        if [[ ! -f "$shadow_config" ]]; then
            print_error "Shadow configuration not found in $config_dir"
            exit 1
        fi
    fi
    
    # Fix Shadow configuration compatibility
    fix_shadow_config "$shadow_config"
    
    # Run simulation with timeout
    local start_time=$(date +%s)
    
    cd "$config_dir"
    
    print_status "Running: shadow $(basename "$shadow_config")"
    
    if timeout "$SIMULATION_TIMEOUT" shadow "$(basename "$shadow_config")" 2>&1 | tee simulation.log; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        print_success "Simulation completed in ${duration}s"
    else
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        print_error "Simulation failed or timed out after ${duration}s"
        
        # Show last few lines of log for debugging
        if [[ -f "simulation.log" ]]; then
            print_status "Last 10 lines of simulation log:"
            tail -10 simulation.log
        fi
        
        cd - > /dev/null
        return 1
    fi
    
    cd - > /dev/null
    
    # Move simulation results to data directory
    if [[ -d "$config_dir/shadow.data" ]]; then
        print_status "Moving simulation results..."
        mv "$config_dir/shadow.data" "$sim_data_dir/"
        # Also move the log file
        [[ -f "$config_dir/simulation.log" ]] && mv "$config_dir/simulation.log" "$sim_data_dir/"
        print_success "Results moved to $sim_data_dir"
    else
        print_warning "No simulation results found in $config_dir/shadow.data"
    fi
}

collect_cell_traces() {
    local sim_data_dir="$1"
    
    print_status "Collecting and parsing cell trace data..."
    
    local shadow_data_dir="$sim_data_dir/shadow.data"
    if [[ ! -d "$shadow_data_dir" ]]; then
        print_error "Shadow simulation data not found in $sim_data_dir"
        return 1
    fi
    
    # Find and count different types of log files
    local oniontrace_logs=$(find "$shadow_data_dir" -name "*oniontrace*.log" 2>/dev/null | wc -l)
    local tgen_logs=$(find "$shadow_data_dir" -name "*tgen*.log" 2>/dev/null | wc -l)
    local tor_logs=$(find "$shadow_data_dir" -name "*tor*.log" 2>/dev/null | wc -l)
    
    print_status "Found $oniontrace_logs OnionTrace logs, $tgen_logs TGen logs, $tor_logs Tor logs"
    
    # Extract basic statistics
    python3 - <<EOF
import os
import json
from pathlib import Path

sim_data_dir = Path("$sim_data_dir")
shadow_data_dir = sim_data_dir / "shadow.data"

stats = {
    'oniontrace_logs': $oniontrace_logs,
    'tgen_logs': $tgen_logs, 
    'tor_logs': $tor_logs,
    'total_files': 0,
    'total_size_mb': 0
}

if shadow_data_dir.exists():
    all_files = list(shadow_data_dir.rglob("*"))
    stats['total_files'] = len([f for f in all_files if f.is_file()])
    stats['total_size_mb'] = sum(f.stat().st_size for f in all_files if f.is_file()) / (1024*1024)

# Save statistics
with open(sim_data_dir / "collection_stats.json", 'w') as f:
    json.dump(stats, f, indent=2)

print(f"Statistics saved to {sim_data_dir / 'collection_stats.json'}")
print(f"Total files: {stats['total_files']}")
print(f"Total size: {stats['total_size_mb']:.1f} MB")
EOF
    
    print_success "Cell trace collection complete"
}

generate_simulation_summary() {
    local sim_data_dir="$1"
    
    print_status "Generating simulation summary..."
    
    # Create summary file
    local summary_file="$sim_data_dir/simulation_summary.txt"
    
    cat > "$summary_file" << EOF
Website Fingerprinting Simulation Summary
========================================
Configuration: $(basename "$sim_data_dir")
Date: $(date)

Data Collection Summary:
$(if [[ -f "$sim_data_dir/collection_stats.json" ]]; then
    python3 -c "
import json
with open('$sim_data_dir/collection_stats.json', 'r') as f:
    stats = json.load(f)
print(f'- OnionTrace logs: {stats[\"oniontrace_logs\"]}')
print(f'- TGen logs: {stats[\"tgen_logs\"]}')
print(f'- Tor logs: {stats[\"tor_logs\"]}')
print(f'- Total files: {stats[\"total_files\"]}')
print(f'- Total size: {stats[\"total_size_mb\"]:.1f} MB')
"
else
    echo "- Statistics not available"
fi)

Files Generated:
$(find "$sim_data_dir" -type f -name "*.log" | wc -l) log files
$(find "$sim_data_dir" -type f -name "*.json" | wc -l) JSON files

Next Steps:
1. Run machine learning analysis: python3 wf_classifiers.py $sim_data_dir
2. Analyze results in $sim_data_dir/
3. Compare with other configurations for robustness analysis

EOF

    print_success "Summary saved to $summary_file"
}

run_single_configuration() {
    local config_dir="$1"
    
    print_status "Running simulation for configuration: $config_dir"
    
    # Setup environment
    local sim_data_dir
    sim_data_dir=$(setup_simulation_environment "$config_dir")
    
    # Run simulation
    if run_shadow_simulation "$config_dir" "$sim_data_dir"; then
        # Collect and parse results
        collect_cell_traces "$sim_data_dir"
        generate_simulation_summary "$sim_data_dir"
        
        print_success "Configuration $config_dir completed successfully"
        print_status "Results available in: $sim_data_dir"
    else
        print_error "Configuration $config_dir failed"
        return 1
    fi
}

# Main script logic
main() {
    local config_dir="$DEFAULT_CONFIG"
    local generate_only=false
    local run_all=false
    local collect_only=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --config-dir)
                config_dir="$2"
                shift 2
                ;;
            --data-dir)
                DATA_DIR="$2"
                shift 2
                ;;
            --timeout)
                SIMULATION_TIMEOUT="$2"
                shift 2
                ;;
            --generate-only)
                generate_only=true
                shift
                ;;
            --run-all-configs)
                run_all=true
                shift
                ;;
            --collect-only)
                collect_only=true
                shift
                ;;
            --help)
                usage
                exit 0
                ;;
            -*)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                config_dir="$1"
                shift
                ;;
        esac
    done
    
    print_status "Website Fingerprinting Simulation Runner"
    print_status "Configuration: $config_dir"
    print_status "Data directory: $DATA_DIR"
    
    # Check prerequisites
    check_prerequisites
    
    # Execute based on options
    if [[ "$generate_only" == true ]]; then
        print_status "Generate-only mode: Running network configuration generation"
        python3 setup_wf_network.py --generate-variations
        print_success "Configuration generation complete"
        
    elif [[ "$collect_only" == true ]]; then
        print_status "Collect-only mode: Processing existing simulation data"
        if [[ -d "$DATA_DIR" ]]; then
            for sim_dir in "$DATA_DIR"/*; do
                if [[ -d "$sim_dir/shadow.data" ]]; then
                    collect_cell_traces "$sim_dir"
                    generate_simulation_summary "$sim_dir"
                fi
            done
        else
            print_error "No existing data directory found: $DATA_DIR"
        fi
        
    elif [[ "$run_all" == true ]]; then
        print_status "Running simulations for all configurations..."
        
        # Find all tornet configuration directories
        local configs=()
        for dir in tornet-0.05*; do
            if [[ -d "$dir" ]]; then
                configs+=("$dir")
            fi
        done
        
        if [[ ${#configs[@]} -eq 0 ]]; then
            print_error "No configuration directories found. Run setup_wf_network.py first."
            exit 1
        fi
        
        print_status "Found ${#configs[@]} configurations to run"
        
        local success_count=0
        for config_dir in "${configs[@]}"; do
            if run_single_configuration "$config_dir"; then
                ((success_count++))
            else
                print_warning "Configuration $config_dir failed, continuing with others..."
            fi
        done
        
        print_success "Completed $success_count/${#configs[@]} configurations successfully"
        
    else
        # Run single configuration
        if [[ ! -d "$config_dir" ]]; then
            print_error "Configuration directory not found: $config_dir"
            print_status "Available configurations:"
            for dir in tornet-0.05*; do
                if [[ -d "$dir" ]]; then
                    echo "  $dir"
                fi
            done
            exit 1
        fi
        
        run_single_configuration "$config_dir"
    fi
    
    print_success "All operations completed successfully!"
}

# Execute main function with all arguments
main "$@"
