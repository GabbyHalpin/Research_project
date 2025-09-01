#!/usr/bin/env python3
"""
Verification script to check if Shadow WF processing is working correctly
Run this on one simulation before processing all of them.
"""

import pickle
import numpy as np
from pathlib import Path
from collections import Counter
import matplotlib.pyplot as plt

def verify_simulation_output(results_dir: str, sim_name: str):
    """Verify the output of a processed simulation"""
    
    results_path = Path(results_dir)
    
    # Check if files exist
    x_file = results_path / f"X_{sim_name}.pkl"
    y_file = results_path / f"y_{sim_name}.pkl"
    labels_file = results_path / f"labels_{sim_name}.pkl"
    
    missing_files = []
    for file in [x_file, y_file, labels_file]:
        if not file.exists():
            missing_files.append(file.name)
    
    if missing_files:
        print(f"❌ Missing files: {missing_files}")
        return False
    
    print("✅ All required files present")
    
    # Load data
    try:
        with open(x_file, 'rb') as f:
            X = pickle.load(f)
        with open(y_file, 'rb') as f:
            y = pickle.load(f)
        with open(labels_file, 'rb') as f:
            labels = pickle.load(f)
    except Exception as e:
        print(f"❌ Error loading files: {e}")
        return False
    
    print("✅ Files loaded successfully")
    
    # Check data shapes
    print(f"\n📊 Data Shapes:")
    print(f"  X shape: {X.shape}")
    print(f"  y shape: {y.shape}")
    
    expected_sequences = 3 * 27 * 30  # 3 monitors × 27 URLs × 30 iterations = 2430
    print(f"  Expected sequences: ~{expected_sequences}")
    print(f"  Actual sequences: {len(X)}")
    
    if len(X) < expected_sequences * 0.5:
        print("⚠️  WARNING: Much fewer sequences than expected!")
        print("   This might indicate correlation issues between lo.pcap and eth0.pcap")
    
    # Check sequence format
    if X.shape[1] != 5000:
        print(f"❌ Wrong sequence length: {X.shape[1]} (expected 5000)")
        return False
    
    print("✅ Correct sequence length (5000)")
    
    # Check packet directions
    unique_values = np.unique(X)
    print(f"\n📦 Packet Direction Values: {unique_values}")
    
    if not all(val in [-1, 0, 1] for val in unique_values):
        print("❌ Invalid packet direction values (should be -1, 0, 1)")
        return False
    
    print("✅ Valid packet direction values")
    
    # Count non-zero sequences (actual traffic vs padding)
    non_zero_counts = np.count_nonzero(X, axis=1)
    avg_traffic_length = np.mean(non_zero_counts)
    
    print(f"\n📈 Traffic Statistics:")
    print(f"  Average traffic length: {avg_traffic_length:.1f} packets")
    print(f"  Min traffic length: {np.min(non_zero_counts)}")
    print(f"  Max traffic length: {np.max(non_zero_counts)}")
    
    if avg_traffic_length < 50:
        print("⚠️  WARNING: Very short traffic sequences!")
        print("   This suggests poor correlation between HTTP and encrypted traffic")
    
    # Check URL labeling
    url_to_label = labels['url_to_label']
    label_to_url = labels['label_to_url']
    
    print(f"\n🏷️  URL Labels:")
    print(f"  Number of unique URLs: {len(url_to_label)}")
    print(f"  Expected URLs: 27 per monitor × 3 monitors = 81")
    
    if len(url_to_label) < 20:
        print("⚠️  WARNING: Very few unique URLs found!")
        print("   Check if HTTP parsing is working correctly")
    
    # Show sample URLs
    sample_urls = list(url_to_label.keys())[:10]
    print(f"  Sample URLs: {sample_urls}")
    
    # Check label distribution
    label_counts = Counter(y)
    print(f"\n📊 Label Distribution:")
    print(f"  Labels per URL: {dict(list(label_counts.items())[:5])}...")
    
    # Check for balanced dataset
    min_count = min(label_counts.values())
    max_count = max(label_counts.values())
    
    if max_count / min_count > 3:
        print("⚠️  WARNING: Highly imbalanced dataset!")
        print(f"   Min sequences per URL: {min_count}")
        print(f"   Max sequences per URL: {max_count}")
    else:
        print(f"✅ Reasonably balanced dataset ({min_count}-{max_count} sequences per URL)")
    
    # Generate summary
    success_rate = len(X) / expected_sequences * 100
    
    print(f"\n📋 Summary:")
    print(f"  Success rate: {success_rate:.1f}% of expected sequences")
    print(f"  Data quality: {'Good' if avg_traffic_length > 100 else 'Poor' if avg_traffic_length < 50 else 'Fair'}")
    print(f"  URL diversity: {'Good' if len(url_to_label) > 50 else 'Poor' if len(url_to_label) < 20 else 'Fair'}")
    
    if success_rate > 70 and avg_traffic_length > 50 and len(url_to_label) > 30:
        print("✅ Overall assessment: GOOD - Ready for training")
        return True
    elif success_rate > 40:
        print("⚠️  Overall assessment: FAIR - May need parameter tuning")
        return True
    else:
        print("❌ Overall assessment: POOR - Needs investigation")
        return False

def check_pcap_structure(sim_path: str):
    """Check the structure of a simulation directory"""
    
    sim_dir = Path(sim_path)
    print(f"🔍 Checking simulation structure: {sim_dir.name}")
    
    monitor_dirs = list(sim_dir.glob("shadow.data/hosts/monitor*"))
    print(f"  Found {len(monitor_dirs)} monitor directories")
    
    for monitor_dir in monitor_dirs:
        lo_pcaps = list(monitor_dir.glob("*lo.pcap"))
        eth0_pcaps = list(monitor_dir.glob("*eth0.pcap"))
        
        print(f"  {monitor_dir.name}: lo.pcap={len(lo_pcaps)}, eth0.pcap={len(eth0_pcaps)}")
        
        if lo_pcaps and eth0_pcaps:
            lo_size = lo_pcaps[0].stat().st_size / 1024 / 1024  # MB
            eth0_size = eth0_pcaps[0].stat().st_size / 1024 / 1024  # MB
            print(f"    File sizes: lo.pcap={lo_size:.1f}MB, eth0.pcap={eth0_size:.1f}MB")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 3:
        print("Usage: python3 verify_dataset.py <results_dir> <sim_name>")
        print("Example: python3 verify_dataset.py ./individual_results tornet-0.005-1")
        sys.exit(1)
    
    results_dir = sys.argv[1]
    sim_name = sys.argv[2]
    
    print("🔬 Shadow WF Dataset Verification")
    print("="*50)
    
    success = verify_simulation_output(results_dir, sim_name)
    
    if success:
        print("\n✅ Verification passed! You can proceed with all simulations.")
    else:
        print("\n❌ Verification failed! Check the issues above before processing more simulations.")