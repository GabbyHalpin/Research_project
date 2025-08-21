#!/usr/bin/env python3
"""
Traffic Data Parser for Deep Fingerprinting Format
Converts network traffic captures to the format required by the DF model.
"""

import os
import pickle
import numpy as np
from scapy.all import rdpcap, IP, TCP
import re
from collections import defaultdict
import argparse
from typing import List, Tuple, Dict

class TrafficParser:
    def __init__(self, data_dir: str, output_dir: str):
        self.data_dir = data_dir
        self.output_dir = output_dir
        self.sequence_length = 5000  # Fixed length as per DF paper
        
    def parse_pcap_file(self, pcap_path: str) -> List[int]:
        """
        Parse a pcap file and extract packet directions.
        Returns a list of +1 (outgoing) and -1 (incoming) packets.
        """
        try:
            packets = rdpcap(pcap_path)
            directions = []
            
            if len(packets) == 0:
                return []
            
            # Method 1: Auto-detect client IP (typically the one initiating connections)
            ip_stats = {}
            for packet in packets:
                if IP in packet and TCP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    
                    # Count outgoing connections (SYN packets)
                    if packet[TCP].flags & 0x02:  # SYN flag
                        ip_stats[src_ip] = ip_stats.get(src_ip, 0) + 1
            
            # Client is likely the IP that initiates most connections
            if ip_stats:
                client_ip = max(ip_stats, key=ip_stats.get)
            elif IP in packets[0]:
                # Fallback: use first packet source as client
                client_ip = packets[0][IP].src
            else:
                return []
            
            print(f"Detected client IP: {client_ip}")
            
            # Extract directions based on client IP
            for packet in packets:
                if IP in packet and TCP in packet:
                    # Skip non-data packets (pure ACKs, etc.) if desired
                    # Uncomment next line to only count packets with payload
                    # if len(packet[TCP].payload) == 0: continue
                    
                    # +1 for outgoing (from client), -1 for incoming (to client)
                    if packet[IP].src == client_ip:
                        directions.append(1)
                    else:
                        directions.append(-1)
            
            print(f"Extracted {len(directions)} packets ({directions.count(1)} out, {directions.count(-1)} in)")
            return directions
            
        except Exception as e:
            print(f"Error parsing {pcap_path}: {e}")
            return []
    
    def parse_text_log(self, log_path: str) -> List[int]:
        """
        Parse text-based traffic logs if your data is in log format.
        Adapt this based on your actual log format.
        """
        directions = []
        try:
            with open(log_path, 'r') as f:
                for line in f:
                    # Example parsing - adapt to your log format
                    # Looking for direction indicators in logs
                    if 'outgoing' in line.lower() or '->' in line:
                        directions.append(1)
                    elif 'incoming' in line.lower() or '<-' in line:
                        directions.append(-1)
                    # Add more parsing logic based on your log format
            return directions
        except Exception as e:
            print(f"Error parsing {log_path}: {e}")
            return []
    
    def extract_website_label(self, filename: str) -> int:
        """
        Extract website label from filename.
        Adapt this regex pattern to match your naming convention.
        """
        # Example patterns - adapt to your naming convention
        patterns = [
            r'(\d+)',  # Extract first number from filename
            r'site_(\d+)',  # site_1, site_2, etc.
            r'website(\d+)',  # website1, website2, etc.
            r'arti\.(\d+)\.',  # arti.1001.something
        ]
        
        for pattern in patterns:
            match = re.search(pattern, filename)
            if match:
                return int(match.group(1))
        
        # Fallback: hash filename to create consistent label
        return hash(filename) % 1000
    
    def pad_or_truncate_sequence(self, sequence: List[int]) -> np.ndarray:
        """
        Pad with zeros or truncate to fixed length of 5000.
        """
        if len(sequence) >= self.sequence_length:
            return np.array(sequence[:self.sequence_length])
        else:
            # Pad with zeros
            padded = sequence + [0] * (self.sequence_length - len(sequence))
            return np.array(padded)
    
    def process_directory(self) -> Tuple[List[np.ndarray], List[int]]:
        """
        Process all traffic files in the directory.
        """
        X_data = []  # Packet sequences
        y_data = []  # Website labels
        
        # Get all files in directory
        files = os.listdir(self.data_dir)
        traffic_files = []
        
        # Filter traffic files based on extensions
        for f in files:
            if f.endswith(('.pcap', '.pcapng', '.cap', '.log', '.txt')):
                traffic_files.append(f)
        
        print(f"Found {len(traffic_files)} traffic files")
        
        for filename in traffic_files:
            filepath = os.path.join(self.data_dir, filename)
            print(f"Processing {filename}...")
            
            # Parse based on file extension
            if filename.endswith(('.pcap', '.pcapng', '.cap')):
                directions = self.parse_pcap_file(filepath)
            else:
                directions = self.parse_text_log(filepath)
            
            if len(directions) > 0:
                # Process sequence
                sequence = self.pad_or_truncate_sequence(directions)
                label = self.extract_website_label(filename)
                
                X_data.append(sequence)
                y_data.append(label)
                
                print(f"  -> {len(directions)} packets, label: {label}")
            else:
                print(f"  -> No valid packets found")
        
        return X_data, y_data
    
    def split_data(self, X_data: List[np.ndarray], y_data: List[int], 
                   train_ratio: float = 0.8, val_ratio: float = 0.1) -> Dict:
        """
        Split data into train/validation/test sets.
        """
        n_samples = len(X_data)
        indices = np.random.permutation(n_samples)
        
        n_train = int(n_samples * train_ratio)
        n_val = int(n_samples * val_ratio)
        
        train_idx = indices[:n_train]
        val_idx = indices[n_train:n_train + n_val]
        test_idx = indices[n_train + n_val:]
        
        splits = {
            'train': (np.array([X_data[i] for i in train_idx]), 
                     np.array([y_data[i] for i in train_idx])),
            'val': (np.array([X_data[i] for i in val_idx]), 
                   np.array([y_data[i] for i in val_idx])),
            'test': (np.array([X_data[i] for i in test_idx]), 
                    np.array([y_data[i] for i in test_idx]))
        }
        
        return splits
    
    def save_dataset(self, data_splits: Dict, defense_type: str = "NoDef"):
        """
        Save datasets in Deep Fingerprinting format.
        """
        os.makedirs(self.output_dir, exist_ok=True)
        
        for split_name, (X, y) in data_splits.items():
            # Save X data (packet sequences)
            X_filename = f"X_{split_name}_{defense_type}.pkl"
            X_path = os.path.join(self.output_dir, X_filename)
            with open(X_path, 'wb') as f:
                pickle.dump(X, f)
            
            # Save y data (labels)
            y_filename = f"y_{split_name}_{defense_type}.pkl"
            y_path = os.path.join(self.output_dir, y_filename)
            with open(y_path, 'wb') as f:
                pickle.dump(y, f)
            
            print(f"Saved {split_name} set: {X.shape[0]} samples")
            print(f"  X: {X_path}")
            print(f"  y: {y_path}")
    
    def validate_dataset(self, data_splits: Dict):
        """
        Validate the generated dataset format.
        """
        print("\n=== Dataset Validation ===")
        for split_name, (X, y) in data_splits.items():
            print(f"{split_name} set:")
            print(f"  X shape: {X.shape}")
            print(f"  y shape: {y.shape}")
            print(f"  Unique labels: {len(np.unique(y))}")
            print(f"  X data type: {X.dtype}")
            print(f"  y data type: {y.dtype}")
            print(f"  X range: [{X.min()}, {X.max()}]")
            print()

def main():
    parser = argparse.ArgumentParser(description='Parse traffic data for Deep Fingerprinting')
    parser.add_argument('--input_dir', required=True, help='Directory containing traffic files')
    parser.add_argument('--output_dir', required=True, help='Output directory for dataset')
    parser.add_argument('--defense_type', default='NoDef', 
                       choices=['NoDef', 'WTFPAD', 'WalkieTalkie'],
                       help='Type of defense applied to traffic')
    parser.add_argument('--seed', type=int, default=42, help='Random seed for data splitting')
    
    args = parser.parse_args()
    
    # Set random seed for reproducible splits
    np.random.seed(args.seed)
    
    # Initialize parser
    traffic_parser = TrafficParser(args.input_dir, args.output_dir)
    
    print(f"Processing traffic files from: {args.input_dir}")
    print(f"Output directory: {args.output_dir}")
    print(f"Defense type: {args.defense_type}")
    
    # Process all files
    X_data, y_data = traffic_parser.process_directory()
    
    if len(X_data) == 0:
        print("No valid traffic data found!")
        return
    
    print(f"\nTotal samples processed: {len(X_data)}")
    print(f"Unique websites: {len(np.unique(y_data))}")
    
    # Split data
    data_splits = traffic_parser.split_data(X_data, y_data)
    
    # Validate dataset
    traffic_parser.validate_dataset(data_splits)
    
    # Save dataset
    traffic_parser.save_dataset(data_splits, args.defense_type)
    
    print(f"\nDataset successfully created in {args.output_dir}")
    print("Files created:")
    for split in ['train', 'val', 'test']:
        print(f"  X_{split}_{args.defense_type}.pkl")
        print(f"  y_{split}_{args.defense_type}.pkl")

if __name__ == "__main__":
    main()