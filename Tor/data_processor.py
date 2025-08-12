#!/usr/bin/env python3
"""
Shadow Network Data Processor for Website Fingerprinting
Processes Shadow simulation output to create datasets compatible with 
the Tik-Tok website fingerprinting attack.
"""

import os
import json
import pandas as pd
import numpy as np
from scapy.all import *
from scapy.utils import RawPcapReader
from collections import defaultdict
import argparse
from pathlib import Path

class ShadowWFProcessor:
    """Process Shadow simulation data for website fingerprinting research"""
    
    def __init__(self, shadow_data_dir, output_dir, cell_trace_length=5000):
        self.shadow_data_dir = Path(shadow_data_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)
        self.cell_trace_length = cell_trace_length  # Following paper's N=5000
        self.tor_cell_size = 514  # Tor cell size in bytes
        
    def extract_cell_traces_from_tor_logs(self, shadow_data_dir):
        """
        Extract cell traces from Tor control interface logs as described in the paper
        Returns: Dictionary mapping circuit_id to cell traces
        """
        cell_traces = {}
        
        # Look for Tor log files that contain cell trace data
        tor_log_files = list(self.shadow_data_dir.glob("**/tor.*.log"))
        
        for log_file in tor_log_files:
            try:
                with open(log_file, 'r') as f:
                    current_circuit = None
                    current_trace = []
                    
                    for line in f:
                        # Parse Tor control events for cell metadata
                        if 'CIRC' in line and 'NEW' in line:
                            # New circuit created
                            parts = line.split()
                            for part in parts:
                                if part.startswith('ID='):
                                    current_circuit = part.split('=')[1]
                                    current_trace = []
                                    break
                        
                        elif 'CELL' in line and current_circuit:
                            # Cell forwarded through circuit
                            parts = line.split()
                            timestamp = float(parts[0])
                            
                            # Extract direction (-1 for outgoing, +1 for incoming)
                            direction = -1 if 'OUT' in line else 1
                            
                            current_trace.append((timestamp, direction))
                            
                            # Limit trace length as per paper
                            if len(current_trace) >= self.cell_trace_length:
                                cell_traces[current_circuit] = current_trace
                                current_circuit = None
                        
                        elif 'CIRC' in line and 'CLOSED' in line and current_circuit:
                            # Circuit closed, save trace
                            if current_trace:
                                cell_traces[current_circuit] = current_trace
                            current_circuit = None
                            
            except Exception as e:
                print(f"Error processing Tor log {log_file}: {e}")
        
        return cell_traces

    def extract_pcap_features(self, pcap_file, client_ip):
        """
        Extract cell-level timing and directional features from PCAP file
        Convert packet-level data to Tor cell-level data
        Returns: List of (timestamp, direction) tuples representing Tor cells
        """
        cells = []
        
        try:
            for (pkt_data, pkt_metadata) in RawPcapReader(str(pcap_file)):
                timestamp = pkt_metadata.sec + pkt_metadata.usec / 1000000.0
                
                # Parse packet to determine direction
                pkt = Ether(pkt_data)
                
                if IP in pkt and TCP in pkt:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    
                    # Determine direction from client perspective
                    if src_ip == client_ip:
                        direction = -1  # Outgoing (client to entry relay)
                    elif dst_ip == client_ip:
                        direction = 1   # Incoming (entry relay to client)
                    else:
                        continue  # Skip packets not involving our client
                    
                    # Convert packet to Tor cells (514 bytes each)
                    payload_size = len(pkt[TCP].payload) if pkt[TCP].payload else 0
                    if payload_size > 0:
                        num_cells = max(1, payload_size // self.tor_cell_size)
                        for _ in range(num_cells):
                            cells.append((timestamp, direction))
                    
        except Exception as e:
            print(f"Error processing {pcap_file}: {e}")
            
        return sorted(cells, key=lambda x: x[0])  # Sort by timestamp
    
    def extract_bursts(self, cells):
        """
        Extract burst information from cell sequence (paper methodology)
        A burst is a sequence of consecutive cells in the same direction
        Returns: List of burst dictionaries
        """
        if not cells:
            return []
            
        bursts = []
        current_burst = {
            'direction': cells[0][1],
            'cells': [cells[0]],
            'start_time': cells[0][0],
            'count': 1
        }
        
        for i in range(1, len(cells)):
            timestamp, direction = cells[i]
            
            # If direction changes, start new burst
            if direction != current_burst['direction']:
                # Finish current burst
                current_burst['end_time'] = current_burst['cells'][-1][0]
                current_burst['duration'] = current_burst['end_time'] - current_burst['start_time']
                bursts.append(current_burst)
                
                # Start new burst
                current_burst = {
                    'direction': direction,
                    'cells': [cells[i]],
                    'start_time': timestamp,
                    'count': 1
                }
            else:
                # Continue current burst
                current_burst['cells'].append(cells[i])
                current_burst['count'] += 1
        
        # Don't forget the last burst
        if current_burst['cells']:
            current_burst['end_time'] = current_burst['cells'][-1][0]
            current_burst['duration'] = current_burst['end_time'] - current_burst['start_time']
            bursts.append(current_burst)
            
        return bursts
    
    def compute_timing_features(self, bursts):
        """
        Compute burst-level timing features as described in both papers
        Combines Tik-Tok features with additional network performance metrics
        """
        if len(bursts) < 2:
            return {}
            
        features = {
            # Tik-Tok timing features
            'median_packet_times': [],
            'variances': [],
            'burst_lengths': [],
            'inter_median_delays': [],
            'ibd_ff': [],  # Inter-burst delay first-to-first
            'ibd_lf': [],  # Inter-burst delay last-to-first
            'ibd_iff': [], # Inter-burst delay incoming first-to-first
            'ibd_off': [], # Inter-burst delay outgoing first-to-first
            
            # Additional features from simulation paper
            'total_cell_count': sum(len(burst['cells']) for burst in bursts),
            'cells_sent': sum(len(burst['cells']) for burst in bursts if burst['direction'] == -1),
            'cells_received': sum(len(burst['cells']) for burst in bursts if burst['direction'] == 1),
            'burst_count': len(bursts),
            'mean_burst_length': np.mean([len(burst['cells']) for burst in bursts]),
            'ttlb': bursts[-1]['end_time'] - bursts[0]['start_time'] if bursts else 0
        }
        
        # Extract features for each burst
        for i, burst in enumerate(bursts):
            # Median cell time
            timestamps = [cell[0] for cell in burst['cells']]
            if timestamps:
                median_time = np.median(timestamps)
                features['median_packet_times'].append(median_time)
                
                # Variance of cell times within burst
                if len(timestamps) > 1:
                    variance = np.var(timestamps)
                    features['variances'].append(variance)
                
                # Burst length (duration)
                features['burst_lengths'].append(burst['duration'])
        
        # Compute inter-burst features
        for i in range(len(bursts) - 1):
            curr_burst = bursts[i]
            next_burst = bursts[i + 1]
            
            # Inter-median delay
            if i < len(features['median_packet_times']) - 1:
                imd = features['median_packet_times'][i + 1] - features['median_packet_times'][i]
                features['inter_median_delays'].append(imd)
            
            # IBD-FF: First cell to first cell
            first_curr = curr_burst['cells'][0][0]
            first_next = next_burst['cells'][0][0]
            features['ibd_ff'].append(first_next - first_curr)
            
            # IBD-LF: Last cell to first cell
            last_curr = curr_burst['cells'][-1][0]
            features['ibd_lf'].append(first_next - last_curr)
            
            # Direction-specific inter-burst delays
            if curr_burst['direction'] == 1 and next_burst['direction'] == 1:  # Both incoming
                features['ibd_iff'].append(first_next - first_curr)
            elif curr_burst['direction'] == -1 and next_burst['direction'] == -1:  # Both outgoing  
                features['ibd_off'].append(first_next - first_curr)
                
        return features
    
    def process_shadow_logs(self):
        """
        Process Shadow log files to extract website visit information
        """
        tgen_logs = list(self.shadow_data_dir.glob("**/tgen.*.log"))
        
        visits = defaultdict(list)
        
        for log_file in tgen_logs:
            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        if 'web-complete' in line:
                            # Parse TGen log to extract completed web transfers
                            parts = line.strip().split()
                            timestamp = parts[0]
                            
                            # Extract URL and other metadata
                            # This depends on your TGen configuration
                            # You may need to adjust parsing based on log format
                            
                            # Example parsing (adjust as needed):
                            for part in parts:
                                if part.startswith('http'):
                                    url = part
                                    visits[url].append({
                                        'timestamp': timestamp,
                                        'log_file': log_file
                                    })
                                    break
                                    
            except Exception as e:
                print(f"Error processing log {log_file}: {e}")
                
        return visits
    
    def create_wf_dataset(self, shadow_data_dir, circuit_mappings=None):
        """
        Create website fingerprinting dataset from Shadow simulation
        Following the methodology from both papers
        
        Args:
            shadow_data_dir: Directory containing Shadow simulation output
            circuit_mappings: Dict mapping circuit IDs to webpage labels
        """
        
        dataset = []
        
        # First try to extract cell traces from Tor control logs (preferred method)
        cell_traces = self.extract_cell_traces_from_tor_logs(shadow_data_dir)
        
        if cell_traces:
            print(f"Found {len(cell_traces)} cell traces from Tor logs")
            
            for circuit_id, cells in cell_traces.items():
                if not cells:
                    continue
                
                # Pad or truncate to fixed length
                if len(cells) > self.cell_trace_length:
                    cells = cells[:self.cell_trace_length]
                else:
                    # Pad with zeros (empty cells)
                    cells.extend([(0, 0)] * (self.cell_trace_length - len(cells)))
                
                # Extract bursts
                bursts = self.extract_bursts(cells)
                
                # Compute timing features
                timing_features = self.compute_timing_features(bursts)
                
                # Create direction-only representation (for comparison with DF)
                direction_sequence = [cell[1] for cell in cells]
                
                # Create raw timing representation
                timing_sequence = [cell[0] for cell in cells]
                
                # Create directional timing (Tik-Tok representation)
                directional_timing = [cell[0] * cell[1] for cell in cells]
                
                # CUMUL representation (cumulative sum of directions)
                cumul_sequence = []
                cumulative_sum = 0
                for direction in direction_sequence:
                    cumulative_sum += direction
                    cumul_sequence.append(cumulative_sum)
                
                # Store trace data
                trace_data = {
                    'circuit_id': circuit_id,
                    'webpage_label': circuit_mappings.get(circuit_id, 'unknown') if circuit_mappings else 'unknown',
                    'cell_count': len([c for c in cells if c != (0, 0)]),
                    'burst_count': len(bursts),
                    'total_duration': cells[-1][0] - cells[0][0] if cells and cells[0][0] > 0 else 0,
                    
                    # Different representations for ML models
                    'direction_sequence': direction_sequence,      # For Deep Fingerprinting
                    'timing_sequence': timing_sequence,           # For raw timing analysis
                    'directional_timing': directional_timing,    # For Tik-Tok
                    'cumul_sequence': cumul_sequence,            # For CUMUL
                    'timing_features': timing_features,          # For k-Fingerprinting
                    'bursts': bursts
                }
                
                dataset.append(trace_data)
        
        else:
            # Fallback to PCAP processing if no Tor logs available
            print("No Tor cell traces found, falling back to PCAP processing")
            pcap_files = list(Path(shadow_data_dir).glob("**/*.pcap"))
            
            for pcap_file in pcap_files:
                print(f"Processing {pcap_file}")
                
                # Extract client info from filename or use default
                client_name = pcap_file.stem
                # For markovclient pattern from your config
                if 'markovclient' in client_name:
                    client_ip = "11.0.0.100"  # Adjust based on your network config
                else:
                    client_ip = "11.0.0.100"  # Default
                
                # Extract cell features
                cells = self.extract_pcap_features(pcap_file, client_ip)
                
                if not cells:
                    continue
                
                # Process similar to Tor logs method above
                # ... (rest of processing logic)
            
        return dataset
    
    def save_dataset(self, dataset, format='pickle'):
        """Save processed dataset"""
        
        if format == 'pickle':
            import pickle
            with open(self.output_dir / 'wf_dataset.pkl', 'wb') as f:
                pickle.dump(dataset, f)
                
        elif format == 'json':
            # Convert numpy arrays to lists for JSON serialization
            json_dataset = []
            for trace in dataset:
                json_trace = trace.copy()
                for key, value in json_trace.items():
                    if isinstance(value, np.ndarray):
                        json_trace[key] = value.tolist()
                json_dataset.append(json_trace)
                
            with open(self.output_dir / 'wf_dataset.json', 'w') as f:
                json.dump(json_dataset, f, indent=2)
        
        print(f"Dataset saved to {self.output_dir}")


def main():
    parser = argparse.ArgumentParser(description='Process Shadow simulation for WF research')
    parser.add_argument('--shadow-data', required=True, help='Shadow simulation data directory')
    parser.add_argument('--output-dir', required=True, help='Output directory for processed dataset')
    parser.add_argument('--pcap-dir', help='Directory containing PCAP files')
    parser.add_argument('--format', choices=['pickle', 'json'], default='pickle', 
                       help='Output format for dataset')
    
    args = parser.parse_args()
    
    # Create processor
    processor = ShadowWFProcessor(args.shadow_data, args.output_dir)
    
    # Example client IP mappings (adjust based on your Shadow config)
    client_mappings = {
        'client1': '11.0.0.100',
        'client2': '11.0.0.101',
        # Add more clients as needed
    }
    
    # Process the simulation data
    if args.pcap_dir:
        dataset = processor.create_wf_dataset(args.pcap_dir, client_mappings)
        processor.save_dataset(dataset, args.format)
    else:
        print("PCAP directory not specified. Processing logs only.")
        visits = processor.process_shadow_logs() 
        print(f"Found {len(visits)} unique URLs with visits")


if __name__ == '__main__':
    main()