#!/usr/bin/env python3
"""
Single Simulation Shadow WF Processor

This script processes one simulation at a time to avoid memory/CPU overload.
Results can be merged later using the merge_pickles.py script.

Author: Claude
Date: 2025
"""

import os
import sys
import pickle
import argparse
import re
import multiprocessing as mp
from pathlib import Path
from typing import Dict, List, Tuple, Optional, NamedTuple
import numpy as np
from collections import defaultdict
import logging
from urllib.parse import unquote
import time

try:
    from scapy.all import PcapReader, IP, TCP, Raw
except ImportError:
    print("Error: scapy is required. Install with: pip install scapy")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class HTTPTrace(NamedTuple):
    """Structure to hold information about an HTTP request"""
    url: str
    start_time: float
    end_time: Optional[float]
    monitor: str
    src_port: int
    dst_port: int

class TrafficSequence(NamedTuple):
    """Structure to hold extracted traffic sequence"""
    url: str
    sequence: List[int]
    start_time: float
    end_time: float
    monitor: str

class SingleSimulationProcessor:
    def __init__(self, sequence_length: int = 5000, time_window: float = 4.0, max_workers: int = None):
        """
        Initialize the single simulation processor
        
        Args:
            sequence_length: Fixed length for packet sequences (default: 5000)
            time_window: Time window in seconds to look for corresponding traffic
            max_workers: Number of parallel workers (default: min(4, CPU count))
        """
        self.sequence_length = sequence_length
        self.time_window = time_window
        # Limit workers to prevent system overload
        self.max_workers = min(max_workers or 4, mp.cpu_count())
        self.url_to_label = {}
        self.label_to_url = {}
        self.current_label = 0
        
    def _extract_url_from_http(self, http_payload: str) -> Optional[str]:
        """Extract URL/page identifier from HTTP GET request"""
        lines = http_payload.split('\n')
        if not lines:
            return None
            
        get_line = lines[0].strip()
        match = re.match(r'GET\s+([^\s]+)\s+HTTP', get_line)
        
        if match:
            path = match.group(1)
            
            # Skip robots.txt requests
            if 'robots.txt' in path:
                return None
            
            # Extract the page identifier from the path
            path_parts = path.split('/')
            if len(path_parts) >= 3:
                page_id = path_parts[-1]
                page_id = unquote(page_id)
                return page_id
            else:
                return path.lstrip('/')
        
        return None
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            octets = ip.split('.')
            if len(octets) != 4:
                return False
                
            first = int(octets[0])
            second = int(octets[1])
            
            # Private IP ranges + Shadow common ranges
            if first == 10:
                return True
            elif first == 172 and 16 <= second <= 31:
                return True
            elif first == 192 and second == 168:
                return True
            elif first == 127:
                return True
            elif first == 11:  # Shadow often uses 11.x.x.x
                return True
                
        except ValueError:
            pass
            
        return False
    
    def process_monitor_sequential(self, monitor_path: Path) -> List[TrafficSequence]:
        """
        Process a monitor's pcap files sequentially to reduce memory usage
        """
        logger.info(f"Processing monitor: {monitor_path.name}")
        
        # Find pcap files
        lo_pcap_files = list(monitor_path.glob("*lo.pcap"))
        eth0_pcap_files = list(monitor_path.glob("*eth0.pcap"))
        
        if not lo_pcap_files or not eth0_pcap_files:
            logger.warning(f"Missing pcap files in {monitor_path}")
            return []
        
        lo_pcap_file = lo_pcap_files[0]
        eth0_pcap_file = eth0_pcap_files[0]
        
        # Phase 1: Extract HTTP traces
        http_traces = self._extract_http_traces(lo_pcap_file, monitor_path.name)
        
        if not http_traces:
            logger.warning(f"No HTTP traces found in {lo_pcap_file}")
            return []
        
        # Phase 2: Extract traffic sequences
        traffic_sequences = self._extract_traffic_sequences(
            eth0_pcap_file, http_traces, monitor_path.name
        )
        
        logger.info(f"Extracted {len(traffic_sequences)} traffic sequences from {monitor_path.name}")
        return traffic_sequences
    
    def _extract_http_traces(self, lo_pcap_file: Path, monitor_name: str) -> List[HTTPTrace]:
        """Extract HTTP traces with memory-efficient streaming"""
        http_traces = []
        request_tracker = {}
        packet_count = 0
        
        try:
            with PcapReader(str(lo_pcap_file)) as pcap_reader:
                for packet in pcap_reader:
                    packet_count += 1
                    
                    # Progress indicator
                    if packet_count % 5000 == 0:
                        logger.debug(f"Processed {packet_count} lo.pcap packets...")
                    
                    if not (IP in packet and TCP in packet and Raw in packet):
                        continue
                    
                    try:
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        packet_time = float(packet.time)
                        src_port = packet[TCP].sport
                        dst_port = packet[TCP].dport
                        
                        # Look for HTTP GET requests
                        if payload.startswith('GET '):
                            url = self._extract_url_from_http(payload)
                            if url:
                                flow_key = (src_port, dst_port)
                                request_tracker[flow_key] = HTTPTrace(
                                    url=url,
                                    start_time=packet_time,
                                    end_time=None,
                                    monitor=monitor_name,
                                    src_port=src_port,
                                    dst_port=dst_port
                                )
                        
                        # Look for HTTP responses
                        elif payload.startswith('HTTP/1.1'):
                            flow_key = (dst_port, src_port)  # Reversed for response
                            if flow_key in request_tracker:
                                trace = request_tracker.pop(flow_key)
                                completed_trace = HTTPTrace(
                                    url=trace.url,
                                    start_time=trace.start_time,
                                    end_time=packet_time,
                                    monitor=monitor_name,
                                    src_port=trace.src_port,
                                    dst_port=trace.dst_port
                                )
                                http_traces.append(completed_trace)
                    
                    except (UnicodeDecodeError, AttributeError):
                        continue
            
            # Handle unclosed requests
            for trace in request_tracker.values():
                completed_trace = HTTPTrace(
                    url=trace.url,
                    start_time=trace.start_time,
                    end_time=trace.start_time + 30.0,
                    monitor=monitor_name,
                    src_port=trace.src_port,
                    dst_port=trace.dst_port
                )
                http_traces.append(completed_trace)
            
            http_traces.sort(key=lambda x: x.start_time)
            logger.info(f"Found {len(http_traces)} HTTP traces")
            
        except Exception as e:
            logger.error(f"Error processing {lo_pcap_file}: {e}")
            
        return http_traces
    
    def _extract_traffic_sequences(self, eth0_pcap_file: Path, 
                                 http_traces: List[HTTPTrace],
                                 monitor_name: str) -> List[TrafficSequence]:
        """Extract traffic sequences with time-based correlation"""
        
        # Create time windows
        time_windows = []
        for trace in http_traces:
            if trace.end_time:
                start_time = trace.start_time - self.time_window/2
                end_time = trace.end_time + self.time_window/2
            else:
                start_time = trace.start_time - self.time_window/2
                end_time = trace.start_time + self.time_window
            time_windows.append((start_time, end_time, trace))
        
        time_windows.sort(key=lambda x: x[0])
        
        # Identify local IPs (quick sample)
        local_ips = set()
        try:
            with PcapReader(str(eth0_pcap_file)) as pcap_reader:
                for i, packet in enumerate(pcap_reader):
                    if i >= 500:  # Sample fewer packets to save memory
                        break
                    
                    if IP in packet:
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                        
                        if self._is_private_ip(src_ip):
                            local_ips.add(src_ip)
                        if self._is_private_ip(dst_ip):
                            local_ips.add(dst_ip)
        except Exception as e:
            logger.warning(f"Could not identify local IPs: {e}")
        
        if not local_ips:
            local_ips = {'11.0.0.101', '10.0.0.1', '172.16.0.1'}
        
        logger.debug(f"Using local IPs: {local_ips}")
        
        # Process traffic
        traffic_sequences = []
        current_sequences = {}
        packet_count = 0
        
        try:
            with PcapReader(str(eth0_pcap_file)) as pcap_reader:
                for packet in pcap_reader:
                    packet_count += 1
                    
                    if packet_count % 10000 == 0:
                        logger.debug(f"Processed {packet_count} eth0 packets...")
                    
                    if not (IP in packet and TCP in packet):
                        continue
                    
                    packet_time = float(packet.time)
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    
                    # Skip loopback
                    if src_ip == '127.0.0.1' or dst_ip == '127.0.0.1':
                        continue
                    
                    # Update active windows
                    active_windows = []
                    for window_idx, (start_time, end_time, trace) in enumerate(time_windows):
                        if start_time <= packet_time <= end_time:
                            active_windows.append(window_idx)
                            if window_idx not in current_sequences:
                                current_sequences[window_idx] = []
                        elif packet_time > end_time and window_idx in current_sequences:
                            # Finalize sequence
                            sequence = current_sequences.pop(window_idx)
                            if len(sequence) > 10:
                                traffic_seq = TrafficSequence(
                                    url=trace.url,
                                    sequence=sequence,
                                    start_time=start_time,
                                    end_time=end_time,
                                    monitor=monitor_name
                                )
                                traffic_sequences.append(traffic_seq)
                    
                    # Determine direction
                    direction = None
                    if src_ip in local_ips and dst_ip not in local_ips:
                        direction = 1  # Outgoing
                    elif dst_ip in local_ips and src_ip not in local_ips:
                        direction = -1  # Incoming
                    
                    # Add to active sequences
                    if direction is not None:
                        for window_idx in active_windows:
                            current_sequences[window_idx].append(direction)
                
                # Finalize remaining sequences
                for window_idx, sequence in current_sequences.items():
                    if len(sequence) > 10:
                        _, _, trace = time_windows[window_idx]
                        traffic_seq = TrafficSequence(
                            url=trace.url,
                            sequence=sequence,
                            start_time=time_windows[window_idx][0],
                            end_time=time_windows[window_idx][1],
                            monitor=monitor_name
                        )
                        traffic_sequences.append(traffic_seq)
        
        except Exception as e:
            logger.error(f"Error processing {eth0_pcap_file}: {e}")
        
        return traffic_sequences
    
    def pad_or_truncate_sequence(self, sequence: List[int]) -> List[int]:
        """Pad or truncate sequence to fixed length"""
        if len(sequence) >= self.sequence_length:
            return sequence[:self.sequence_length]
        else:
            padding = [0] * (self.sequence_length - len(sequence))
            return sequence + padding
    
    def get_url_label(self, url: str) -> int:
        """Get or create label for URL"""
        if url not in self.url_to_label:
            self.url_to_label[url] = self.current_label
            self.label_to_url[self.current_label] = url
            self.current_label += 1
        
        return self.url_to_label[url]
    
    def process_single_simulation(self, sim_path: Path, output_dir: Path, use_parallel_monitors: bool = True):
        """Process a single simulation and save results"""
        logger.info(f"Processing simulation: {sim_path.name}")
        start_time = time.time()
        
        # Find monitor directories
        monitor_dirs = list(sim_path.glob("shadow.data/hosts/monitor*"))
        
        if not monitor_dirs:
            logger.error(f"No monitor directories found in {sim_path}")
            return
        
        logger.info(f"Found {len(monitor_dirs)} monitors")
        
        if use_parallel_monitors and len(monitor_dirs) > 1 and self.max_workers > 1:
            # Use controlled parallel processing for monitors
            all_sequences = self._process_monitors_parallel(monitor_dirs)
        else:
            # Use sequential processing
            all_sequences = self._process_monitors_sequential(monitor_dirs)
        
        if not all_sequences:
            logger.warning(f"No sequences extracted from {sim_path.name}")
            return
        
        # Convert to arrays
        X_data = []
        y_data = []
        
        for seq in all_sequences:
            label = self.get_url_label(seq.url)
            fixed_sequence = self.pad_or_truncate_sequence(seq.sequence)
            X_data.append(fixed_sequence)
            y_data.append(label)
        
        X_array = np.array(X_data)
        y_array = np.array(y_data)
        
        # Create output directory
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Save simulation data
        sim_name = sim_path.name
        
        with open(output_dir / f"X_{sim_name}.pkl", 'wb') as f:
            pickle.dump(X_array, f)
        with open(output_dir / f"y_{sim_name}.pkl", 'wb') as f:
            pickle.dump(y_array, f)
        with open(output_dir / f"labels_{sim_name}.pkl", 'wb') as f:
            pickle.dump({
                'url_to_label': self.url_to_label,
                'label_to_url': self.label_to_url
            }, f)
        
        processing_time = time.time() - start_time
        logger.info(f"Simulation {sim_name} completed: {len(X_data)} sequences in {processing_time:.1f}s")
        logger.info(f"Found {len(self.url_to_label)} unique URLs")
    
    def _process_monitors_parallel(self, monitor_dirs):
        """Process monitors in parallel with resource control"""
        from concurrent.futures import ProcessPoolExecutor, as_completed
        
        all_sequences = []
        # Limit to 3 workers max (one per monitor typically)
        max_monitor_workers = min(3, len(monitor_dirs), self.max_workers)
        
        logger.info(f"Processing {len(monitor_dirs)} monitors with {max_monitor_workers} parallel workers")
        
        with ProcessPoolExecutor(max_workers=max_monitor_workers) as executor:
            # Submit jobs
            future_to_monitor = {
                executor.submit(process_single_monitor_worker, monitor_dir, self.time_window, self.sequence_length): monitor_dir
                for monitor_dir in monitor_dirs
            }
            
            # Collect results
            for future in as_completed(future_to_monitor):
                monitor_dir = future_to_monitor[future]
                try:
                    sequences = future.result()
                    all_sequences.extend(sequences)
                    logger.info(f"Completed {monitor_dir.name}: {len(sequences)} sequences")
                except Exception as e:
                    logger.error(f"Error processing {monitor_dir}: {e}")
        
        return all_sequences
    
    def _process_monitors_sequential(self, monitor_dirs):
        """Process monitors sequentially (fallback method)"""
        all_sequences = []
        
        for monitor_dir in monitor_dirs:
            logger.info(f"Processing monitor {monitor_dir.name}")
            try:
                sequences = self.process_monitor_sequential(monitor_dir)
                all_sequences.extend(sequences)
                logger.info(f"Monitor {monitor_dir.name}: {len(sequences)} sequences")
                
                # Force garbage collection after each monitor
                import gc
                gc.collect()
                
            except Exception as e:
                logger.error(f"Error processing {monitor_dir}: {e}")
                continue
        
        return all_sequences


def process_single_monitor_worker(monitor_path: Path, time_window: float, sequence_length: int) -> List[TrafficSequence]:
    """Worker function for parallel monitor processing"""
    try:
        # Create a temporary processor for this worker
        processor = SingleSimulationProcessor(sequence_length=sequence_length, time_window=time_window, max_workers=1)
        return processor.process_monitor_sequential(monitor_path)
    except Exception as e:
        logger.error(f"Worker error processing {monitor_path}: {e}")
        return []


def main():
    parser = argparse.ArgumentParser(description='Single Simulation Shadow WF Processor')
    parser.add_argument('sim_path', help='Path to single simulation directory')
    parser.add_argument('output_dir', help='Output directory for processed data')
    parser.add_argument('--sequence-length', type=int, default=5000,
                        help='Fixed sequence length (default: 5000)')
    parser.add_argument('--time-window', type=float, default=4.0,
                        help='Time window in seconds (default: 4.0)')
    parser.add_argument('--max-workers', type=int, default=4,
                        help='Maximum workers (default: 4)')
    parser.add_argument('--no-parallel-monitors', action='store_true',
                        help='Disable parallel monitor processing')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize processor
    processor = SingleSimulationProcessor(
        args.sequence_length,
        args.time_window,
        args.max_workers
    )
    
    sim_path = Path(args.sim_path)
    output_dir = Path(args.output_dir)
    
    # Process single simulation
    use_parallel = not args.no_parallel_monitors
    processor.process_single_simulation(sim_path, output_dir, use_parallel)
    
    logger.info("Single simulation processing complete!")


if __name__ == "__main__":
    main()