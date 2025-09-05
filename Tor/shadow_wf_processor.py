#!/usr/bin/env python3
"""
Single Simulation Shadow WF Processor chronological and port correlation

This script processes one simulation at a time to chronologically
merge lo.pcap and eth0.pcap for accurate request-traffic correlation.

Date: 2025
"""

import os
import sys
import pickle
import argparse
import re
import multiprocessing as mp
import subprocess
import tempfile
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
    def __init__(self, sequence_length: int = 5000, max_workers: int = None, reference_labels_file: str = None):
        """
        Initialize the single simulation processor
        
        Args:
            sequence_length: Fixed length for packet sequences (default: 5000)
            max_workers: Number of parallel workers (default: min(4, CPU count))
            reference_labels_file: Path to existing labels file for consistent labeling
        """
        self.sequence_length = sequence_length
        self.max_workers = min(max_workers or 4, mp.cpu_count())
        self.reference_labels_file = reference_labels_file
        
        # Initialize label mappings
        if reference_labels_file:
            self._load_reference_labels(reference_labels_file)
        else:
            self.url_to_label = {}
            self.label_to_url = {}
            self.current_label = 0
            
    def _load_reference_labels(self, labels_file: str):
        """Load existing label mappings from a reference file"""
        try:
            labels_path = Path(labels_file)
            if not labels_path.exists():
                logger.warning(f"Reference labels file not found: {labels_file}")
                logger.info("Creating new label mappings...")
                self.url_to_label = {}
                self.label_to_url = {}
                self.current_label = 0
                return
            
            with open(labels_path, 'rb') as f:
                labels_data = pickle.load(f)
            
            self.url_to_label = labels_data.get('url_to_label', {})
            self.label_to_url = labels_data.get('label_to_url', {})
            
            # Set current_label to continue from where the reference left off
            if self.label_to_url:
                self.current_label = max(self.label_to_url.keys()) + 1
            else:
                self.current_label = 0
            
            logger.info(f"Loaded reference labels: {len(self.url_to_label)} existing URLs")
            logger.debug(f"Next available label: {self.current_label}")
            
            # Show sample URLs from reference
            sample_urls = list(self.url_to_label.keys())[:10]
            logger.debug(f"Reference URLs sample: {sample_urls}")
            
        except Exception as e:
            logger.error(f"Error loading reference labels from {labels_file}: {e}")
            logger.info("Creating new label mappings...")
            self.url_to_label = {}
            self.label_to_url = {}
            self.current_label = 0
        
    def _extract_url_from_http(self, http_payload: str) -> Optional[Tuple[str, bool]]:
        """Extract URL/page identifier and determine if it's a main page"""
        lines = http_payload.split('\n')
        if not lines:
            return None
            
        get_line = lines[0].strip()
        match = re.match(r'GET\s+([^\s]+)\s+HTTP', get_line)
        
        if match:
            path = match.group(1)
            
            # Skip robots.txt and favicon requests
            skip_patterns = ['robots.txt', 'favicon.ico', '.cur', '.php', 'main_page']
            if any(pattern in path.lower() for pattern in skip_patterns):
                return None
            
            # Remove query parameters and fragments
            clean_path = path.split('?')[0].split('#')[0]
            
            # Determine if this is a resource or main page
            resource_patterns = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', 
                               '.ico', '.svg', '.woff', '.ttf', '.pdf', '.mp4', '.webp']
            is_resource = any(pattern in clean_path.lower() for pattern in resource_patterns)
            
            # Extract page identifier
            path_parts = clean_path.split('/')
            
            if is_resource:
                # For resources, try to infer the parent page
                if len(path_parts) >= 3:
                    # e.g., "/William_Shakespeare/style.css" -> "William_Shakespeare"
                    parent_page = path_parts[-2]
                elif len(path_parts) >= 2:
                    # e.g., "/style.css" -> might be for previous main page
                    parent_page = None  # Let the processor handle this
                else:
                    parent_page = None
                
                if parent_page and len(parent_page) > 2:
                    page_id = unquote(parent_page).strip()
                    return (page_id, False)  # (page_id, is_main_page)
                else:
                    return None
            else:
                # Main page request
                if len(path_parts) >= 3:
                    page_id = path_parts[-1]
                elif len(path_parts) == 2 and path_parts[1]:
                    page_id = path_parts[1]
                else:
                    return None
                
                page_id = unquote(page_id).strip()
                
                # Skip empty, very short, or numeric-only IDs
                if not page_id or len(page_id) < 3 or page_id.isdigit() or page_id.lower() == 'main_page':
                    return None
                    
                return (page_id, True)  # (page_id, is_main_page)
        
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
    
    def process_merged_pcap(self, merged_pcap_file: Path, monitor_name: str) -> List[TrafficSequence]:
        """Process chronologically merged pcap file"""
        logger.info(f"Processing merged pcap for {monitor_name}")
        
        # Identify local IPs first
        local_ips = self._identify_local_ips(merged_pcap_file)
        logger.debug(f"Using local IPs: {local_ips}")
        
        traffic_sequences = []
        current_main_page = None
        page_start_time = None
        packet_count = 0
        http_request_count = 0
        all_sequences = {}
        port_url={}

        try:
            with PcapReader(str(merged_pcap_file)) as pcap_reader:
                prev_seq = 0
                prev_ack = 0
                prev_win = 0
                prev_len = 0

                for packet in pcap_reader:
                    packet_count += 1
                    
                    if packet_count % 10000 == 0:
                        logger.debug(f"Processed {packet_count} merged packets...")
                    
                    packet_time = float(packet.time)
                    
                    # Check for HTTP requests (from lo.pcap - loopback traffic)
                    if (IP in packet and TCP in packet and Raw in packet and packet[IP].len > 40):
                        try:
                            payload = packet[Raw].load.decode('utf-8', errors='ignore')
                            if packet[TCP].seq!=prev_seq or prev_ack!=packet[TCP].ack or prev_win!=packet[TCP].window or (prev_len!=len(packet[TCP].payload)):
                                if payload.startswith('GET ') and packet[TCP].dport == 9050:
                                    url_info = self._extract_url_from_http(payload)
                                    
                                    if url_info:
                                        page_id, is_main_page = url_info
                                        http_request_count += 1
                                        
                                        if is_main_page:
                                            # Save previous sequence if exists
                                            sport = packet[TCP].sport
                                            temp_url = port_url.get(sport, "unknown")
                                            temp_sequences = all_sequences.get(page_id, "None")
                                            if (temp_url == "unknown" or temp_url != page_id) and temp_sequences != "None" and temp_sequences != []:
                                                traffic_seq = TrafficSequence(
                                                    url=page_id,
                                                    sequence=all_sequences.get(page_id).copy(),
                                                    start_time=page_start_time,
                                                    end_time=packet_time,
                                                    monitor=monitor_name
                                                )
                                                traffic_sequences.append(traffic_seq)
                                                
                                                logger.debug(f"Completed page {current_main_page}: {len(all_sequences.get(page_id))} packets")
                                            
                                            # Start new main page
                                            current_main_page = page_id
                                            page_start_time = packet_time
                                            #url_port[current_main_page] = packet[TCP].sport 
                                            port_url[packet[TCP].sport] = page_id
                                            all_sequences[page_id] = [1]

                                            
                                            logger.debug(f"Started new main page: {page_id}")
                                        
                                        else:
                                            # Resource request - should belong to current main page
                                            if 'Referer:' in payload:
                                                for line in payload.split('\r\n'):
                                                    if line.lower().startswith('referer:'):
                                                        referer = line.split(':', 1)[1].strip()
                                                        all_sequences[referer].append(1)
                                                        # Resource without main page - use the resource's inferred page
                                                        current_main_page = page_id
                                                        page_start_time = packet_time
                                                        logger.debug(f"Started page from resource: {page_id}")
                                                        
                                                        logger.debug(f"Found resource for {current_main_page}: {page_id}")

                                elif packet[TCP].sport == 9050:
                                    dport = packet[TCP].dport
                                    temp_url = port_url.get(dport, "unknown")
                                    if temp_url != "unknown":
                                        cells = len(packet[TCP].payload) // 512
                                        for i in range(cells):
                                            all_sequences[temp_url].append(-1)

                                prev_seq = packet[TCP].seq
                                prev_ack = packet[TCP].ack
                                prev_len = len(packet[TCP].payload)
                                prev_win = packet[TCP].window

                        except (UnicodeDecodeError, AttributeError):
                            continue
            for page, seq in all_sequences.items():
                traffic_seq = TrafficSequence(
                        url=page,
                        sequence=seq.copy(),
                        start_time=page_start_time,
                        end_time=packet_time,
                        monitor=monitor_name
                    )
                traffic_sequences.append(traffic_seq)
                logger.debug(f"Final page {page}: {len(seq)} packets")
        
        except Exception as e:
            logger.exception(f"Error processing merged pcap")
        
        logger.info(f"Found {http_request_count} HTTP requests, extracted {len(traffic_sequences)} traffic sequences")
        return traffic_sequences
    
    def _identify_local_ips(self, merged_pcap_file: Path) -> set:
        """Identify local IPs from merged pcap file"""
        local_ips = set()
        
        try:
            with PcapReader(str(merged_pcap_file)) as pcap_reader:
                for i, packet in enumerate(pcap_reader):
                    if i >= 1000:  # Sample first 1000 packets
                        break
                    
                    if IP in packet:
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                        
                        # Skip loopback
                        if src_ip == '127.0.0.1' or dst_ip == '127.0.0.1':
                            continue
                        
                        if self._is_private_ip(src_ip):
                            local_ips.add(src_ip)
                        if self._is_private_ip(dst_ip):
                            local_ips.add(dst_ip)
        
        except Exception as e:
            logger.warning(f"Could not sample for local IPs: {e}")
        
        # Default local IPs if none found
        if not local_ips:
            local_ips = {'11.0.0.101', '10.0.0.1', '172.16.0.1'}
        
        return local_ips
    
    def process_monitor_sequential(self, monitor_path: Path) -> List[TrafficSequence]:
        """Process a monitor's pcap files"""
        logger.info(f"Processing monitor: {monitor_path.name}")
        
        # Find pcap files
        lo_pcap_files = list(monitor_path.glob("*lo.pcap"))

        if not lo_pcap_files:
            logger.warning(f"Missing pcap files in {monitor_path}")
            return []

        
        lo_pcap_file = lo_pcap_files[0]
            
        if lo_pcap_file:
            try:
                traffic_sequences = self.process_merged_pcap(lo_pcap_file, monitor_path.name)
                logger.info(f"Extracted {len(traffic_sequences)} traffic sequences")
                return traffic_sequences
            
            finally:
                # Clean up temporary file
                # if merged_pcap_file.exists():
                #     merged_pcap_file.unlink()
                pass
        
        else:
            logger.warning(f"Mergecap failed for {monitor_path.name}, falling back to time-based method")
    
    
    def pad_or_truncate_sequence(self, sequence: List[int]) -> List[int]:
        """Pad or truncate sequence to fixed length"""
        if len(sequence) >= self.sequence_length:
            return sequence[:self.sequence_length]
        else:
            padding = [0] * (self.sequence_length - len(sequence))
            return sequence + padding
    
    def get_url_label(self, url: str) -> int:
        """Get or create label for URL using reference mappings"""
        if url not in self.url_to_label:
            # New URL not in reference - create new label
            self.url_to_label[url] = self.current_label
            self.label_to_url[self.current_label] = url
            #logger.debug(f"Created new label {self.current_label} for URL: {url}")
            self.current_label += 1
        # else:
        #     pass
            #logger.debug(f"Using existing label {self.url_to_label[url]} for URL: {url}")
        
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
        
        # Report new URLs if using reference labels
        if self.reference_labels_file:
            reference_url_count = self._count_reference_urls()
            new_urls = len(self.url_to_label) - reference_url_count
            if new_urls > 0:
                logger.info(f"Found {new_urls} new URLs not in reference file")
    
    def _count_reference_urls(self) -> int:
        """Count URLs from the reference file (for reporting purposes)"""
        if not self.reference_labels_file:
            return 0
        
        try:
            with open(self.reference_labels_file, 'rb') as f:
                labels_data = pickle.load(f)
            return len(labels_data.get('url_to_label', {}))
        except:
            return 0
    
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
                executor.submit(process_single_monitor_worker, monitor_dir, self.sequence_length, self.reference_labels_file): monitor_dir
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


def process_single_monitor_worker(monitor_path: Path, sequence_length: int, reference_labels_file: str = None) -> List[TrafficSequence]:
    """Worker function for parallel monitor processing"""
    try:
        # Create a temporary processor for this worker
        processor = SingleSimulationProcessor(sequence_length=sequence_length, max_workers=1,
                                            reference_labels_file=reference_labels_file)
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
    parser.add_argument('--max-workers', type=int, default=4,
                        help='Maximum workers (default: 4)')
    parser.add_argument('--no-parallel-monitors', action='store_true',
                        help='Disable parallel monitor processing')
    parser.add_argument('--reference-labels', type=str, default=None,
                        help='Path to reference labels file for consistent labeling')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize processor
    processor = SingleSimulationProcessor(
        args.sequence_length,
        args.max_workers,
        reference_labels_file=args.reference_labels
    )
    
    sim_path = Path(args.sim_path)
    output_dir = Path(args.output_dir)
    
    # Process single simulation
    use_parallel = not args.no_parallel_monitors
    processor.process_single_simulation(sim_path, output_dir, use_parallel)
    
    logger.info("Single simulation processing complete!")


if __name__ == "__main__":
    main()