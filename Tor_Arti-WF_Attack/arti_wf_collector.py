#!/usr/bin/env python3
"""
Arti-Compatible Website Fingerprinting Data Collector
Modified for Docker container with Arti proxy

Key changes from original:
- Removed Tor control port dependencies
- Simplified circuit management (relies on Arti's built-in behavior)
- Docker-compatible paths and networking
- Manual timing delays instead of programmatic circuit control
"""

import time
import json
import logging
import threading
import numpy as np
import os
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
import subprocess
import signal
import sys

# Core dependencies
try:
    from scapy.all import sniff, IP, TCP, Raw, get_if_list
    from tbselenium.tbdriver import TorBrowserDriver
    import tbselenium.common as cm
except ImportError as e:
    print(f"Missing required dependency: {e}")
    print("Install with: pip install scapy tbselenium")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/wf_collector.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class PacketInfo:
    """Individual packet information following Tik-Tok methodology"""
    timestamp: float
    size: int
    direction: int  # +1 for outgoing, -1 for incoming
    tcp_flags: int
    sequence_num: int = 0

@dataclass
class TrafficTrace:
    """Complete traffic trace for a website visit"""
    url: str
    packets: List[PacketInfo]
    start_time: float
    end_time: float
    total_packets: int = 0
    total_bytes_in: int = 0
    total_bytes_out: int = 0

class ArtiProxyManager:
    """Simplified proxy management for Arti (no control port)"""
    
    def __init__(self, socks_port: int = 9150):
        self.socks_port = socks_port
        self.restart_interval = 300  # Restart Arti every 5 minutes for fresh circuits
        self.last_restart = time.time()
        
    def ensure_fresh_circuits(self):
        """Restart Arti periodically to get fresh circuits"""
        if time.time() - self.last_restart > self.restart_interval:
            logger.info("Restarting Arti for fresh circuits")
            self.restart_arti()
            self.last_restart = time.time()
    
    def restart_arti(self):
        """Restart Arti process (Docker-specific)"""
        try:
            # Kill existing Arti process
            subprocess.run(['pkill', '-f', 'arti'], check=False)
            time.sleep(2)
            
            # Start new Arti process
            subprocess.Popen([
                '/opt/arti/target/release/arti', 'proxy',
                '-l', 'debug', '-p', str(self.socks_port)
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Wait for Arti to be ready
            time.sleep(10)
            logger.info("Arti restarted successfully")
            
        except Exception as e:
            logger.error(f"Failed to restart Arti: {e}")

class PacketCollector:
    """Collects packets with timing information"""
    
    def __init__(self, interface: str = "eth0"):
        self.interface = interface
        self.packets = []
        self.collecting = False
        self.start_time = None
        
    def packet_handler(self, packet):
        """Process individual packets"""
        if not self.collecting:
            return
        
        if packet.haslayer(TCP) and packet.haslayer(IP):
            # Determine direction based on Arti SOCKS port
            direction = self.determine_direction(packet)
            
            packet_info = PacketInfo(
                timestamp=float(packet.time),
                size=len(packet),
                direction=direction,
                tcp_flags=packet[TCP].flags,
                sequence_num=len(self.packets)
            )
            
            self.packets.append(packet_info)
    
    def determine_direction(self, packet) -> int:
        """Determine packet direction for Arti traffic"""
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        
        # Arti SOCKS port
        if dst_port == 9150:
            return 1  # Outgoing to Arti
        elif src_port == 9150:
            return -1  # Incoming from Arti
        else:
            # Default heuristic for other connections
            return 1 if src_port > dst_port else -1
    
    def start_collection(self):
        """Start packet collection"""
        self.packets = []
        self.collecting = True
        self.start_time = time.time()
        
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            daemon=True
        )
        self.capture_thread.start()
        logger.info(f"Started packet collection on {self.interface}")
    
    def _capture_packets(self):
        """Background packet capture"""
        try:
            sniff(
                iface=self.interface,
                filter="tcp and not port 22",  # Exclude SSH
                prn=self.packet_handler,
                store=0,
                stop_filter=lambda p: not self.collecting
            )
        except Exception as e:
            logger.error(f"Packet capture error: {e}")
    
    def stop_collection(self) -> List[PacketInfo]:
        """Stop collection and return packets"""
        self.collecting = False
        time.sleep(1)
        logger.info(f"Collected {len(self.packets)} packets")
        return self.packets.copy()

class TikTokFeatureExtractor:
    """Extract Tik-Tok timing features from traffic traces"""
    
    @staticmethod
    def extract_directional_timing(packets: List[PacketInfo]) -> np.ndarray:
        """Extract directional timing sequence"""
        if not packets:
            return np.array([])
        
        start_time = packets[0].timestamp
        directional_times = []
        
        for packet in packets:
            rel_time = packet.timestamp - start_time
            directional_time = rel_time * packet.direction
            directional_times.append(directional_time)
        
        return np.array(directional_times)
    
    @staticmethod
    def extract_burst_features(packets: List[PacketInfo]) -> Dict:
        """Extract burst-level timing features"""
        if not packets:
            return {}
        
        # Identify bursts
        bursts = []
        current_burst = [packets[0]]
        
        for i in range(1, len(packets)):
            if packets[i].direction == packets[i-1].direction:
                current_burst.append(packets[i])
            else:
                bursts.append(current_burst)
                current_burst = [packets[i]]
        
        if current_burst:
            bursts.append(current_burst)
        
        # Calculate burst statistics
        burst_lengths = [len(burst) for burst in bursts]
        burst_durations = []
        inter_burst_delays = []
        
        for burst in bursts:
            if len(burst) > 1:
                duration = burst[-1].timestamp - burst[0].timestamp
                burst_durations.append(duration)
        
        for i in range(len(bursts) - 1):
            delay = bursts[i+1][0].timestamp - bursts[i][-1].timestamp
            inter_burst_delays.append(delay)
        
        return {
            'num_bursts': len(bursts),
            'avg_burst_length': np.mean(burst_lengths) if burst_lengths else 0,
            'avg_burst_duration': np.mean(burst_durations) if burst_durations else 0,
            'avg_inter_burst_delay': np.mean(inter_burst_delays) if inter_burst_delays else 0,
            'burst_length_variance': np.var(burst_lengths) if burst_lengths else 0
        }

class ArtiWebsiteFingerprintCollector:
    """Arti-compatible website fingerprinting collector"""
    
    def __init__(self, output_dir: str = "/app/wf_data"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Initialize components
        self.proxy_manager = ArtiProxyManager()
        self.packet_collector = PacketCollector()
        self.feature_extractor = TikTokFeatureExtractor()
        
        # Collection statistics
        self.collected_traces = 0
        self.failed_collections = 0
        
        # Docker environment variables
        self.tbb_path = os.environ.get('TBB_PATH', '/opt/tor-browser')
        
    def collect_single_trace(self, url: str, visit_duration: int = 30) -> Optional[TrafficTrace]:
        """Collect traffic trace for a single website"""
        logger.info(f"Collecting trace for: {url}")
        
        # Ensure fresh circuits
        self.proxy_manager.ensure_fresh_circuits()
        
        # Start packet collection
        self.packet_collector.start_collection()
        
        try:
            start_time = time.time()
            
            # Configure tbselenium for Arti
            driver_options = {
                'tbb_dir': self.tbb_path,
                'headless': True,
                'tbb_logfile_path': '/dev/null',
                'socks_port': 9150,
                'pref_dict': {
                    'network.proxy.socks': 'localhost',
                    'network.proxy.socks_port': 9150,
                    'network.proxy.type': 1
                }
            }
            
            with TorBrowserDriver(**driver_options) as driver:
                driver.get(url)
                time.sleep(visit_duration)
            
            end_time = time.time()
            
            # Stop packet collection
            packets = self.packet_collector.stop_collection()
            
            # Create traffic trace
            trace = TrafficTrace(
                url=url,
                packets=packets,
                start_time=start_time,
                end_time=end_time,
                total_packets=len(packets),
                total_bytes_in=sum(p.size for p in packets if p.direction == -1),
                total_bytes_out=sum(p.size for p in packets if p.direction == 1)
            )
            
            self.collected_traces += 1
            logger.info(f"Successfully collected trace with {len(packets)} packets")
            return trace
            
        except Exception as e:
            logger.error(f"Error collecting trace for {url}: {e}")
            self.failed_collections += 1
            return None
    
    def collect_dataset(self, urls: List[str], instances_per_site: int = 10,
                       visit_duration: int = 30) -> Dict:
        """Collect complete dataset"""
        logger.info(f"Starting dataset collection for {len(urls)} sites")
        
        dataset = {
            'traces': [],
            'metadata': {
                'collection_start': datetime.now().isoformat(),
                'urls': urls,
                'instances_per_site': instances_per_site,
                'visit_duration': visit_duration,
                'methodology': 'Tik-Tok with Arti proxy',
                'environment': 'Docker container'
            }
        }
        
        for site_idx, url in enumerate(urls):
            logger.info(f"Processing site {site_idx + 1}/{len(urls)}: {url}")
            
            for instance in range(instances_per_site):
                # Collect trace
                trace = self.collect_single_trace(url, visit_duration)
                
                if trace:
                    # Extract features
                    directional_timing = self.feature_extractor.extract_directional_timing(trace.packets)
                    burst_features = self.feature_extractor.extract_burst_features(trace.packets)
                    
                    # Store trace data
                    trace_data = {
                        'site_index': site_idx,
                        'instance_index': instance,
                        'trace': asdict(trace),
                        'directional_timing': directional_timing.tolist(),
                        'burst_features': burst_features
                    }
                    
                    dataset['traces'].append(trace_data)
                    
                    # Save intermediate results
                    if len(dataset['traces']) % 5 == 0:
                        self.save_dataset(dataset, f"intermediate_{len(dataset['traces'])}")
                
                # Delay between visits
                time.sleep(10)  # Longer delay since we can't control circuits directly
        
        dataset['metadata']['collection_end'] = datetime.now().isoformat()
        dataset['metadata']['total_traces'] = len(dataset['traces'])
        
        if self.collected_traces + self.failed_collections > 0:
            dataset['metadata']['success_rate'] = self.collected_traces / (self.collected_traces + self.failed_collections)
        
        return dataset
    
    def save_dataset(self, dataset: Dict, filename: str = None):
        """Save dataset to disk"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"arti_wf_dataset_{timestamp}"
        
        filepath = self.output_dir / f"{filename}.json"
        
        with open(filepath, 'w') as f:
            json.dump(dataset, f, indent=2)
        
        logger.info(f"Dataset saved to: {filepath}")

def main():
    """Main execution function for Docker environment"""
    
    # Test websites (educational/research sites)
    test_urls = [
        "https://www.torproject.org",
        "https://duckduckgo.com",
        "https://httpbin.org/html",
    ]
    
    # Initialize collector
    collector = ArtiWebsiteFingerprintCollector("/app/output")
    
    try:
        logger.info("Starting Arti-based data collection")
        
        # Collect dataset
        dataset = collector.collect_dataset(
            urls=test_urls,
            instances_per_site=3,  # Small test dataset
            visit_duration=20
        )
        
        # Save final dataset
        collector.save_dataset(dataset, "final_arti_dataset")
        
        # Print summary
        print("\n" + "="*50)
        print("ARTI DATA COLLECTION SUMMARY")
        print("="*50)
        print(f"Total traces collected: {len(dataset['traces'])}")
        if 'success_rate' in dataset['metadata']:
            print(f"Success rate: {dataset['metadata']['success_rate']:.2%}")
        print(f"Output directory: /app/output")
        
    except Exception as e:
        logger.error(f"Collection failed: {e}")

if __name__ == "__main__":
    main()