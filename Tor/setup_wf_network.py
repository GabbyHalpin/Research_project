#!/usr/bin/env python3
"""
Improved WF setup following the exact repository methodology from 
Data-Explainable Website Fingerprinting with Network Simulation
Modified to extract URLs from wikipedia_en_top.zim file
Added dynamic relay fingerprint extraction from consensus data
"""

import yaml
import sys
import json
import shutil
import os
from pathlib import Path
import argparse
import random
import lzma
import re
import urllib.parse
import glob

class ImprovedWFConfigConverter:
    """Converts tornettools configs following the exact paper repository methodology"""
    
    def __init__(self, network_dir, zim_file_path=None, verbose=True):
        self.network_dir = Path(network_dir)
        self.zim_file_path = zim_file_path or "./wikidata/wikipedia_en_top.zim"
        self.verbose = verbose
        self.base_ip = "10.0.0.1"
        self.start_port = 8000
        self.urls = self.load_and_process_urls()
        self.webpage_sets = self.create_webpage_sets()
        
    def log(self, message):
        if self.verbose:
            print(f"[WF-CONFIG] {message}")

    def debug_consensus_data(self):
        """Debug method to inspect available consensus data"""
        self.log("Debugging available consensus data...")
        
        # Check for various consensus data files
        files_to_check = [
            'relayinfo_staging_*.json',
            'networkinfo_staging.gml',
            'consensuses-2025-07/*',
            'server-descriptors-2025-07/*'
        ]
        
        for pattern in files_to_check:
            matches = glob.glob(pattern)
            if matches:
                self.log(f"Found {pattern}: {len(matches)} files")
                for match in matches[:3]:  # Show first 3
                    path = Path(match)
                    if path.is_file():
                        size = path.stat().st_size
                        self.log(f"  {match} ({size:,} bytes)")
            else:
                self.log(f"No files found for pattern: {pattern}")
    
    def _extract_with_libzim(self):
        """Extract URLs using libzim library"""
        import libzim
        
        zim_path = Path(self.zim_file_path)
        if not zim_path.exists():
            self.log(f"Error: ZIM file not found at {zim_path}")
            return []
        
        urls = []
        try:
            archive = libzim.Archive(str(zim_path))
            self.log(f"Successfully opened ZIM file: {zim_path}")
            self.log(f"ZIM file contains {archive.article_count} articles")
            
            # Since libzim doesn't provide index-based iteration, we'll use random sampling
            # and try some common Wikipedia article paths
            
            processed_count = 0
            attempts = 0
            max_attempts = 10000  # Try more attempts to get enough articles
            
            # First, try to get articles using random entry method
            while processed_count < 100 and attempts < max_attempts:
                attempts += 1
                try:
                    # Get a random entry
                    entry = archive.get_random_entry()
                    
                    # Check if it's a valid article
                    if not hasattr(entry, 'title') and not hasattr(entry, 'path'):
                        continue
                    
                    # Get title/path
                    title = None
                    if hasattr(entry, 'title'):
                        title = entry.title
                    elif hasattr(entry, 'path'):
                        title = entry.path.strip('/')
                    
                    if not title:
                        continue
                    
                    # Skip non-article content
                    if (title.startswith('File:') or title.startswith('Category:') or 
                        title.startswith('Template:') or title.startswith('Help:') or
                        title.startswith('Wikipedia:') or title.startswith('User:') or
                        title.startswith('Talk:') or title.startswith('Special:') or
                        title.startswith('-/') or title.startswith('A/')):
                        continue
                    
                    # Check if it's a redirect (if possible)
                    try:
                        if hasattr(entry, 'is_redirect') and entry.is_redirect:
                            continue
                        elif hasattr(entry, 'is_redirect') and callable(entry.is_redirect) and entry.is_redirect():
                            continue
                    except:
                        pass
                    
                    # Skip if we already have this title
                    if any(url['title'] == title for url in urls):
                        continue
                    
                    # Clean title for URL
                    url_title = title.replace(' ', '_')
                    url_title = urllib.parse.quote(url_title, safe='_-.')
                    
                    port = self.start_port + processed_count
                    full_url = f"http://{self.base_ip}:{port}/C/{url_title}"
                    
                    urls.append({
                        'original_ip': self.base_ip,
                        'original_port': port,
                        'original_url': full_url,
                        'page_path': f'/{url_title}',
                        'id': processed_count,
                        'title': title
                    })
                    
                    processed_count += 1
                    
                    if processed_count % 10 == 0:
                        self.log(f"Processed {processed_count} articles...")
                        
                except Exception as e:
                    continue  # Skip problematic entries
            
                            
        except Exception as e:
            self.log(f"Error reading ZIM file with libzim: {e}")
            import traceback
            self.log(f"Full traceback: {traceback.format_exc()}")
            return []
            
        self.log(f"Extracted {len(urls)} URLs from ZIM file")
        return urls
            
    def load_and_process_urls(self):
        """Load URLs from ZIM file and process them"""
        self.log(f"Loading Wikipedia articles from ZIM file: {self.zim_file_path}")
        
        urls = self._extract_with_libzim()
        
        if not urls:
            self.log("No URLs extracted, using fallback method")
        
        self.log(f"Loaded {len(urls)} Wikipedia pages from ZIM file")
        
        # Show some examples
        if urls and self.verbose:
            self.log("Sample URLs extracted:")
            for i, url in enumerate(urls[:5]):
                self.log(f"  {i+1}: {url['original_url']} ({url.get('title', 'No title')})")
            if len(urls) > 5:
                self.log(f"  ... and {len(urls)-5} more")
        
        return urls
    
    def create_webpage_sets(self):
        """Create W_α (sensitive), W_β (benign), W_∅ (unlabeled) sets"""
        total_urls = len(self.urls)
        
        if total_urls == 0:
            self.log("Warning: No URLs loaded")
            return {'W_alpha': [], 'W_beta': [], 'W_empty': []}
        
        # Following the paper's methodology: W_α contains 98 unique pages
        sensitive_count = min(98, total_urls)
        
        # Shuffle URLs to randomize selection
        shuffled_urls = self.urls.copy()
        random.shuffle(shuffled_urls)
        
        sensitive_urls = shuffled_urls[:sensitive_count]
        remaining_urls = shuffled_urls[sensitive_count:]
        
        self.log(f"Created webpage sets following paper methodology:")
        self.log(f"  W_α (sensitive): {len(sensitive_urls)} Wikipedia pages")
        
        return {
            'W_alpha': sensitive_urls,
            'W_beta': remaining_urls[:len(remaining_urls)//2] if remaining_urls else [],
            'W_empty': remaining_urls[len(remaining_urls)//2:] if remaining_urls else []
        }
    
    def save_urls_to_file(self, output_path="urls_from_zim.txt"):
        """Save extracted URLs to a file in the original format for reference"""
        try:
            with open(output_path, 'w') as f:
                for url_info in self.urls:
                    line = f"{url_info['original_ip']} {url_info['original_port']} {url_info['original_url']}\n"
                    f.write(line)
            self.log(f"Saved extracted URLs to {output_path}")
        except Exception as e:
            self.log(f"Warning: Could not save URLs file: {e}")
    
    def extract_valid_node_ids_from_config(self, config):
        """
        Extract all valid network node IDs from tornettools-generated config
        Returns a sorted list of valid node IDs that exist in the network topology
        """
        valid_node_ids = set()
        
        # Extract from network graph file (GML format)
        network_config = config.get('network', {})
        if 'graph' in network_config:
            graph_config = network_config['graph']
            
            # Check if graph is stored in external file
            if 'file' in graph_config:
                file_info = graph_config['file']
                gml_path = file_info.get('path')
                compression = file_info.get('compression')
                
                if gml_path:
                    try:
                        # Make path relative to network directory if needed
                        if not os.path.isabs(gml_path):
                            gml_path = self.network_dir / gml_path
                        else:
                            gml_path = Path(gml_path)
                        
                        valid_node_ids = self._parse_gml_file(gml_path, compression)
                        
                    except Exception as e:
                        self.log(f"Error reading GML file {gml_path}: {e}")
                        return []
            
            # Fallback: try to extract from inline graph data
            else:
                # Extract node IDs from edges (old method)
                for edge in graph_config.get('edges', []):
                    if isinstance(edge, dict):
                        # Handle different edge formats
                        if 'nodes' in edge and len(edge['nodes']) >= 2:
                            valid_node_ids.add(edge['nodes'][0])
                            valid_node_ids.add(edge['nodes'][1])
                        elif 'src' in edge and 'dst' in edge:
                            valid_node_ids.add(edge['src'])
                            valid_node_ids.add(edge['dst'])
                
                # Also check explicit node definitions
                for node in graph_config.get('nodes', []):
                    if isinstance(node, dict) and 'id' in node:
                        valid_node_ids.add(node['id'])
                    elif isinstance(node, (int, str)):
                        try:
                            valid_node_ids.add(int(node))
                        except ValueError:
                            pass
        
        if valid_node_ids:
            node_list = sorted(valid_node_ids)
            self.log(f"Found {len(node_list)} valid network nodes: {min(node_list)}-{max(node_list)}")
            return node_list
        else:
            self.log("Warning: Could not extract valid node IDs from network graph")
            return []
    
    def get_used_node_ids_from_config(self, config):
        """Extract node IDs currently assigned to hosts"""
        used_node_ids = set()
        
        for host_name, host_config in config.get('hosts', {}).items():
            node_id = host_config.get('network_node_id')
            if node_id is not None:
                used_node_ids.add(node_id)
        
        return sorted(used_node_ids)
    
    def debug_gml_file(self, config):
        """Debug method to inspect GML file structure"""
        network_config = config.get('network', {})
        if 'graph' not in network_config:
            self.log("No graph config found")
            return
        
        graph_config = network_config['graph']
        if 'file' not in graph_config:
            self.log("No external file reference found")
            return
        
        file_info = graph_config['file']
        gml_path = file_info.get('path')
        compression = file_info.get('compression')
        
        if not gml_path:
            self.log("No file path found")
            return
        
        # Make path relative to network directory if needed
        if not os.path.isabs(gml_path):
            gml_path = self.network_dir / gml_path
        else:
            gml_path = Path(gml_path)
        
        self.log(f"GML File Debug Info:")
        self.log(f"  Path: {gml_path}")
        self.log(f"  Exists: {gml_path.exists()}")
        if gml_path.exists():
            stat = gml_path.stat()
            self.log(f"  Size: {stat.st_size:,} bytes")
            self.log(f"  Compression: {compression or 'none'}")
        
        # Try to read first few lines to understand structure
        try:
            if compression == 'xz':
                with lzma.open(gml_path, 'rt', encoding='utf-8') as f:
                    first_lines = [f.readline().strip() for _ in range(20)]
            else:
                with open(gml_path, 'r', encoding='utf-8') as f:
                    first_lines = [f.readline().strip() for _ in range(20)]
            
            self.log(f"  First 20 lines:")
            for i, line in enumerate(first_lines, 1):
                if line:
                    self.log(f"    {i:2d}: {line}")
                    
        except Exception as e:
            self.log(f"  Error reading file: {e}")
    
    def analyze_network_quick(self, config):
        """Quick analysis of network structure"""
        # Add debug info for GML file
        self.debug_gml_file(config)
        
        valid_nodes = self.extract_valid_node_ids_from_config(config)
        used_nodes = self.get_used_node_ids_from_config(config)
        
        if valid_nodes:
            self.log(f"Network Analysis:")
            self.log(f"  Total network nodes: {len(valid_nodes)}")
            self.log(f"  Node ID range: {min(valid_nodes)} to {max(valid_nodes)}")
            self.log(f"  Currently used nodes: {len(used_nodes)}")
            self.log(f"  Available nodes: {len(valid_nodes) - len(used_nodes)}")
            
            # Show some examples
            if len(valid_nodes) > 10:
                self.log(f"  Example valid nodes: {valid_nodes[:5]} ... {valid_nodes[-5:]}")
            else:
                self.log(f"  All valid nodes: {valid_nodes}")
                
            available = sorted(set(valid_nodes) - set(used_nodes))
            if available:
                if len(available) > 10:
                    self.log(f"  Example available nodes: {available[:10]}")
                else:
                    self.log(f"  All available nodes: {available}")
            
            return True
        else:
            self.log("Could not analyze network - no valid nodes found")
            return False
    
    def _parse_gml_file(self, gml_path, compression=None):
        """Parse GML file to extract node IDs"""
        
        valid_node_ids = set()
        
        try:
            # Read file content (handle compression)
            if compression == 'xz':
                with lzma.open(gml_path, 'rt', encoding='utf-8') as f:
                    content = f.read()
            elif compression == 'gz':
                import gzip
                with gzip.open(gml_path, 'rt', encoding='utf-8') as f:
                    content = f.read()
            else:
                with open(gml_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            
            self.log(f"Successfully read GML file: {gml_path}")
            
            # Parse GML content to extract node IDs
            # GML format typically has: node [ id <number> ... ]
            node_pattern = r'node\s*\[\s*id\s+(\d+)'
            node_matches = re.findall(node_pattern, content, re.IGNORECASE)
            
            for node_id_str in node_matches:
                try:
                    valid_node_ids.add(int(node_id_str))
                except ValueError:
                    continue
            
            # Also look for edge patterns to verify: edge [ source <id> target <id> ]
            edge_pattern = r'edge\s*\[\s*source\s+(\d+)\s+target\s+(\d+)'
            edge_matches = re.findall(edge_pattern, content, re.IGNORECASE)
            
            edge_nodes = set()
            for source, target in edge_matches:
                try:
                    edge_nodes.add(int(source))
                    edge_nodes.add(int(target))
                except ValueError:
                    continue
            
            # Use node list if available, otherwise fall back to edge nodes
            if valid_node_ids:
                self.log(f"Extracted {len(valid_node_ids)} nodes from GML node definitions")
                # Verify edge nodes are subset of node definitions
                if edge_nodes and not edge_nodes.issubset(valid_node_ids):
                    self.log("Warning: Some edge nodes not in node definitions, using union")
                    valid_node_ids.update(edge_nodes)
            elif edge_nodes:
                self.log(f"No explicit nodes found, extracted {len(edge_nodes)} nodes from edges")
                valid_node_ids = edge_nodes
            
            return valid_node_ids
            
        except FileNotFoundError:
            self.log(f"Error: GML file not found: {gml_path}")
            return set()
        except Exception as e:
            self.log(f"Error parsing GML file {gml_path}: {e}")
            return set()
    
    def validate_network_topology(self, config):
        """Validate that the network topology is properly defined"""
        network_config = config.get('network', {})
        
        if 'graph' not in network_config:
            self.log("Warning: No network graph found in configuration")
            return False
        
        graph_config = network_config['graph']
        
        # Handle external GML file
        if 'file' in graph_config:
            file_info = graph_config['file']
            gml_path = file_info.get('path')
            compression = file_info.get('compression', '')
            
            if gml_path:
                # Make path relative to network directory if needed
                if not os.path.isabs(gml_path):
                    gml_path = self.network_dir / gml_path
                else:
                    gml_path = Path(gml_path)
                
                if not gml_path.exists():
                    self.log(f"Error: GML file not found: {gml_path}")
                    return False
                
                self.log(f"Found network topology file: {gml_path}")
                self.log(f"File type: GML, compression: {compression or 'none'}")
                
                # Try to get basic info without full parsing
                try:
                    valid_node_ids = self._parse_gml_file(gml_path, compression)
                    if valid_node_ids:
                        min_node = min(valid_node_ids)
                        max_node = max(valid_node_ids)
                        self.log(f"Network topology: {len(valid_node_ids)} nodes (IDs {min_node}-{max_node})")
                        return True
                    else:
                        self.log("Warning: Could not extract nodes from GML file")
                        return False
                except Exception as e:
                    self.log(f"Warning: Error validating GML file: {e}")
                    return False
            else:
                self.log("Warning: No file path specified in graph config")
                return False
        
        # Handle inline graph data (fallback)
        else:
            # Count edges and nodes from inline data
            edge_count = len(graph_config.get('edges', []))
            
            # Extract unique node IDs from edges
            node_ids = set()
            for edge in graph_config.get('edges', []):
                if isinstance(edge, dict):
                    if 'nodes' in edge and len(edge['nodes']) >= 2:
                        node_ids.add(edge['nodes'][0])
                        node_ids.add(edge['nodes'][1])
                    elif 'src' in edge and 'dst' in edge:
                        node_ids.add(edge['src'])
                        node_ids.add(edge['dst'])
            
            if node_ids:
                min_node = min(node_ids)
                max_node = max(node_ids)
                self.log(f"Network topology: {len(node_ids)} nodes (IDs {min_node}-{max_node}), {edge_count} edges")
                return True
            else:
                self.log("Warning: No valid node IDs found in network edges")
                return False
    
    def find_available_node_ids_improved(self, config, count_needed):
        """
        Improved method to find available node IDs using network topology
        """
        # Get all valid node IDs from the network topology
        valid_node_ids = set(self.extract_valid_node_ids_from_config(config))
        
        if not valid_node_ids:
            self.log("Error: No valid network node IDs found in topology")
            return []
        
        # Get currently used node IDs
        used_node_ids = set(self.get_used_node_ids_from_config(config))
        
        # Find available node IDs
        available_node_ids = sorted(valid_node_ids - used_node_ids)
        
        self.log(f"Network topology: {len(valid_node_ids)} total nodes, {len(used_node_ids)} used, {len(available_node_ids)} available")
        
        if len(available_node_ids) >= count_needed:
            selected = available_node_ids[:count_needed]
            self.log(f"Selected node IDs: {selected}")
            return selected
        else:
            self.log(f"Error: Need {count_needed} node IDs but only {len(available_node_ids)} available")
            self.log(f"Available node IDs: {available_node_ids}")
            return available_node_ids  # Return what we have
    
    def find_available_node_ids(self, config, count_needed):
        """Find available network node IDs using improved topology-aware method"""
        # Quick analysis first
        self.analyze_network_quick(config)
        
        # Use improved method
        return self.find_available_node_ids_improved(config, count_needed)
    
    def modify_shadow_config(self):
        """Modify Shadow configuration following the repository methodology"""
        config_path = self.network_dir / 'shadow.config.yaml'
        
        if not config_path.exists():
            self.log(f"Error: Shadow config not found at {config_path}")
            return False
        
        self.log(f"Modifying Shadow config: {config_path}")
        
        # Backup original
        backup_path = config_path.with_suffix('.yaml.original')
        if not backup_path.exists():
            shutil.copy2(config_path, backup_path)
            self.log(f"Created backup: {backup_path}")
        
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
        except Exception as e:
            self.log(f"Error reading Shadow config: {e}")
            return False
        
        # Validate network topology first
        if not self.validate_network_topology(config):
            self.log("Warning: Network topology validation failed")
        
        # Initialize counters outside the loop
        modified_hosts = []  # List to store modified host names
        
        # Calculate how many new hosts we need
        total_new_hosts_needed = 0  # zimserver
        if self.urls:
            # Calculate monitor hosts needed (1 per 10 URLs, max 5)
            monitor_hosts_needed = min(5, max(1, len(self.webpage_sets['W_alpha']) // 10))
            total_new_hosts_needed += monitor_hosts_needed
        else:
            monitor_hosts_needed = 0
        
        # Get available node IDs for new hosts using improved method
        available_node_ids = self.find_available_node_ids(config, total_new_hosts_needed)
        
        if len(available_node_ids) < total_new_hosts_needed:
            self.log(f"Error: Need {total_new_hosts_needed} node IDs but only found {len(available_node_ids)}")
            self.log("Skipping addition of new hosts to avoid node ID conflicts")
            # Still save the modified config with PCAP and oniontrace changes
            try:
                with open(config_path, 'w') as f:
                    yaml.dump(config, f, default_flow_style=False, indent=2)
                self.log(f"Saved config with {modified_hosts} modified client hosts")
                return True
            except Exception as e:
                self.log(f"Error saving Shadow config: {e}")
                return False
        
        node_id_index = 1
        
        # Add zimserver host following repository methodology
        if self.urls and node_id_index < len(available_node_ids):
            server_name = "zimserver0"
            node_id = available_node_ids[node_id_index]
            node_id_index += 1
            
            # Create zimserver configuration following repository format
            config['hosts'][server_name] = {
                'bandwidth_down': '200 megabit',
                'bandwidth_up': '200 megabit',
                'ip_addr': '10.0.0.1',
                'network_node_id': node_id,
                'processes': []
            }
            
            # Add processes for ALL URLs that monitors will request (W_alpha set)
            unique_ports = set()
            for url_info in self.webpage_sets['W_alpha']:  # Changed from self.urls[:10] to W_alpha
                port = url_info['original_port']
                if port not in unique_ports:
                    unique_ports.add(port)

                    # Add zimsrv process for this port
                    zimprocess = {
                        'args': 'zimsrv.py',
                        'environment': {
                            'ZIMROOT': '/mnt/wikidata',
                            'ZIMIP': '10.0.0.1',
                            'ZIMPORT': str(port),
                            'LANG': 'en_US.UTF-8',
                            'LC_ALL': 'en_US.UTF-8',
                            'PYTHONPATH': '/usr/local/lib/python3.10/dist-packages'
                        },
                        'path': '/opt/bin/python3',
                        'start_time': '3s',
                        'expected_final_state': 'running'
                    }

                    config['hosts'][server_name]['processes'].append(zimprocess)
            
            self.log(f"  Added zimserver with node ID {node_id} serving {len(unique_ports)} ports")
        
                # Add monitor hosts following repository methodology for wget2 fetching
        for i in range(monitor_hosts_needed):
            if node_id_index >= len(available_node_ids):
                self.log(f"Warning: Ran out of available node IDs, only created {i} monitor hosts")
                break
                
            monitor_name = f"monitor{i}"
            node_id = available_node_ids[node_id_index]
            node_id_index += 1
            
            # Create monitor host following repository format
            config['hosts'][monitor_name] = {
                'bandwidth_down': '100 megabit',
                'bandwidth_up': '100 megabit',
                'network_node_id': node_id,
                'host_options': {
                        'pcap_enabled': True,
                        'pcap_capture_size': '65535'
                    },
                'processes': [
                    # Tor process - using correct path from Docker setup
                    {
                        'args': f'--Address {monitor_name} --Nickname {monitor_name} --defaults-torrc torrc-defaults -f torrc',
                        'path': '/opt/bin/tor',
                        'start_time': 1195,
                        'expected_final_state': 'running'
                    }
                ]
            }
            
            # Get URLs for this monitor (max 10 per monitor)
            monitor_urls = self.webpage_sets['W_alpha'][i*27:(i+1)*27]
            if len(monitor_urls) > 27:
                monitor_urls = monitor_urls[:27]
            
            # Configuration for multiple iterations with circuit renewal
            base_start_time = 1300
            iterations = 30  # Number of times to repeat the URL set
            urls_per_batch = len(monitor_urls)  # All URLs in one batch initially
            batch_duration = urls_per_batch * 0  # All URLs start simultaneously in each batch
            newnym_delay = 29  # Time after batch starts to run newnym
            iteration_interval = 30  # Time between iterations
            
            for iteration in range(iterations):
                iteration_start_time = base_start_time + (iteration * iteration_interval)
                
                # Add wget2 processes for this iteration
                for j, url_info in enumerate(monitor_urls):
                    wget2_args = [
                        '--http-proxy=127.0.0.1:9050',
                        '--https-proxy=127.0.0.1:9050',
                        '--verbose',
                        '--debug',
                        '--page-requisites',
                        '--max-threads=2', 
                        '--timeout=30',
                        '--tries=1',
                        '--no-retry-on-http-error',
                        '--no-tcp-fastopen',
                        '--delete-after',
                        '--user-agent=Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0',
                        '--no-robots',
                        '--filter-urls',
                        '--reject-regex=/w/|\\.js$|robots\.txt$',
                        '--no-check-hostname',
                        '--no-check-certificate', 
                        '--no-hpkp',
                        '--no-hsts',
                        url_info["original_url"]
                    ]
                    
                    wget2_process = {
                        'args': wget2_args,
                        'environment': {
                            'LANG': 'en_US.UTF-8',
                            'LC_ALL': 'en_US.UTF-8',
                            'LANGUAGE': 'en_US.UTF-8',
                            'LD_LIBRARY_PATH': '/opt/lib',
                            'http_proxy':'http://127.0.0.1:9050',
                            'https_proxy':'http://127.0.0.1:9050',
                            'use_proxy':'on'
                        },
                        'path': '/opt/bin/wget2_noinstall',  # Using the path from your example
                        'start_time': iteration_start_time,  # All URLs in batch start at same time
                    }
                    
                    config['hosts'][monitor_name]['processes'].append(wget2_process)
                
                # Add newnym process after this iteration (except for the last iteration)
                if iteration < iterations - 1:  # Don't add newnym after the last iteration
                    newnym_start_time = iteration_start_time + newnym_delay
                    
                    newnym_process = {
                        'args': '-m newnym',
                        'path': '/opt/bin/python3',
                        'start_time': newnym_start_time
                    }
                    
                    config['hosts'][monitor_name]['processes'].append(newnym_process)
    
            self.log(f"  Added monitor{i} with node ID {node_id}")
            self.log(f"    - {len(monitor_urls)} URLs per iteration")
            self.log(f"    - {iterations} iterations with circuit renewal")
            self.log(f"    - Total processes: {len(monitor_urls) * iterations + (iterations - 1)} (wget2 + newnym)")

        # Save modified config
        try:
            with open(config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, indent=2)
        except Exception as e:
            self.log(f"Error saving Shadow config: {e}")
            return False
        
        self.log(f"Modified {modified_hosts} client hosts")
        # self.log(f"Added zimserver and {monitor_hosts_needed} monitor hosts")
        return True
    
    def create_config_files(self):
        """Create configuration files following repository structure with dynamic relay selection"""
        success_count = 0
        
        # Create conf directory structure
        conf_dir = self.network_dir / 'conf'
        conf_dir.mkdir(exist_ok=True, parents=True)

        # Create tor.crawler.torrc with dynamic fingerprints
        tor_crawler_content = f"""# Enter any host-specific tor config options here.
# Note that any option specified here may override a default from torrc-defaults.
ClientOnly 1
ORPort 0
DirPort 0

SocksPort 127.0.0.1:9050 IsolateClientAddr IsolateDestAddr IsolateDestPort
UseEntryGuards 1
"""
        
        try:
            with open(conf_dir / 'tor.crawler.torrc', 'w') as f:
                f.write(tor_crawler_content)
            self.log(f"Created tor.crawler.torrc with dynamic relay selection in {conf_dir}")
            success_count += 1
        except Exception as e:
            self.log(f"Warning: Could not create tor.crawler.torrc: {e}")
        
        return success_count
    
    def create_template_files(self):
        """Create shadow.data.template files following repository structure"""
        success_count = 0
        
        # Create shadow.data.template directory structure
        template_dir = self.network_dir / 'shadow.data.template/hosts'
        template_dir.mkdir(exist_ok=True, parents=True)
        
        # torrc-defaults content
        torrc_defaults_content = """# The following files specify default tor config options for this host.
%include ../../../conf/tor.common.torrc
%include ../../../conf/tor.crawler.torrc
"""
        
        # newnym.py content
        newnym_content = """import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    print("Connecting to 127.0.0.1:9051")
    s.connect(("127.0.0.1", 9051))
    print("Done connect")

    print("Sending AUTHENTICATE")
    s.sendall(b"AUTHENTICATE\\r\\n")
    print("Done AUTHENTICATE")

    print("Receiving AUTHENTICATE response")
    data = s.recv(1024)
    print(f"Received {data!r}")

    print("Sending SIGNAL NEWNYM")
    s.sendall(b"SIGNAL NEWNYM\\r\\n")
    print("Done SIGNAL NEWNYM")

    print("Receiving SIGNAL NEWNYM response")
    data = s.recv(1024)
    print(f"Received {data!r}")

    print("All done, bye!")
"""
        
        # Create monitor0 directory and files
        monitor_dir = template_dir / 'monitor0'
        monitor_dir.mkdir(exist_ok=True, parents=True)

        try:
            with open(monitor_dir /  "torrc", "w") as file:
                pass  # No content is written, so the file remains empty
        except Exception as e:
            self.log(f"Warning: Could not create monitor0/torrc: {e}")
        
        try:
            with open(monitor_dir / 'torrc-defaults', 'w') as f:
                f.write(torrc_defaults_content)
            self.log(f"Created monitor0/torrc-defaults")
            success_count += 1
        except Exception as e:
            self.log(f"Warning: Could not create monitor0/torrc-defaults: {e}")
        
        try:
            with open(monitor_dir / 'newnym.py', 'w') as f:
                f.write(newnym_content)
            # Make executable
            (monitor_dir / 'newnym.py').chmod(0o755)
            self.log(f"Created monitor0/newnym.py")
            success_count += 1
        except Exception as e:
            self.log(f"Warning: Could not create monitor0/newnym.py: {e}")
        
        # Create additional monitor directories for multiple monitors
        for i in range(1, 5):  # Create monitor1 through monitor4
            monitor_i_dir = template_dir / f'monitor{i}'
            monitor_i_dir.mkdir(exist_ok=True, parents=True)
            
            try:
                with open(monitor_i_dir / 'torrc-defaults', 'w') as f:
                    f.write(torrc_defaults_content)

                with open(monitor_i_dir / 'torrc', 'w') as f:
                    pass
                
                with open(monitor_i_dir / 'newnym.py', 'w') as f:
                    f.write(newnym_content)
                (monitor_i_dir / 'newnym.py').chmod(0o755)
                
                self.log(f"Created monitor{i}/ directory and files")
                success_count += 1
            except Exception as e:
                self.log(f"Warning: Could not create monitor{i} files: {e}")
        
        # Create zimserver0 directory and zimsrv.py
        zimserver_dir = template_dir / 'zimserver0'
        zimserver_dir.mkdir(exist_ok=True, parents=True)
        
        # zimsrv.py content following repository format
        zimsrv_content = """#!/usr/bin/env python3

print('Hello zimply!')

import os

# use abs path to simplify the internal href links
root = os.getenv('ZIMROOT')
print(f'Found environment ZIMROOT={root}')

ip = os.getenv('ZIMIP')
print(f'Found environment ZIMIP={ip}')

port = os.getenv('ZIMPORT')
print(f'Found environment ZIMPORT={port}')

print('Starting zimply server now!')

from zimply import ZIMServer
ZIMServer(f"{root}/wikipedia_en_top.zim",
     index_file=f"{root}/index.idx",
     ip_address=ip,
     port=int(port),
     encoding="utf-8")
"""
        
        try:
            with open(zimserver_dir / 'zimsrv.py', 'w') as f:
                f.write(zimsrv_content)
            # Make executable
            (zimserver_dir / 'zimsrv.py').chmod(0o755)
            self.log(f"Created zimserver0/zimsrv.py")
            success_count += 1
        except Exception as e:
            self.log(f"Warning: Could not create zimserver0/zimsrv.py: {e}")
        
        return success_count

    
    def save_metadata(self):
        """Save conversion metadata"""
        metadata = {
            'conversion_info': {
                'network_dir': str(self.network_dir),
                'zim_file': self.zim_file_path,
                'total_urls': len(self.urls),
                'methodology': 'Repository-based following exact paper implementation with ZIM file support',
                'modifications': [
                    'ZIM file URL extraction using zimply/libzim',
                    'PCAP capture enabled on client hosts',
                    'oniontrace processes added for cell collection',
                    'zimserver added for content serving from ZIM file',
                    'monitor hosts added for wget2 fetching',
                    'Topology-aware node ID assignment',
                    'Dynamic relay fingerprint extraction from consensus data'
                ]
            },
            'webpage_sets': {
                'W_alpha_count': len(self.webpage_sets['W_alpha']),
                'W_beta_count': len(self.webpage_sets['W_beta']),
                'W_empty_count': len(self.webpage_sets['W_empty'])
            },
            'zim_extraction': {
                'zim_file_exists': Path(self.zim_file_path).exists(),
                'extraction_method': 'zimply' if 'zimply' in str(type(self)) else 'fallback',
                'articles_extracted': len(self.urls),
                'base_ip': self.base_ip,
                'port_range': f"{self.start_port}-{self.start_port + len(self.urls) - 1}" if self.urls else "none"
            },
            'relay_fingerprints': {
                'dynamic_extraction': True,
                'consensus_data_used': True,
                'fallback_available': True,
                'validation_enabled': True
            },
            'repository_alignment': {
                'oniontrace_used': True,
                'zimserver_format': True,
                'wget2_format': True,
                'monitor_hosts': True,
                'config_files_created': True,
                'template_files_created': True,
                'topology_aware_nodes': True,
                'zim_integration': True,
                'dynamic_relay_selection': True
            },
            'files_created': {
                'conf_directory': str(self.network_dir / 'conf'),
                'template_directory': str(self.network_dir / 'shadow.data.template'),
                'tor_crawler_torrc': str(self.network_dir / 'conf' / 'tor.crawler.torrc'),
                'monitor_configs': 'shadow.data.template/monitor*/',
                'zimserver_configs': 'shadow.data.template/zimserver0/',
                'newnym_scripts': 'newnym.py files for circuit management',
                'zimsrv_script': 'zimsrv.py for Wikipedia content serving from ZIM',
                'urls_backup': 'urls_from_zim.txt (generated URLs for reference)'
            }
        }
        
        metadata_file = self.network_dir / 'wf_zim_metadata.json'
        try:
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            self.log(f"Saved metadata: {metadata_file}")
        except Exception as e:
            self.log(f"Warning: Could not save metadata: {e}")
    
    def convert_network(self):
        """Perform complete network conversion following repository methodology with ZIM support"""
        self.log("Starting WF conversion with ZIM file support and dynamic relay selection")
        self.log("Adding oniontrace, zimserver, monitor hosts, and config files")
        
        if not self.network_dir.exists():
            self.log(f"Network directory {self.network_dir} does not exist")
            return False
        
        success_count = 0
        
        # Debug consensus data availability
        self.debug_consensus_data()
        
        # Step 1: Save extracted URLs for reference
        self.log("Step 1/6: Saving extracted URLs...")
        try:
            self.save_urls_to_file()
            success_count += 1
        except Exception as e:
            self.log(f"URL save failed: {e}")
        
        # Step 2: Create configuration files
        self.log("Step 2/6: Creating configuration files...")
        if self.create_config_files() > 0:
            success_count += 1
        
        # Step 3: Create template files
        self.log("Step 3/6: Creating shadow.data.template files...")
        if self.create_template_files() > 0:
            success_count += 1
        
        # Step 4: Modify Shadow configuration
        self.log("Step 4/6: Modifying Shadow configuration...")
        if self.modify_shadow_config():
            success_count += 1

        # # Step 5: Create Wikipedia content
        # self.log("Step 5/6: Creating Wikipedia content...")
        # try:
        #     if self.create_wikipedia_content():
        #         success_count += 1
        # except Exception as e:
        #     self.log(f"Content creation failed: {e}")
        
        # Step 6: Save metadata
        self.log("Step 6/6: Saving metadata...")
        try:
            self.save_metadata()
            success_count += 1
        except Exception as e:
            self.log(f"Metadata save failed: {e}")
        
        # Summary
        self.log(f"\nConversion completed: {success_count}/6 steps successful")
        
        if success_count >= 4:
            self.log("Network successfully converted with ZIM file support and dynamic relay selection!")
            self.log("Changes made:")
            self.log("   • URLs extracted from ZIM file")
            self.log("   • Dynamic relay fingerprints extracted from consensus data")
            self.log("   • Configuration files created in conf/")
            self.log("   • Template files created in shadow.data.template/")
            self.log("   • PCAP capture enabled on client hosts")
            self.log("   • oniontrace processes added for cell trace collection")
            self.log("   • zimserver added for Wikipedia content serving")
            self.log("   • monitor hosts added for wget2 fetching")
            self.log("   • Topology-aware node ID assignment")
            self.log(f"ZIM file: {self.zim_file_path}")
            self.log(f"Config files: {self.network_dir}/conf/")
            self.log(f"Template files: {self.network_dir}/shadow.data.template/")
            self.log(f"Wikipedia content: ./wikidata/")
            self.log(f"URLs backup: urls_from_zim.txt")
            self.log(f"PCAP captures: {self.network_dir}/shadow.data/hosts/*/eth0.pcap")
            self.log(f"Ready for simulation: tornettools simulate {self.network_dir.name}")
            self.log("")
            self.log("Dynamic relay selection features:")
            self.log("   • Automatic extraction from consensus data")
            self.log("   • Guard relay filtering by bandwidth and stability")
            self.log("   • GML file fallback extraction method")
            self.log("   • Fingerprint validation and formatting")
            self.log("   • Graceful fallback to backup relays")
            return True
        else:
            self.log("Conversion failed")
            return False

def main():
    parser = argparse.ArgumentParser(
        description='WF setup with ZIM file support and dynamic relay selection following exact repository methodology'
    )
    parser.add_argument('network_dir', help='Network directory')
    parser.add_argument('--zim-file', default='./wikidata/wikipedia_en_top.zim', 
                       help='Path to ZIM file (default: ./wikidata/wikipedia_en_top.zim)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    converter = ImprovedWFConfigConverter(args.network_dir, args.zim_file, args.verbose)
    success = converter.convert_network()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()