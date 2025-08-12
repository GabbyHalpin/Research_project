#!/usr/bin/env python3
"""
Enhanced Shadow Configuration for Website Fingerprinting Research
Incorporates methodology from both Tik-Tok and simulation papers
"""

import yaml
import json
from pathlib import Path
import argparse

class EnhancedShadowConfigurator:
    """Configure Shadow for explainable website fingerprinting research"""
    
    def __init__(self, base_config_path, urls_file):
        self.base_config_path = base_config_path
        self.urls_file = urls_file
        self.urls = self.load_urls()
        
    def load_urls(self):
        """Load URLs and create labeled sets for WF experiments"""
        urls = []
        with open(self.urls_file, 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3:
                    ip = parts[0]
                    port = parts[1] 
                    url = parts[2]
                    urls.append({
                        'ip': ip,
                        'port': port,
                        'url': url,
                        'endpoint': f"{ip}:{port}"
                    })
        return urls
    
    def create_webpage_sets(self):
        """
        Create W_α (sensitive), W_β (benign), and W_∅ (unlabeled) sets
        Following the paper's methodology
        """
        total_urls = len(self.urls)
        
        # Use subset for sensitive pages (W_α) - similar to paper's 98 pages
        sensitive_count = min(98, total_urls // 4)
        sensitive_set = self.urls[:sensitive_count]
        
        # Split remaining into benign (W_β) and unlabeled (W_∅)
        remaining = self.urls[sensitive_count:]
        benign_count = len(remaining) // 2
        benign_set = remaining[:benign_count]
        unlabeled_set = remaining[benign_count:]
        
        return {
            'W_alpha': sensitive_set,    # Monitored/sensitive pages
            'W_beta': benign_set,        # Labeled benign pages  
            'W_empty': unlabeled_set     # Unlabeled pages
        }
    
    def configure_tor_cell_tracing(self, config):
        """
        Configure Tor relays to collect cell traces as described in the paper
        """
        for host_name, host_config in config['hosts'].items():
            if 'tor' in str(host_config.get('processes', [])):
                # Add cell trace collection to Tor processes
                for process in host_config.get('processes', []):
                    if 'tor' in process.get('path', ''):
                        # Enable control interface for cell trace collection
                        if 'args' not in process:
                            process['args'] = ''
                        process['args'] += ' --ControlPort 9051 --CookieAuthentication 0'
                        
                        # Add environment for cell tracing
                        if 'environment' not in process:
                            process['environment'] = {}
                        process['environment']['TOR_CELL_TRACE'] = 'true'
        
        return config
    
    def configure_network_variations(self, base_config, output_dir):
        """
        Create multiple network configurations with different load levels
        Following the paper's methodology for studying network effects
        """
        load_scales = {
            'low': 1.5,
            'base': 2.0, 
            'high': 2.5
        }
        
        network_seeds = [1, 2, 3]  # Different relay compositions
        
        configs = {}
        
        for seed in network_seeds:
            for load_name, load_scale in load_scales.items():
                config_name = f"network_seed_{seed}_load_{load_name}"
                
                # Copy base config
                new_config = yaml.safe_load(yaml.dump(base_config))
                
                # Modify for this variation
                new_config['general']['seed'] = seed
                
                # Adjust load by modifying client activity
                self._adjust_network_load(new_config, load_scale)
                
                # Configure cell tracing
                new_config = self.configure_tor_cell_tracing(new_config)
                
                configs[config_name] = new_config
        
        return configs
    
    def _adjust_network_load(self, config, load_scale):
        """Adjust network load by modifying client behavior"""
        for host_name, host_config in config['hosts'].items():
            if 'markovclient' in host_name:
                # Adjust TGen activity based on load scale
                for process in host_config.get('processes', []):
                    if 'tgen' in process.get('path', ''):
                        # Scale the timing parameters
                        if load_scale < 2.0:
                            # Lower load - longer think times
                            process['args'] = process['args'].replace('300', str(int(300 / load_scale)))
                        elif load_scale > 2.0:
                            # Higher load - shorter think times  
                            process['args'] = process['args'].replace('300', str(int(300 / load_scale)))
    
    def configure_wget2_clients(self, config, webpage_sets):
        """
        Add wget2-based web clients for controlled page fetching
        Alternative to browser-based collection
        """
        
        # Add web client hosts
        base_node_id = 10000
        
        for i, url_info in enumerate(webpage_sets['W_alpha'][:10]):  # Limit for testing
            client_name = f"wf_client_{i}"
            
            config['hosts'][client_name] = {
                'network_node_id': base_node_id + i,
                'bandwidth_down': '10 Mbit',
                'bandwidth_up': '10 Mbit',
                'pcap': {
                    'enabled': True,
                    'directory': f'./pcap/{client_name}/',
                    'capture_size': 65535
                },
                'processes': [
                    {
                        'path': 'tor',
                        'args': '--defaults-torrc torrc-defaults --ControlPort 9051 --SocksPort 9050',
                        'start_time': '60s',
                        'expected_final_state': 'running'
                    },
                    {
                        'path': 'wget2',
                        'args': f'--socks5-hostname=127.0.0.1:9050 --page-requisites --max-threads=5 {url_info["url"]}',
                        'start_time': '120s',
                        'expected_final_state': 'exited'
                    }
                ]
            }
        
        return config
    
    def create_tgen_configs(self, webpage_sets, output_dir):
        """
        Create TGen configuration files for systematic webpage fetching
        """
        output_dir = Path(output_dir)
        tgen_dir = output_dir / 'tgen_configs'
        tgen_dir.mkdir(exist_ok=True, parents=True)
        
        # Create client configuration for fetching sensitive pages
        client_config = self._create_wf_client_tgen_config(webpage_sets['W_alpha'])
        
        with open(tgen_dir / 'wf_client.tgen.xml', 'w') as f:
            f.write(client_config)
        
        # Create server configurations
        for i, url_info in enumerate(webpage_sets['W_alpha']):
            server_config = self._create_server_tgen_config(url_info['port'])
            with open(tgen_dir / f'server_{i}.tgen.xml', 'w') as f:
                f.write(server_config)