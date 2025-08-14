#!/usr/bin/env python3
"""
Network configuration generator for Website Fingerprinting research
Based on "Data-Explainable Website Fingerprinting with Network Simulation"

This script generates Shadow network configurations at 5% scale with web infrastructure
for collecting website fingerprinting datasets.
"""

import os
import sys
import json
import yaml
import subprocess
from pathlib import Path
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class WFNetworkGenerator:
    def __init__(self, network_scale=0.05, base_load=0.4):
        self.network_scale = network_scale
        self.base_load = base_load
        self.network_seeds = [1, 2, 3]
        self.load_variations = [0.3, 0.4, 0.5]  # low, base, high (scaled for 5%)
        
        # Scaled infrastructure for 5% network (down from 25% in paper)
        # Paper had: 69 servers, 40+136 clients at 25% scale
        # 5% scale: roughly 1/5 of infrastructure
        self.num_web_servers = 14    # down from 69
        self.num_sensitive_clients = 8   # down from 40  
        self.num_benign_clients = 27     # down from 136
        
    def check_prerequisites(self):
        """Check if all required files and tools are available"""
        logger.info("Checking prerequisites...")
        
        required_files = [
            "relayinfo_staging_2025-01-01--2025-01-31.json",
            "userinfo_staging_2025-01-01--2025-01-31.json", 
            "networkinfo_staging.gml",
            "tmodel-ccs2018.github.io"
        ]
        
        missing_files = []
        for file_path in required_files:
            if not os.path.exists(file_path):
                missing_files.append(file_path)
                
        if missing_files:
            logger.error(f"Missing required files: {missing_files}")
            logger.info("Make sure you have run 'tornettools stage' successfully first")
            return False
            
        # Check if tornettools is available
        try:
            result = subprocess.run(["tornettools", "--version"], capture_output=True, text=True)
            if result.returncode != 0:
                logger.error("tornettools command not found or not working")
                return False
            logger.info(f"tornettools version check passed")
        except FileNotFoundError:
            logger.error("tornettools not found in PATH")
            return False
            
        # Check current directory permissions
        if not os.access(".", os.W_OK):
            logger.error("Current directory is not writable")
            return False
            
        logger.info("All prerequisites check passed")
        return True
        
    def run_command_safely(self, cmd, description="Command"):
        """Run a command with proper error handling and logging"""
        logger.info(f"Running: {description}")
        logger.debug(f"Command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                logger.info(f"{description} completed successfully")
                if result.stdout.strip():
                    logger.debug(f"stdout: {result.stdout}")
                return True, result.stdout
            else:
                logger.error(f"{description} failed with return code {result.returncode}")
                logger.error(f"stderr: {result.stderr}")
                if result.stdout.strip():
                    logger.error(f"stdout: {result.stdout}")
                return False, result.stderr
                
        except subprocess.TimeoutExpired:
            logger.error(f"{description} timed out after 5 minutes")
            return False, "Command timed out"
        except FileNotFoundError as e:
            logger.error(f"{description} failed: Command not found - {e}")
            return False, f"Command not found: {e}"
        except Exception as e:
            logger.error(f"{description} failed with unexpected error: {e}")
            return False, f"Unexpected error: {e}"
    
    def generate_base_networks(self):
        """Generate base tornettools network configurations"""
        logger.info("Generating base network configurations...")
        
        # Check if output directory already exists
        output_dir = "tornet-0.05-base"
        if os.path.exists(output_dir):
            logger.warning(f"Output directory {output_dir} already exists - removing it")
            try:
                import shutil
                shutil.rmtree(output_dir)
            except Exception as e:
                logger.error(f"Failed to remove existing directory: {e}")
                return None
        
        # Build the command
        base_cmd = [
            "tornettools", "generate",
            "relayinfo_staging_2025-01-01--2025-01-31.json",
            "userinfo_staging_2025-01-01--2025-01-31.json", 
            "networkinfo_staging.gml",
            "tmodel-ccs2018.github.io",
            f"--network_scale={self.network_scale}",
            f"--load_scale={self.base_load}",
            f"--prefix={output_dir}"
        ]
        
        success, output = self.run_command_safely(base_cmd, "Base network generation")
        
        if not success:
            logger.error("Failed to generate base network configuration")
            logger.info("Troubleshooting tips:")
            logger.info("1. Check that tornettools stage completed successfully")
            logger.info("2. Verify all staging files exist and are readable")
            logger.info("3. Check available disk space")
            logger.info("4. Try running tornettools generate manually with debug output")
            return None
            
        # Verify the output directory was created
        if not os.path.exists(output_dir):
            logger.error(f"Output directory {output_dir} was not created")
            return None
            
        # Check for expected files in output directory
        expected_files = ["shadow.config.yaml"]
        missing_output_files = []
        for file_name in expected_files:
            file_path = os.path.join(output_dir, file_name)
            if not os.path.exists(file_path):
                missing_output_files.append(file_path)
                
        if missing_output_files:
            logger.warning(f"Some expected output files are missing: {missing_output_files}")
        
        logger.info(f"Base network configuration generated successfully in {output_dir}")
        return output_dir
    
    def generate_network_variations(self):
        """Generate multiple network configurations for robustness analysis"""
        logger.info("Generating network variations for robustness analysis...")
        
        configurations = []
        
        for seed in self.network_seeds:
            for load in self.load_variations:
                config_name = f"tornet-0.05-seed{seed}-load{load}"
                
                # Skip if directory exists
                if os.path.exists(config_name):
                    logger.warning(f"Directory {config_name} already exists - skipping")
                    configurations.append(config_name)
                    continue
                
                cmd = [
                    "tornettools", "generate",
                    "relayinfo_staging_2025-01-01--2025-01-31.json",
                    "userinfo_staging_2025-01-01--2025-01-31.json",
                    "networkinfo_staging.gml", 
                    "tmodel-ccs2018.github.io",
                    f"--network_scale={self.network_scale}",
                    f"--load_scale={load}",
                    f"--prefix={config_name}",
                    f"--seed={seed}"
                ]
                
                success, output = self.run_command_safely(cmd, f"Network variation {config_name}")
                
                if success and os.path.exists(config_name):
                    configurations.append(config_name)
                else:
                    logger.warning(f"Failed to generate {config_name} - continuing with others")
                    
        logger.info(f"Generated {len(configurations)} network variations")
        return configurations
    
    def modify_shadow_config(self, config_dir):
        """Modify Shadow configuration to add web infrastructure"""
        logger.info(f"Modifying Shadow configuration in {config_dir}...")
        
        config_file = Path(config_dir) / "shadow.config.yaml"
        if not config_file.exists():
            logger.error(f"Shadow config file not found at {config_file}")
            return False
            
        try:
            # Load existing configuration
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
                
            if config is None:
                logger.error(f"Failed to parse YAML configuration from {config_file}")
                return False
                
            # Ensure hosts section exists
            if 'hosts' not in config:
                config['hosts'] = {}
                
            # Add web server hosts
            logger.info(f"Adding {self.num_web_servers} web servers...")
            for i in range(self.num_web_servers):
                server_name = f"webserver{i}"
                config['hosts'][server_name] = {
                    'network_node_id': i % 10,  # Distribute across network nodes
                    'processes': [{
                        'path': '/usr/bin/python3',
                        'args': f'-m zimply --port={8080+i} --content-dir=/opt/wikipedia-content',
                        'start_time': '5s',
                        'expected_final_state': 'running'
                    }]
                }
                
            # Add web client hosts for sensitive pages (W_α)
            logger.info(f"Adding {self.num_sensitive_clients} sensitive clients...")
            for i in range(self.num_sensitive_clients):
                client_name = f"webclient_sensitive_{i}"
                config['hosts'][client_name] = {
                    'network_node_id': (i + self.num_web_servers) % 10,
                    'processes': [{
                        'path': '/opt/bin/wget2',
                        'args': '--page-requisites --max-threads=30 --reject-regex=/w/|\.js$ --user-agent="Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0"',
                        'start_time': '60s',
                        'expected_final_state': {'exited': 0}
                    }]
                }
                
            # Add web client hosts for benign/unlabeled pages (W_β ∪ W_∅)
            logger.info(f"Adding {self.num_benign_clients} benign clients...")
            for i in range(self.num_benign_clients):
                client_name = f"webclient_benign_{i}"
                config['hosts'][client_name] = {
                    'network_node_id': (i + self.num_web_servers + self.num_sensitive_clients) % 10,
                    'processes': [{
                        'path': '/opt/bin/wget2', 
                        'args': '--page-requisites --max-threads=30 --reject-regex=/w/|\.js$ --user-agent="Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0"',
                        'start_time': '90s',
                        'expected_final_state': {'exited': 0}
                    }]
                }
                
            # Configure all Tor entry relays to collect cell traces
            logger.info("Configuring OnionTrace on entry relays...")
            entry_relays_found = 0
            for host_name, host_config in config['hosts'].items():
                if 'relay' in host_name and any('Entry' in str(proc.get('args', '')) for proc in host_config.get('processes', [])):
                    # Add OnionTrace to entry relays for cell trace collection
                    host_config['processes'].append({
                        'path': '/opt/bin/oniontrace',
                        'args': f'--tor-control-port=127.0.0.1:9051 --output=/tmp/oniontrace-{host_name}.log',
                        'start_time': '10s',
                        'expected_final_state': 'running'
                    })
                    entry_relays_found += 1
                    
            logger.info(f"Configured OnionTrace on {entry_relays_found} entry relays")
                    
            # Extend simulation time for data collection
            if 'general' not in config:
                config['general'] = {}
            config['general']['stop_time'] = '30 min'
            
            # Save modified configuration
            modified_config_file = Path(config_dir) / "shadow.config.wf.yaml"
            with open(modified_config_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
                
            logger.info(f"Modified configuration saved to {modified_config_file}")
            return True
            
        except yaml.YAMLError as e:
            logger.error(f"YAML parsing error: {e}")
            return False
        except Exception as e:
            logger.error(f"Error modifying configuration: {e}")
            return False
        
    def create_website_lists(self):
        """Create website selection files for different categories"""
        logger.info("Creating website selection lists...")
        
        try:
            # W_α: Sensitive pages (98 pages following paper methodology)
            sensitive_pages = [f"sensitive_page_{i}.html" for i in range(98)]
            with open("W_alpha_pages.txt", "w") as f:
                f.write("\n".join(sensitive_pages))
                
            # W_β: Benign pages (subset for binary classification)
            benign_pages = [f"benign_page_{i}.html" for i in range(33859)]
            with open("W_beta_pages.txt", "w") as f:
                f.write("\n".join(benign_pages))
                
            # W_∅: Unlabeled pages (remaining subset)
            unlabeled_pages = [f"unlabeled_page_{i}.html" for i in range(33859)]
            with open("W_empty_pages.txt", "w") as f:
                f.write("\n".join(unlabeled_pages))
                
            logger.info("Website lists created (placeholder format)")
            logger.info("Note: You'll need to implement random walk generation for actual Wikipedia pages")
            return True
            
        except Exception as e:
            logger.error(f"Error creating website lists: {e}")
            return False
        
    def generate_all_configurations(self):
        """Generate all network configurations needed for WF research"""
        logger.info("=== Website Fingerprinting Network Configuration Generator ===")
        logger.info(f"Network scale: {self.network_scale} (5%)")
        logger.info(f"Web servers: {self.num_web_servers}")
        logger.info(f"Sensitive clients: {self.num_sensitive_clients}")
        logger.info(f"Benign clients: {self.num_benign_clients}")
        logger.info("")
        
        # Check prerequisites first
        if not self.check_prerequisites():
            logger.error("Prerequisites check failed - cannot continue")
            return []
        
        # Generate base configuration
        base_config = self.generate_base_networks()
        if not base_config:
            logger.error("Failed to generate base configuration")
            return []
            
        if not self.modify_shadow_config(base_config):
            logger.error("Failed to modify base configuration")
            return [base_config]  # Return it anyway in case user wants to debug
        
        # Generate network variations for robustness analysis
        variations = self.generate_network_variations()
        successful_configs = [base_config]
        
        for config_dir in variations:
            if self.modify_shadow_config(config_dir):
                successful_configs.append(config_dir)
            else:
                logger.warning(f"Failed to modify configuration {config_dir}")
            
        # Create website lists
        self.create_website_lists()
        
        logger.info("\n=== Configuration Complete ===")
        logger.info(f"Base configuration: {base_config}")
        logger.info(f"Successful configurations: {len(successful_configs)}")
        logger.info("\nTo run simulations:")
        logger.info("1. ./run_wf_simulation.sh <config_dir>")
        logger.info("2. Process results with WF classifiers")
        
        return successful_configs

def main():
    # Set up argument handling
    import argparse
    parser = argparse.ArgumentParser(description='Generate WF network configurations')
    parser.add_argument('--generate-variations', action='store_true', 
                       help='Generate multiple configurations for robustness analysis')
    parser.add_argument('--debug', action='store_true', 
                       help='Enable debug logging')
    parser.add_argument('--network-scale', type=float, default=0.05,
                       help='Network scale factor (default: 0.05 for 5%)')
    parser.add_argument('--base-load', type=float, default=0.4,
                       help='Base load factor (default: 0.4)')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        generator = WFNetworkGenerator(
            network_scale=args.network_scale,
            base_load=args.base_load
        )
        
        if args.generate_variations:
            # Generate multiple configurations for robustness analysis
            configs = generator.generate_all_configurations()
            if configs:
                logger.info(f"Successfully generated {len(configs)} configurations")
            else:
                logger.error("No configurations were generated successfully")
                sys.exit(1)
        else:
            # Generate just base configuration
            if not generator.check_prerequisites():
                logger.error("Prerequisites check failed")
                sys.exit(1)
                
            base_config = generator.generate_base_networks()
            if not base_config:
                logger.error("Failed to generate base configuration")
                sys.exit(1)
                
            if generator.modify_shadow_config(base_config):
                generator.create_website_lists()
                logger.info(f"Base configuration ready: {base_config}")
            else:
                logger.error("Failed to modify base configuration")
                sys.exit(1)
                
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()