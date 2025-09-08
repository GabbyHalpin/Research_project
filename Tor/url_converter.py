#!/usr/bin/env python3
"""
Shadow Config URL Synchronizer

This script extracts URLs from a reference shadow.config.yaml file and 
applies them to a target simulation config to ensure consistent labeling 
across multiple simulations.
"""

import yaml
import argparse
import shutil
from pathlib import Path
from collections import defaultdict
import re
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ShadowConfigURLSyncer:
    def __init__(self, reference_config_path: str, target_config_path: str, verbose: bool = True):
        self.reference_config_path = Path(reference_config_path)
        self.target_config_path = Path(target_config_path)
        self.verbose = verbose
        
    def log(self, message):
        if self.verbose:
            print(f"[URL-SYNC] {message}")
    
    def extract_urls_from_reference(self):
        """Extract URLs from reference config organized by monitor"""
        if not self.reference_config_path.exists():
            self.log(f"Error: Reference config not found: {self.reference_config_path}")
            return {}
        
        try:
            with open(self.reference_config_path, 'r') as f:
                config = yaml.safe_load(f)
        except Exception as e:
            self.log(f"Error reading reference config: {e}")
            return {}
        
        monitor_urls = defaultdict(list)
        zimserver_ports = set()
        
        # Extract URLs from monitor hosts
        for host_name, host_config in config.get('hosts', {}).items():
            if host_name.startswith('monitor'):
                monitor_id = host_name.replace('monitor', '')
                
                # Extract URLs from wget2 processes
                for process in host_config.get('processes', []):
                    if process.get('path') == '/opt/bin/wget2_noinstall':
                        args = process.get('args', [])
                        
                        # Find URL in arguments (last argument is typically the URL)
                        url = None
                        for arg in reversed(args):
                            if arg.startswith('http://'):
                                url = arg
                                break
                        
                        if url:
                            monitor_urls[monitor_id].append(url)
            
            elif host_name.startswith('zimserver'):
                # Extract ports from zimserver processes
                for process in host_config.get('processes', []):
                    if 'ZIMPORT' in process.get('environment', {}):
                        port = process['environment']['ZIMPORT']
                        try:
                            zimserver_ports.add(int(port))
                        except ValueError:
                            pass
        
        # Remove duplicates while preserving order
        for monitor_id in monitor_urls:
            seen = set()
            unique_urls = []
            for url in monitor_urls[monitor_id]:
                if url not in seen:
                    seen.add(url)
                    unique_urls.append(url)
            monitor_urls[monitor_id] = unique_urls
        
        self.log(f"Extracted URLs from reference config:")
        total_urls = 0
        for monitor_id, urls in monitor_urls.items():
            self.log(f"  Monitor {monitor_id}: {len(urls)} URLs")
            total_urls += len(urls)
        
        self.log(f"  Total unique URLs: {total_urls}")
        self.log(f"  Zimserver ports: {len(zimserver_ports)}")
        
        return {
            'monitor_urls': dict(monitor_urls),
            'zimserver_ports': sorted(zimserver_ports)
        }
    
    def apply_urls_to_target(self, extracted_data):
        """Apply extracted URLs to target config"""
        if not self.target_config_path.exists():
            self.log(f"Error: Target config not found: {self.target_config_path}")
            return False
        
        # Create backup
        backup_path = self.target_config_path.with_suffix('.yaml.backup')
        shutil.copy2(self.target_config_path, backup_path)
        self.log(f"Created backup: {backup_path}")
        
        try:
            with open(self.target_config_path, 'r') as f:
                target_config = yaml.safe_load(f)
        except Exception as e:
            self.log(f"Error reading target config: {e}")
            return False
        
        monitor_urls = extracted_data['monitor_urls']
        zimserver_ports = extracted_data['zimserver_ports']
        
        modifications = 0
        
        # Update monitor hosts with reference URLs
        for host_name, host_config in target_config.get('hosts', {}).items():
            if host_name.startswith('monitor'):
                monitor_id = host_name.replace('monitor', '')
                
                if monitor_id not in monitor_urls:
                    self.log(f"Warning: No reference URLs found for {host_name}")
                    continue
                
                reference_urls = monitor_urls[monitor_id]
                new_processes = []
                
                # Preserve non-wget2 processes (Tor, newnym)
                for process in host_config.get('processes', []):
                    if process.get('path') != '/opt/bin/wget2_noinstall':
                        new_processes.append(process)
                
                # Add wget2 processes with reference URLs
                # Extract timing parameters from existing config
                existing_wget2_processes = [p for p in host_config.get('processes', []) 
                                          if p.get('path') == '/opt/bin/wget2_noinstall']
                
                if existing_wget2_processes:
                    # Use timing from first existing wget2 process as template
                    template_process = existing_wget2_processes[0]
                    base_start_time = template_process.get('start_time', 1300)
                    
                    # Calculate timing parameters
                    iterations = len(existing_wget2_processes) // len(reference_urls) if reference_urls else 1
                    iteration_interval = 30  # Default from your setup
                    
                    self.log(f"  {host_name}: Applying {len(reference_urls)} URLs with {iterations} iterations")
                    
                    # Generate new wget2 processes with reference URLs
                    for iteration in range(iterations):
                        iteration_start_time = base_start_time + (iteration * iteration_interval)
                        
                        for url in reference_urls:
                            # Copy template process and update URL
                            new_process = template_process.copy()
                            new_process['start_time'] = iteration_start_time
                            
                            # Update URL in arguments
                            new_args = []
                            args = new_process.get('args', [])
                            
                            for arg in args:
                                if arg.startswith('http://'):
                                    new_args.append(url)  # Replace with reference URL
                                else:
                                    new_args.append(arg)
                            
                            new_process['args'] = new_args
                            new_processes.append(new_process)
                        
                        # Add newnym process after each iteration (except last)
                        if iteration < iterations - 1:
                            newnym_processes = [p for p in host_config.get('processes', []) 
                                              if p.get('args') == '-m newnym']
                            if newnym_processes:
                                newnym_template = newnym_processes[0].copy()
                                newnym_template['start_time'] = iteration_start_time + 29
                                new_processes.append(newnym_template)
                
                # Update host processes
                target_config['hosts'][host_name]['processes'] = new_processes
                modifications += 1
        
        # Update zimserver with reference ports
        if zimserver_ports:
            for host_name, host_config in target_config.get('hosts', {}).items():
                if host_name.startswith('zimserver'):
                    new_processes = []
                    
                    # Preserve non-zimsrv processes
                    for process in host_config.get('processes', []):
                        if 'ZIMPORT' not in process.get('environment', {}):
                            new_processes.append(process)
                    
                    # Add zimsrv processes for reference ports
                    existing_zimsrv = [p for p in host_config.get('processes', []) 
                                      if 'ZIMPORT' in p.get('environment', {})]
                    
                    if existing_zimsrv:
                        template_process = existing_zimsrv[0]
                        
                        for port in zimserver_ports:
                            new_process = template_process.copy()
                            new_process['environment'] = template_process['environment'].copy()
                            new_process['environment']['ZIMPORT'] = str(port)
                            new_processes.append(new_process)
                    
                    target_config['hosts'][host_name]['processes'] = new_processes
                    self.log(f"  {host_name}: Updated with {len(zimserver_ports)} ports")
                    modifications += 1
        
        # Save modified config
        try:
            with open(self.target_config_path, 'w') as f:
                yaml.dump(target_config, f, default_flow_style=False, indent=2)
            self.log(f"Successfully updated target config with {modifications} host modifications")
            return True
        except Exception as e:
            self.log(f"Error saving target config: {e}")
            return False
    
    def verify_synchronization(self, extracted_data):
        """Verify that URLs were correctly applied to target"""
        try:
            with open(self.target_config_path, 'r') as f:
                target_config = yaml.safe_load(f)
        except Exception as e:
            self.log(f"Error reading target config for verification: {e}")
            return False
        
        reference_urls = extracted_data['monitor_urls']
        verification_passed = True
        
        for host_name, host_config in target_config.get('hosts', {}).items():
            if host_name.startswith('monitor'):
                monitor_id = host_name.replace('monitor', '')
                
                if monitor_id not in reference_urls:
                    continue
                
                expected_urls = set(reference_urls[monitor_id])
                actual_urls = set()
                
                # Extract URLs from target config
                for process in host_config.get('processes', []):
                    if process.get('path') == '/opt/bin/wget2_noinstall':
                        args = process.get('args', [])
                        for arg in reversed(args):
                            if arg.startswith('http://'):
                                actual_urls.add(arg)
                                break
                
                if expected_urls == actual_urls:
                    self.log(f"✓ {host_name}: URLs match reference ({len(actual_urls)} URLs)")
                else:
                    self.log(f"✗ {host_name}: URL mismatch!")
                    self.log(f"    Expected: {len(expected_urls)} URLs")
                    self.log(f"    Actual: {len(actual_urls)} URLs")
                    verification_passed = False
        
        return verification_passed
    
    def synchronize_configs(self):
        """Main synchronization process"""
        self.log("Starting URL synchronization between Shadow configs")
        self.log(f"Reference: {self.reference_config_path}")
        self.log(f"Target: {self.target_config_path}")
        
        # Step 1: Extract URLs from reference
        self.log("Step 1/3: Extracting URLs from reference config...")
        extracted_data = self.extract_urls_from_reference()
        
        if not extracted_data['monitor_urls']:
            self.log("Error: No URLs found in reference config")
            return False
        
        # Step 2: Apply URLs to target
        self.log("Step 2/3: Applying URLs to target config...")
        if not self.apply_urls_to_target(extracted_data):
            self.log("Error: Failed to apply URLs to target config")
            return False
        
        # Step 3: Verify synchronization
        self.log("Step 3/3: Verifying synchronization...")
        if self.verify_synchronization(extracted_data):
            self.log("✓ URL synchronization completed successfully!")
            self.log(f"Target config updated: {self.target_config_path}")
            self.log(f"Backup created: {self.target_config_path.with_suffix('.yaml.backup')}")
            return True
        else:
            self.log("✗ URL synchronization verification failed")
            return False

def main():
    parser = argparse.ArgumentParser(description='Synchronize URLs between Shadow simulation configs')
    parser.add_argument('reference_config', help='Path to reference shadow.config.yaml')
    parser.add_argument('target_config', help='Path to target shadow.config.yaml to modify')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    syncer = ShadowConfigURLSyncer(args.reference_config, args.target_config, args.verbose)
    success = syncer.synchronize_configs()
    
    if success:
        print("✓ URL synchronization completed successfully")
        return 0
    else:
        print("✗ URL synchronization failed")
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main())