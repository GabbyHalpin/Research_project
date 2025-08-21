#!/usr/bin/env python3
"""
Script to modify shadow.config.yaml to convert perfclient hosts to articlient-extra hosts
with Arti Tor implementation, PCAP capture enabled, and tgen traffic generation.
"""

import yaml
import sys
import shutil
from pathlib import Path
import argparse
import os
import re


def copy_arti_config_files(config_dir, verbose=True):
    """
    Copy arti configuration files from /opt/src/arti/tests/shadow/conf to the conf folder
    
    Args:
        config_dir: Directory where the shadow.config.yaml file is located
        verbose: Whether to print detailed output
    
    Returns:
        bool: True if successful, False otherwise
    """
    source_dir = Path('/opt/src/arti/tests/shadow/conf')
    target_dir = Path(config_dir) / 'conf'
    
    # Files to copy
    config_files = ['arti.common.toml']
    
    if verbose:
        print(f"Copying Arti configuration files...")
        print(f"Source: {source_dir}")
        print(f"Target: {target_dir}")
    
    # Check if source directory exists
    if not source_dir.exists():
        print(f"Error: Source directory not found: {source_dir}")
        return False
    
    # Create target directory if it doesn't exist
    try:
        target_dir.mkdir(exist_ok=True, parents=True)
        if verbose:
            print(f"Ensured directory exists: {target_dir}")
    except Exception as e:
        print(f"Error creating target directory {target_dir}: {e}")
        return False
    
    # Check if files already exist
    existing_files = []
    for config_file in config_files:
        target_path = target_dir / config_file
        if target_path.exists():
            existing_files.append(config_file)
    
    if existing_files:
        if verbose:
            print(f"Files already exist: {', '.join(existing_files)}")
            print("Skipping copy operation - files already present")
        return True
    
    # Copy each configuration file
    copied_files = []
    for config_file in config_files:
        source_path = source_dir / config_file
        target_path = target_dir / config_file
        
        if not source_path.exists():
            print(f"Warning: Source file not found: {source_path}")
            continue
        
        try:
            shutil.copy2(source_path, target_path)
            copied_files.append(config_file)
            if verbose:
                print(f"  ✓ Copied {config_file}")
        except Exception as e:
            print(f"Error copying {config_file}: {e}")
            return False
    
    if copied_files:
        if verbose:
            print(f"Successfully copied {len(copied_files)} configuration files to {target_dir}")
        return True
    else:
        print("No configuration files were copied")
        return False


def extract_authorities_from_config(config):
    """
    Extract authority host names from the shadow.config.yaml
    
    Args:
        config: The loaded YAML configuration
    
    Returns:
        list: List of authority host names
    """
    authorities = []
    
    for host_name, host_config in config.get('hosts', {}).items():
        # Check if this host has tor processes that might be authorities
        processes = host_config.get('processes', [])
        for process in processes:
            if 'tor' in process.get('path', '').lower():
                args = process.get('args', '')
                # Look for authority-related arguments or naming patterns
                if ('authority' in host_name.lower() or 
                    '4uthority' in host_name or
                    'bwauth' in host_name.lower() or
                    ('--Address' in args and any(auth_keyword in args.lower() 
                                               for auth_keyword in ['authority', '4uthority']))):
                    authorities.append(host_name)
                    break
    
    return authorities


def read_authorities_from_torrc(config_dir, verbose=True):
    """
    Read authority information from tor.common.torrc file
    
    Args:
        config_dir: Directory containing the shadow config
        verbose: Whether to print detailed output
    
    Returns:
        dict: Mapping of authority name to {v3ident, ip, port}
    """
    torrc_path = Path(config_dir) / 'conf' / 'tor.common.torrc'
    
    if not torrc_path.exists():
        if verbose:
            print(f"Warning: tor.common.torrc file not found at {torrc_path}")
        return {}
    
    authorities = {}
    
    try:
        with open(torrc_path, 'r') as f:
            for line in f:
                line = line.strip()
                # Parse DirServer lines
                # Format: DirServer 4uthority1 v3ident=HEXSTRING orport=9001 IP:PORT FINGERPRINT
                if line.startswith('DirServer '):
                    parts = line.split()
                    if len(parts) >= 5:
                        auth_name = parts[1]
                        v3ident = None
                        orport = None
                        ip_port = None
                        
                        for part in parts[2:]:
                            if part.startswith('v3ident='):
                                v3ident = part.replace('v3ident=', '')
                            elif part.startswith('orport='):
                                orport = part.replace('orport=', '')
                            elif ':' in part and '.' in part:  # IP:port format
                                ip_port = part
                                break
                        
                        if auth_name and v3ident and ip_port:
                            ip = ip_port.split(':')[0]
                            port = ip_port.split(':')[1] if ':' in ip_port else '8080'
                            authorities[auth_name] = {
                                'v3ident': v3ident,
                                'ip': ip,
                                'port': port,
                                'orport': orport or '9001'
                            }
                            if verbose:
                                print(f"  Found authority {auth_name}: v3ident={v3ident}, ip={ip}, port={port}")
        
        if verbose:
            print(f"Extracted {len(authorities)} authorities from tor.common.torrc")
        
    except Exception as e:
        if verbose:
            print(f"Error reading tor.common.torrc file: {e}")
        return {}
    
    return authorities


def read_authority_fingerprints(config_dir, authorities, verbose=True):
    """
    Read RSA and ed25519 fingerprints from authority directories
    
    Args:
        config_dir: Directory containing the shadow config
        authorities: Dictionary of authority information
        verbose: Whether to print detailed output
    
    Returns:
        dict: Updated authorities dict with RSA and ed25519 fingerprints
    """
    shadow_data_dir = Path(config_dir) / 'shadow.data.template' / 'hosts'
    
    for auth_name in authorities:
        auth_dir = shadow_data_dir / auth_name
        
        # Read RSA fingerprint
        rsa_fingerprint_path = auth_dir / 'fingerprint'
        if rsa_fingerprint_path.exists():
            try:
                with open(rsa_fingerprint_path, 'r') as f:
                    rsa_fp = f.read().strip()
                    # Remove authority name prefix if present
                    # Format: "4uthority1ABCD1234..." -> "ABCD1234..."
                    if rsa_fp.startswith(auth_name):
                        rsa_fp = rsa_fp[len(auth_name):]
                    # Remove any remaining spaces
                    rsa_fp = rsa_fp.replace(' ', '')
                    authorities[auth_name]['rsa_identity'] = rsa_fp
                    if verbose:
                        print(f"  Found RSA fingerprint for {auth_name}: {rsa_fp}")
            except Exception as e:
                if verbose:
                    print(f"  Error reading RSA fingerprint for {auth_name}: {e}")
        else:
            if verbose:
                print(f"  Warning: RSA fingerprint not found for {auth_name} at {rsa_fingerprint_path}")
        
        # Read ed25519 fingerprint
        ed25519_fingerprint_path = auth_dir / 'fingerprint-ed25519'
        if ed25519_fingerprint_path.exists():
            try:
                with open(ed25519_fingerprint_path, 'r') as f:
                    ed25519_content = f.read().strip()
                    # Remove authority name prefix if present
                    # Format: "4uthority1 WI+huJ4KBpE..." -> "WI+huJ4KBpE..."
                    if ed25519_content.startswith(auth_name):
                        # Remove authority name and any following whitespace
                        ed25519_fp = ed25519_content[len(auth_name):].strip()
                    else:
                        ed25519_fp = ed25519_content
                    authorities[auth_name]['ed_identity'] = ed25519_fp
                    if verbose:
                        print(f"  Found ed25519 fingerprint for {auth_name}: {ed25519_fp}")
            except Exception as e:
                if verbose:
                    print(f"  Error reading ed25519 fingerprint for {auth_name}: {e}")
        else:
            if verbose:
                print(f"  Warning: ed25519 fingerprint not found for {auth_name} at {ed25519_fingerprint_path}")
    
    return authorities


def update_arti_common_toml(config_dir, authorities_info, verbose=True):
    """
    Update arti.common.toml with the authorities and fallback caches from the config
    
    Args:
        config_dir: Directory containing the config files
        authorities_info: Dictionary of authority information with v3ident, ip, port, etc.
        verbose: Whether to print detailed output
    
    Returns:
        bool: True if successful, False otherwise
    """
    arti_common_path = Path(config_dir) / 'conf' / 'arti.common.toml'
    
    if not arti_common_path.exists():
        if verbose:
            print(f"Error: arti.common.toml not found at {arti_common_path}")
        return False
    
    try:
        # Read the current file
        with open(arti_common_path, 'r') as f:
            content = f.read()
        
        # Build the new authorities section
        auth_entries = []
        for auth_name, auth_info in authorities_info.items():
            v3ident = auth_info['v3ident']
            auth_entries.append(f'    {{ name = "{auth_name}", v3ident = "{v3ident}" }},')
            if verbose:
                print(f"  Added authority {auth_name} -> {v3ident}")
        
        # Build the fallback_caches section
        fallback_entries = []
        for auth_name, auth_info in authorities_info.items():
            orport = auth_info.get('orport', '9001')
            ip = auth_info['ip']
            rsa_identity = auth_info.get('rsa_identity', '')
            ed_identity = auth_info.get('ed_identity', '')
            
            if rsa_identity and ed_identity:
                fallback_entry = f'    {{ rsa_identity = "{rsa_identity}", ed_identity = "{ed_identity}", orports = [ "{ip}:{orport}" ] }},'
                fallback_entries.append(fallback_entry)
                if verbose:
                    print(f"  Added fallback cache {auth_name}: {ip}:{orport}")
            else:
                missing = []
                if not rsa_identity:
                    missing.append("RSA identity")
                if not ed_identity:
                    missing.append("ed25519 identity")
                if verbose:
                    print(f"  Warning: Missing {', '.join(missing)} for {auth_name}, skipping fallback cache")
        
        if not auth_entries:
            if verbose:
                print("No authorities found to add")
            return True
        
        # Remove any existing sections that we're going to replace
        # Remove [tor_network] section completely
        content = re.sub(r'\[tor_network\].*?(?=\n\[|\n*$)', '', content, flags=re.DOTALL)
        
        # Remove [path_rules] section completely 
        content = re.sub(r'\[path_rules\].*?(?=\n\[|\n*$)', '', content, flags=re.DOTALL)
        
        # Remove any standalone subnet family prefix lines that might be floating around
        content = re.sub(r'^ipv4_subnet_family_prefix\s*=.*\n?', '', content, flags=re.MULTILINE)
        content = re.sub(r'^ipv6_subnet_family_prefix\s*=.*\n?', '', content, flags=re.MULTILINE)
        
        # Clean up multiple newlines
        content = re.sub(r'\n{3,}', '\n\n', content).strip()
        
        # Build the new [tor_network] section
        tor_network_content = "[tor_network]\n"
        
        if fallback_entries:
            tor_network_content += "fallback_caches = [\n"
            tor_network_content += "\n".join(fallback_entries) + "\n"
            tor_network_content += "]\n"
        
        if auth_entries:
            tor_network_content += "authorities = [\n"
            tor_network_content += "\n".join(auth_entries) + "\n"
            tor_network_content += "]\n"
        
        # Build the [path_rules] section
        path_rules_content = "\n[path_rules]\n"
        path_rules_content += "ipv4_subnet_family_prefix = 33\n"
        path_rules_content += "ipv6_subnet_family_prefix = 129\n"
        
        # Handle [override_net_params] section for hsdir_interval
        if '[override_net_params]' in content:
            # Update existing section to use 120 instead of 900
            override_pattern = r'(\[override_net_params\][^[]*?)hsdir_interval\s*=\s*\d+'
            if re.search(override_pattern, content, flags=re.DOTALL):
                content = re.sub(override_pattern, r'\1hsdir_interval = 120', content, flags=re.DOTALL)
            else:
                # Add hsdir_interval to existing section
                override_pattern = r'(\[override_net_params\][^[]*?)(?=\n\[|\n*$)'
                content = re.sub(override_pattern, r'\1hsdir_interval = 120\n', content, flags=re.DOTALL)
        else:
            # Add new section
            content += "\n\n[override_net_params]\n# When TestingTorNetwork is enabled, tor uses a hard-coded value\n# of 120 here; match it.\nhsdir_interval = 120\n"
        
        # Combine everything: tor_network + path_rules + existing content
        final_content = tor_network_content + path_rules_content + "\n" + content
        
        # Final cleanup of multiple newlines
        final_content = re.sub(r'\n{3,}', '\n\n', final_content).strip() + '\n'
        
        # Write the updated content back
        with open(arti_common_path, 'w') as f:
            f.write(final_content)
        
        if verbose:
            print(f"Successfully updated arti.common.toml with {len(auth_entries)} authorities")
            if fallback_entries:
                print(f"Added {len(fallback_entries)} fallback caches")
        
        return True
        
    except Exception as e:
        if verbose:
            print(f"Error updating arti.common.toml: {e}")
        return False


def modify_shadow_config(config_path, backup=True, verbose=True):
    """
    Modify Shadow configuration to convert perfclient hosts to articlient-extra
    
    Args:
        config_path: Path to shadow.config.yaml file
        backup: Whether to create a backup of the original file
        verbose: Whether to print detailed output
    """
    config_path = Path(config_path)
    
    if not config_path.exists():
        print(f"Error: Configuration file not found: {config_path}")
        return False
    
    if verbose:
        print(f"Modifying Shadow config: {config_path}")
    
    # Create backup if requested
    if backup:
        backup_path = config_path.with_suffix('.yaml.backup')
        if not backup_path.exists():
            shutil.copy2(config_path, backup_path)
            if verbose:
                print(f"Created backup: {backup_path}")
    
    # Load configuration
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
    except Exception as e:
        print(f"Error reading configuration file: {e}")
        return False
    
    if 'hosts' not in config:
        print("Error: No 'hosts' section found in configuration")
        return False
    
    # Track modifications
    modified_hosts = []
    
    # Iterate through hosts and modify perfclient hosts
    for host_name, host_config in config['hosts'].items():
        # Check if this is a perfclient host
        if any(pattern in host_name.lower() for pattern in ['markov']):
            if verbose:
                print(f"Converting {host_name} to articlient-extra format...")
            
            # Preserve the original network_node_id
            original_node_id = host_config.get('network_node_id')
            if original_node_id is None:
                print(f"Warning: No network_node_id found for {host_name}, skipping...")
                continue
            
            # Create new articlient-extra configuration
            new_config = {
                'network_node_id': original_node_id,
                'bandwidth_up': '1000000 kilobit',
                'bandwidth_down': '1000000 kilobit',
                'host_options': {
                    'pcap_enabled': True,
                    'pcap_capture_size': '65535'
                },
                'processes': [
                    # Arti process (replaces Tor)
                    {
                        'path': '/opt/bin/arti',
                        'args': [
                            'proxy',
                            '-c=/mnt/tornet-0.01/conf/arti.common.toml',
                            '-o=proxy.socks_listen="127.0.0.1:9050"',
                            '--disable-fs-permission-checks',
                            '-l='  # Disable console logging
                        ],
                        'environment': {
                            'RUST_BACKTRACE': '1',
                            'OPENBLAS_NUM_THREADS': '1',
                            'HOME': './home'
                        },
                        'start_time': 240,
                        'expected_final_state': 'running'
                    },
                    # tgen process for traffic generation
                    {
                        'path': '~/.local/bin/tgen',
                        'args': 'tgenrc.graphml',
                        'start_time': 300,
                        'expected_final_state': 'running'
                    }
                ]
            }
            
            # Replace the host configuration
            config['hosts'][host_name] = new_config
            modified_hosts.append(host_name)
            
            if verbose:
                print(f"  ✓ Converted {host_name} (node_id: {original_node_id})")
                print(f"    - Replaced Tor with Arti")
                print(f"    - Enabled PCAP capture")
                print(f"    - Added tgen traffic generation")

        if any(pattern in host_name.lower() for pattern in ['perf', 'client']):
            if verbose:
                print(f"Converting {host_name} to articlient format...")
            
            # Preserve the original network_node_id
            original_node_id = host_config.get('network_node_id')
            if original_node_id is None:
                print(f"Warning: No network_node_id found for {host_name}, skipping...")
                continue
            
            # Create new articlient-extra configuration
            new_config = {
                'network_node_id': original_node_id,
                'bandwidth_up': '1000000 kilobit',
                'bandwidth_down': '1000000 kilobit',
                'host_options': {
                    'pcap_enabled': True,
                    'pcap_capture_size': '65535'
                },
                'processes': [
                    # Arti process (replaces Tor)
                    {
                        'path': '/opt/bin/arti',
                        'args': [
                            'proxy',
                            '-c=/mnt/tornet-0.01/conf/arti.common.toml',
                            '-o=proxy.socks_listen="127.0.0.1:9050"',
                            '--disable-fs-permission-checks',
                            '-l='  # Disable console logging
                        ],
                        'environment': {
                            'RUST_BACKTRACE': '1',
                            'OPENBLAS_NUM_THREADS': '1',
                            'HOME': './home'
                        },
                        'start_time': 240,
                        'expected_final_state': 'running'
                    },
                    # tgen process for traffic generation
                    {
                        'path': '~/.local/bin/tgen',
                        'args': '../../../conf/tgen-perf-exit.tgenrc.graphml',
                        'start_time': 300,
                        'expected_final_state': 'running'
                    }
                ]
            }
            
            # Replace the host configuration
            config['hosts'][host_name] = new_config
            modified_hosts.append(host_name)
            
            if verbose:
                print(f"  ✓ Converted {host_name} (node_id: {original_node_id})")
                print(f"    - Replaced Tor with Arti")
                print(f"    - Enabled PCAP capture")
                print(f"    - Added tgen traffic generation")

    if not modified_hosts:
        print("No perfclient hosts found to modify")
        return False
    
    # Save modified configuration
    try:
        with open(config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, indent=2, sort_keys=False)
        
        if verbose:
            print(f"\nSuccessfully modified {len(modified_hosts)} hosts:")
            for host_name in modified_hosts:
                print(f"  - {host_name}")
            print(f"\nConfiguration saved to: {config_path}")
        
        return True
        
    except Exception as e:
        print(f"Error saving configuration file: {e}")
        return False


def validate_config(config_path, verbose=True):
    """
    Validate the modified configuration file
    """
    config_path = Path(config_path)
    
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
    except Exception as e:
        print(f"Error reading configuration for validation: {e}")
        return False
    
    articlient_count = 0
    validation_errors = []
    
    for host_name, host_config in config.get('hosts', {}).items():
        if 'perfclient' in host_name.lower():
            # Check if conversion was successful
            processes = host_config.get('processes', [])
            has_arti = any('arti' in proc.get('path', '') for proc in processes)
            has_tgen = any('tgen' in proc.get('path', '') for proc in processes)
            has_pcap = host_config.get('host_options', {}).get('pcap_enabled', False)
            
            if has_arti and has_tgen and has_pcap:
                articlient_count += 1
                if verbose:
                    print(f"✓ {host_name}: Successfully converted to articlient-extra")
            else:
                missing = []
                if not has_arti:
                    missing.append("arti")
                if not has_tgen:
                    missing.append("tgen")
                if not has_pcap:
                    missing.append("pcap")
                validation_errors.append(f"✗ {host_name}: Missing {', '.join(missing)}")
    
    if validation_errors:
        print("\nValidation errors found:")
        for error in validation_errors:
            print(f"  {error}")
        return False
    
    if verbose and articlient_count > 0:
        print(f"\nValidation successful: {articlient_count} articlient-extra hosts configured")
    
    return True


def main():
    parser = argparse.ArgumentParser(
        description='Convert perfclient hosts to articlient-extra hosts in shadow.config.yaml'
    )
    parser.add_argument(
        'config_file', 
        nargs='?', 
        default='shadow.config.yaml',
        help='Path to shadow.config.yaml file (default: shadow.config.yaml)'
    )
    parser.add_argument(
        '--no-backup', 
        action='store_true', 
        help='Skip creating backup file'
    )
    parser.add_argument(
        '--validate-only', 
        action='store_true', 
        help='Only validate configuration without modifying'
    )
    parser.add_argument(
        '--quiet', '-q', 
        action='store_true', 
        help='Suppress verbose output'
    )
    
    args = parser.parse_args()
    
    verbose = not args.quiet
    
    # First, copy Arti configuration files
    if not args.validate_only:
        if verbose:
            print("Step 1: Copying Arti configuration files...")
        
        # Get the directory containing the config file
        config_dir = Path(args.config_file).parent
        
        config_copy_success = copy_arti_config_files(config_dir, verbose)
        if not config_copy_success:
            print("Warning: Failed to copy Arti configuration files")
            print("You may need to copy them manually before running the simulation")
    
    if args.validate_only:
        if verbose:
            print("Validating configuration...")
        success = validate_config(args.config_file, verbose)
    else:
        # Step 2: Modify shadow.config.yaml
        if verbose:
            print("\nStep 2: Modifying shadow.config.yaml...")
        
        success = modify_shadow_config(
            args.config_file, 
            backup=not args.no_backup, 
            verbose=verbose
        )
        
        # Step 3: Update arti.common.toml with authorities
        if success and config_copy_success:
            if verbose:
                print("\nStep 3: Updating arti.common.toml with authorities...")
            
            # Load the config again to extract authorities
            try:
                with open(args.config_file, 'r') as f:
                    config = yaml.safe_load(f)
                
                # Extract authorities from the config
                authorities = extract_authorities_from_config(config)
                if verbose and authorities:
                    print(f"Found authorities in config: {', '.join(authorities)}")
                
                # Read authority information from tor.common.torrc
                authorities_info = read_authorities_from_torrc(config_dir, verbose)
                
                # Read RSA and ed25519 fingerprints from authority directories
                if authorities_info:
                    authorities_info = read_authority_fingerprints(config_dir, authorities_info, verbose)
                
                # Update arti.common.toml with the authorities
                if authorities_info:
                    arti_update_success = update_arti_common_toml(config_dir, authorities_info, verbose)
                    if not arti_update_success:
                        print("Warning: Failed to update arti.common.toml with authorities")
                else:
                    if verbose:
                        print("No authorities found in tor.common.torrc to add to arti.common.toml")
                        
            except Exception as e:
                print(f"Error processing authorities for arti.common.toml: {e}")
        
        if success and verbose:
            print("\nValidating modified configuration...")
            validate_config(args.config_file, verbose)
    
    if success:
        if verbose:
            print("\nOperation completed successfully!")
            print("\nNext steps:")
            print("1. Verify arti.common.toml was updated correctly")
            print("2. Ensure arti binary is built and available")
            print("3. Check tgenrc.graphml traffic generation config")
            print("4. Run simulation: tornettools simulate <network_dir>")
    else:
        print("Operation failed!")
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()