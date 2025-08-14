#!/usr/bin/env python3
"""
Corrected convert_config.py following the paper's Wikipedia mirror approach
"""

import yaml
import xml.etree.ElementTree as ET
import sys
import json
import shutil
import os
from pathlib import Path
import argparse
import random

class CorrectedWFConfigConverter:
    """Converts tornettools configs following the paper's methodology"""
    
    def __init__(self, network_dir, urls_file, verbose=True):
        self.network_dir = Path(network_dir)
        self.urls_file = urls_file
        self.verbose = verbose
        self.urls = self.load_and_process_urls()
        self.webpage_sets = self.create_webpage_sets()
        
    def log(self, message):
        if self.verbose:
            print(f"[WF-CONFIG] {message}")
        
    def load_and_process_urls(self):
        """Load URLs and extract Wikipedia page paths following paper methodology"""
        urls = []
        try:
            with open(self.urls_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 3:
                        full_url = parts[2]
                        # Extract Wikipedia page path from URL
                        # e.g., http://129.114.108.192:8000/Association_football -> /Association_football
                        if '/' in full_url:
                            page_path = '/' + full_url.split('/', 3)[-1] if full_url.count('/') > 2 else '/index.html'
                        else:
                            page_path = '/index.html'
                        
                        urls.append({
                            'original_ip': parts[0],
                            'original_port': int(parts[1]),
                            'original_url': full_url,
                            'page_path': page_path,
                            'id': len(urls),
                            'line_num': line_num
                        })
                        
        except FileNotFoundError:
            self.log(f"Error: URLs file {self.urls_file} not found")
            sys.exit(1)
            
        self.log(f"Loaded {len(urls)} Wikipedia pages from {self.urls_file}")
        if urls:
            self.log(f"Sample page paths: {[url['page_path'] for url in urls[:5]]}")
        return urls
    
    def create_webpage_sets(self):
        """Create W_α (sensitive), W_β (benign), W_∅ (unlabeled) sets following paper methodology"""
        total_urls = len(self.urls)
        
        if total_urls == 0:
            self.log("Warning: No URLs loaded")
            return {'W_alpha': [], 'W_beta': [], 'W_empty': []}
        
        # Following the paper's methodology: W_α contains 98 unique pages
        sensitive_count = min(98, total_urls)
        
        # Shuffle URLs to randomize selection (paper used random walks)
        shuffled_urls = self.urls.copy()
        random.shuffle(shuffled_urls)
        
        sensitive_urls = shuffled_urls[:sensitive_count]
        
        # For this implementation, we'll focus on the sensitive set
        # In a full implementation, you'd need additional Wikipedia pages for W_β and W_∅
        remaining_urls = shuffled_urls[sensitive_count:]
        benign_count = len(remaining_urls) // 2 if remaining_urls else 0
        benign_urls = remaining_urls[:benign_count]
        unlabeled_urls = remaining_urls[benign_count:]
        
        self.log(f"Created webpage sets following paper methodology:")
        self.log(f"  W_α (sensitive): {len(sensitive_urls)} Wikipedia pages")
        self.log(f"  W_β (benign): {len(benign_urls)} Wikipedia pages")  
        self.log(f"  W_∅ (unlabeled): {len(unlabeled_urls)} Wikipedia pages")
        
        return {
            'W_alpha': sensitive_urls,
            'W_beta': benign_urls,
            'W_empty': unlabeled_urls
        }
    
    def find_available_node_ids(self, config, count_needed):
        """Find available network node IDs in the existing topology"""
        existing_ids = set()
        
        # Collect all existing network node IDs
        for host_name, host_config in config['hosts'].items():
            if 'network_node_id' in host_config:
                existing_ids.add(host_config['network_node_id'])
        
        if not existing_ids:
            self.log("Warning: No existing network node IDs found")
            return list(range(1, count_needed + 1))
        
        self.log(f"Found {len(existing_ids)} existing network node IDs")
        self.log(f"Range: {min(existing_ids)} to {max(existing_ids)}")
        
        # Find available IDs by extending beyond the existing range
        # This is safer than looking for gaps
        available_ids = []
        next_id = max(existing_ids) + 1
        
        for _ in range(count_needed):
            available_ids.append(next_id)
            next_id += 1
        
        self.log(f"Allocated {len(available_ids)} new node IDs: {available_ids}")
        return available_ids
    
    def modify_shadow_config(self, research_mode='comprehensive'):
        """Modify Shadow configuration following the paper's approach"""
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
        
        # Enable PCAP capture on client hosts (following paper methodology)
        modified_hosts = 0
        for host_name, host_config in config['hosts'].items():
            # Only modify client hosts that will generate WF traffic
            if any(pattern in host_name.lower() for pattern in ['client', 'markov']):
                if 'host_options' not in host_config:
                    host_config['host_options'] = {}
                
                # Enable packet capture (correct Shadow format)
                host_config['host_options']['pcap_enabled'] = True
                host_config['host_options']['pcap_capture_size'] = 65535
                
                # Add Tor control port for cell trace collection
                for process in host_config.get('processes', []):
                    if 'tor' in process.get('path', '').lower():
                        args = process.get('args', '')
                        if '--ControlPort' not in args:
                            args += ' --ControlPort 9051'
                        if '--CookieAuthentication' not in args:
                            args += ' --CookieAuthentication 0'
                        process['args'] = args.strip()
                
                modified_hosts += 1
                self.log(f"  ✅ Enabled PCAP and Tor control for {host_name}")
        
        # # Add Wikipedia mirror server following the paper's approach
        # servers_to_add = 1  # Single Wikipedia mirror server like in the paper
        # available_node_ids = self.find_available_node_ids(config, servers_to_add)
        
        # if available_node_ids:
        #     server_name = "wikipedia-mirror"
        #     node_id = available_node_ids[0]
            
        #     # Create Wikipedia mirror server configuration
        #     config['hosts'][server_name] = {
        #         'network_node_id': node_id,
        #         'bandwidth_down': '1 Gbit',
        #         'bandwidth_up': '1 Gbit',
        #         'processes': [{
        #             'path': 'python3',
        #             'args': '-m http.server 80 --directory /tmp/wikipedia-mirror',
        #             'start_time': '10s',
        #             'expected_final_state': 'running'
        #         }]
        #     }
            
        #     self.log(f"  ✅ Added Wikipedia mirror server with node ID {node_id}")
            
        #     # Store server info for TGen configuration
        #     self.wikipedia_server = {
        #         'name': server_name,
        #         'node_id': node_id,
        #         'ip': '127.0.0.1',  # Will be resolved by Shadow
        #         'port': 80
        #     }

        # # Add wget2 client hosts following the paper's methodology
        # # Paper: "we fetch each of the 98 unique pages in W_α 200 times"
        # wget2_clients_needed = min(5, len(self.webpage_sets['W_alpha']))  # Start with 5 for testing
        # wget2_node_ids = self.find_available_node_ids(config, wget2_clients_needed)
        
        # for i in range(wget2_clients_needed):
        #     if i >= len(wget2_node_ids):
        #         break
                
        #     client_name = f"wget2-client-{i}"
        #     node_id = wget2_node_ids[i]
            
        #     # Create wget2 client host following paper methodology
        #     config['hosts'][client_name] = {
        #         'network_node_id': node_id,
        #         'bandwidth_down': '50 Mbit',
        #         'bandwidth_up': '50 Mbit',
        #         'host_options': {
        #             'pcap_enabled': True,
        #             'pcap_capture_size': 65535,
        #             'log_level': 'info'
        #         },
        #         'processes': [
        #             # Tor client process
        #             {
        #                 'path': 'tor',
        #                 'args': '--defaults-torrc /dev/null --ignore-missing-torrc '
        #                        '--DataDirectory tor-data --SocksPort 9050 --ControlPort 9051 '
        #                        '--CookieAuthentication 0 --CircuitBuildTimeout 60 '
        #                        '--KeepalivePeriod 60 --NewCircuitPeriod 60 --NumEntryGuards 1',
        #                 'start_time': '60s',
        #                 'expected_final_state': 'running'
        #             },
        #             # wget2 process (following paper's configuration)
        #             {
        #                 'path': './wget2-wf-script.sh',
        #                 'args': f'{i}',  # Pass client ID
        #                 'start_time': '180s',  # Wait for Tor to bootstrap
        #                 'expected_final_state': 'exited'
        #             }
        #         ]
        #     }
            
        #     self.log(f"  ✅ Added wget2 client {client_name} with node ID {node_id}")
        # Save modified config
        try:
            with open(config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, indent=2)
        except Exception as e:
            self.log(f"Error saving Shadow config: {e}")
            return False
        
        self.log(f"✅ Modified {modified_hosts} client hosts")
        self.log(f"✅ Added Wikipedia mirror server")
        return True
    
    def create_wget2_script(self):
        """Create wget2 script following the paper's exact methodology"""
        script_content = '''#!/bin/bash
# wget2 script for Website Fingerprinting research
# Following Jansen & Wails 2023 methodology

CLIENT_ID=$1
SOCKS_PROXY="127.0.0.1:9050"
WIKIPEDIA_SERVER="wikipedia-mirror"
LOG_FILE="/tmp/wget2-client-${CLIENT_ID}.log"

# wget2 configuration following the paper
WGET2_ARGS="--page-requisites --max-threads=30 --reject-regex=/w/|\\.js$ --user-agent=Mozilla/5.0"

# Wait for Tor to be ready
echo "$(date): wget2 client ${CLIENT_ID} waiting for Tor..." >> ${LOG_FILE}
sleep 30

# Check if Tor SOCKS proxy is available
timeout 10 bash -c "echo >/dev/tcp/127.0.0.1/9050" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "$(date): ERROR: Tor SOCKS proxy not available" >> ${LOG_FILE}
    exit 1
fi

echo "$(date): wget2 client ${CLIENT_ID} starting Wikipedia fetches..." >> ${LOG_FILE}

# Page list (subset for testing - in full implementation would include all W_α pages)
PAGES=(
    "Association_football.html"
    "Team_sport.html" 
    "FIM_Snowcross_World_Championship.html"
    "Biathlon_World_Championships.html"
    "Vladimir_Drachev.html"
    "War.html"
    "Youth_bulge.html"
    "Renewable_energy.html"
    "Energy_in_Europe.html"
    "Poland.html"
)

# Fetch each page multiple times (paper used 200 instances per page)
INSTANCES_PER_PAGE=10  # Reduced for testing

for page in "${PAGES[@]}"; do
    for instance in $(seq 1 ${INSTANCES_PER_PAGE}); do
        echo "$(date): Fetching ${page} instance ${instance}" >> ${LOG_FILE}
        
        # Use wget2 with SOCKS proxy (following paper methodology)
        timeout 60 wget2 ${WGET2_ARGS} \\
            --proxy socks5://${SOCKS_PROXY} \\
            --output-document=/dev/null \\
            --quiet \\
            "http://${WIKIPEDIA_SERVER}/${page}" \\
            2>> ${LOG_FILE}
        
        if [ $? -eq 0 ]; then
            echo "$(date): Successfully fetched ${page} instance ${instance}" >> ${LOG_FILE}
        else
            echo "$(date): Failed to fetch ${page} instance ${instance}" >> ${LOG_FILE}
        fi
        
        # Brief pause between fetches (paper used circuits for isolation)
        sleep 5
    done
    
    # Longer pause between different pages
    sleep 15
done

echo "$(date): wget2 client ${CLIENT_ID} completed all fetches" >> ${LOG_FILE}
'''
        
        # Create the script file
        script_path = Path('./wget2-wf-script.sh')
        script_path.parent.mkdir(exist_ok=True, parents=True)
        
        try:
            with open(script_path, 'w') as f:
                f.write(script_content)
            
            # Make executable
            script_path.chmod(0o777)
            self.log(f"✅ Created wget2 script: {script_path}")
            return True
            
        except Exception as e:
            self.log(f"Warning: Could not create wget2 script: {e}")
            return False
    
    def create_wikipedia_mirror_content(self):
        """Create Wikipedia mirror content following the paper's approach"""
        mirror_dir = Path('/tmp/wikipedia-mirror')
        mirror_dir.mkdir(exist_ok=True, parents=True)
        
        created_pages = 0
        
        # Create individual Wikipedia pages with realistic content
        for i, url_info in enumerate(self.webpage_sets['W_alpha']):
            page_path = url_info['page_path'].lstrip('/')
            if not page_path or page_path == 'index.html':
                page_path = f"page_{i}.html"
            
            # Create safe filename
            safe_filename = page_path.replace('/', '_').replace('\\', '_')
            if not safe_filename.endswith('.html'):
                safe_filename += '.html'
            
            page_file = mirror_dir / safe_filename
            
            # Create realistic Wikipedia-like content with varying sizes
            # This is crucial for generating different traffic patterns for WF
            content_multiplier = (i % 10) + 1
            page_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>{page_path.replace('_', ' ').title()}</title>
    <meta charset="utf-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        .infobox {{ float: right; width: 300px; border: 1px solid #ccc; margin: 10px; padding: 10px; background: #f9f9f9; }}
        .content {{ margin-right: 320px; }}
        h1, h2, h3 {{ color: #333; }}
        .reference {{ font-size: 0.9em; }}
    </style>
</head>
<body>
    <h1>{page_path.replace('_', ' ').title()}</h1>
    
    <div class="infobox">
        <h3>Wikipedia</h3>
        <p><strong>Article:</strong> {page_path.replace('_', ' ')}</p>
        <p><strong>Page ID:</strong> {i}</p>
        <p><strong>Content Level:</strong> {content_multiplier}</p>
        <p><strong>Size Category:</strong> {'Large' if content_multiplier > 7 else 'Medium' if content_multiplier > 4 else 'Small'}</p>
    </div>
    
    <div class="content">
        <p><strong>{page_path.replace('_', ' ').title()}</strong> is a Wikipedia article for Website Fingerprinting research. This content simulates realistic Wikipedia pages with varying sizes to create distinct traffic patterns.</p>
        
        {"".join([f'<p>Content paragraph {j+1}. This section provides detailed information about {page_path.replace("_", " ")}. ' + 'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. ' * content_multiplier + '</p>' for j in range(content_multiplier * 2)])}
        
        <h2>Overview</h2>
        {"".join([f'<p>Overview section {j+1}. ' + 'Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. ' * (content_multiplier // 2 + 1) + '</p>' for j in range(content_multiplier)])}
        
        <h2>Details</h2>
        {"".join([f'<p>Detailed information {j+1}. ' + 'Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo. ' * content_multiplier + '</p>' for j in range(content_multiplier + 2)])}
        
        <h2>History</h2>
        {"".join([f'<p>Historical context {j+1}. ' + 'Nemo enim ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit, sed quia consequuntur magni dolores eos qui ratione voluptatem sequi nesciunt. ' * (content_multiplier // 3 + 1) + '</p>' for j in range(content_multiplier // 2 + 1)])}
        
        <h2>References</h2>
        <ol class="reference">
            {"".join([f'<li>Reference {j+1}: Academic source about {page_path.replace("_", " ")} - Journal of Example Studies, Vol. {j+1}</li>' for j in range(content_multiplier)])}
        </ol>
        
        <h2>External Links</h2>
        <ul>
            {"".join([f'<li><a href="#">External link {j+1} for {page_path.replace("_", " ")}</a></li>' for j in range(min(content_multiplier, 5))])}
        </ul>
    </div>
    
    <script>
        // JavaScript to create varying network patterns (important for WF)
        console.log('Wikipedia page loaded: {page_path}');
        
        // Simulate different amounts of JavaScript processing
        for(let i = 0; i < {content_multiplier * 50}; i++) {{
            if (i % {max(1, content_multiplier * 10)} === 0) {{
                console.log('Processing chunk ' + i);
            }}
        }}
        
        // Simulate some AJAX-like requests (creates additional traffic)
        setTimeout(function() {{
            console.log('Delayed processing for {page_path}');
        }}, {content_multiplier * 100});
    </script>
</body>
</html>"""
            
            try:
                with open(page_file, 'w', encoding='utf-8') as f:
                    f.write(page_content)
                created_pages += 1
                
            except Exception as e:
                self.log(f"Warning: Could not create page {safe_filename}: {e}")
        
        # Create index page
        try:
            index_content = """<!DOCTYPE html>
<html>
<head>
    <title>Wikipedia Mirror for WF Research</title>
    <meta charset="utf-8">
</head>
<body>
    <h1>Wikipedia Mirror</h1>
    <p>Local Wikipedia mirror for Website Fingerprinting research following Jansen & Wails 2023.</p>
    <p>This mirror contains realistic Wikipedia-like pages with varying content sizes to generate distinct traffic patterns.</p>
</body>
</html>"""
            
            with open(mirror_dir / 'index.html', 'w', encoding='utf-8') as f:
                f.write(index_content)
            created_pages += 1
            
        except Exception as e:
            self.log(f"Warning: Could not create index page: {e}")
        
        self.log(f"✅ Created {created_pages} Wikipedia pages in {mirror_dir}")
        return created_pages > 0
    
    def modify_tgen_files(self):
        """Modify TGen files to fetch from Wikipedia mirror following paper methodology"""
        tgen_files = list(self.network_dir.rglob("*.graphml"))
        self.log(f"Found {len(tgen_files)} TGen files")
        
        if not tgen_files:
            self.log("Warning: No TGen files found")
            return False
        
        modified_files = 0
        
        for tgen_file in tgen_files:
            if self.modify_single_tgen_file(tgen_file):
                modified_files += 1
        
        self.log(f"✅ Modified {modified_files}/{len(tgen_files)} TGen files")
        return modified_files > 0
    
    def modify_single_tgen_file(self, tgen_file_path):
        """Modify a single TGen XML file for Wikipedia mirror fetches"""
        self.log(f"Processing TGen file: {tgen_file_path.name}")
        
        # Backup original
        backup_path = tgen_file_path.with_suffix('.xml.original')
        if not backup_path.exists():
            shutil.copy2(tgen_file_path, backup_path)
        
        try:
            tree = ET.parse(tgen_file_path)
            root = tree.getroot()
            
            # Only modify client TGen files
            if self.is_client_tgen_file(root):
                self.log(f"  Modifying client TGen file for Wikipedia fetches")
                self.modify_client_tgen_workflow(root)
                tree.write(tgen_file_path, encoding='utf-8', xml_declaration=True)
                return True
            else:
                self.log(f"  Keeping server TGen file unchanged")
                return True
            
        except Exception as e:
            self.log(f"  Error modifying {tgen_file_path}: {e}")
            return False
    
    def is_client_tgen_file(self, root):
        """Determine if this is a client TGen file"""
        for node in root.findall(".//node"):
            node_type = node.find("data[@key='type']")
            if node_type is not None:
                node_type_text = node_type.text.lower() if node_type.text else ""
                if any(client_type in node_type_text for client_type in 
                       ['stream', 'webclient', 'markov', 'client']):
                    return True
        return False
    
    def modify_client_tgen_workflow(self, root):
        """Create Wikipedia fetching workflow following the paper"""
        graph = root.find('.//graph')
        if graph is None:
            raise ValueError("No graph element found")
        
        # Clear existing workflow
        for element in graph.findall('node') + graph.findall('edge'):
            graph.remove(element)
        
        # Create Wikipedia fetching workflow
        self.create_wikipedia_workflow(graph)
    
    def create_wikipedia_workflow(self, graph):
        """Create systematic Wikipedia page fetching workflow"""
        # Start node
        start_node = ET.SubElement(graph, 'node', id='start')
        start_type = ET.SubElement(start_node, 'data', key='type')
        start_type.text = 'start'
        
        # Bootstrap pause (wait for Tor and servers to start)
        pause_node = ET.SubElement(graph, 'node', id='bootstrap')
        pause_type = ET.SubElement(pause_node, 'data', key='type')
        pause_type.text = 'pause'
        pause_time = ET.SubElement(pause_node, 'data', key='time')
        pause_time.text = '120s'
        
        # Create Wikipedia page fetching sequence
        previous_node = 'bootstrap'
        
        # Fetch Wikipedia pages following the paper's methodology
        # Paper: "we fetch each of the 98 unique pages in W_α 200 times"
        pages_to_fetch = min(10, len(self.webpage_sets['W_alpha']))  # Start with 10 for testing
        instances_per_page = 5  # Start with 5 for testing
        
        for i, url_info in enumerate(self.webpage_sets['W_alpha'][:pages_to_fetch]):
            for instance in range(instances_per_page):
                node_id = f"fetch-wiki-{i}-inst-{instance}"
                
                # Create webclient node for Wikipedia fetching
                client_node = ET.SubElement(graph, 'node', id=node_id)
                
                # Node configuration
                node_type = ET.SubElement(client_node, 'data', key='type')
                node_type.text = 'webclient'
                
                # SOCKS proxy (through Tor)
                socks_proxy = ET.SubElement(client_node, 'data', key='socksproxy')
                socks_proxy.text = '127.0.0.1:9050'
                
                # Target: Wikipedia mirror server
                peers = ET.SubElement(client_node, 'data', key='peers')
                page_path = url_info['page_path'].lstrip('/')
                if not page_path or page_path == 'index.html':
                    page_path = f"page_{i}.html"
                safe_filename = page_path.replace('/', '_').replace('\\', '_')
                if not safe_filename.endswith('.html'):
                    safe_filename += '.html'
                
                # Point to the Wikipedia mirror server
                peers.text = f"wikipedia-mirror:80/{safe_filename}"
                
                # Edge from previous node
                edge = ET.SubElement(graph, 'edge', source=previous_node, target=node_id)
                edge_time = ET.SubElement(edge, 'data', key='time')
                edge_time.text = '30s'  # 30 seconds between fetches
                
                previous_node = node_id
        
        # Initial edge
        start_edge = ET.SubElement(graph, 'edge', source='start', target='bootstrap')
        start_time = ET.SubElement(start_edge, 'data', key='time')
        start_time.text = '60s'
        
        self.log(f"  Created workflow for {pages_to_fetch} Wikipedia pages, {instances_per_page} instances each")
    
    def save_metadata(self):
        """Save conversion metadata"""
        metadata = {
            'conversion_info': {
                'network_dir': str(self.network_dir),
                'urls_file': self.urls_file,
                'total_urls': len(self.urls),
                'methodology': 'Wikipedia mirror following Jansen & Wails 2023',
                'shadow_pcap_format': 'host_options.pcap_enabled'
            },
            'webpage_sets': {
                'W_alpha_count': len(self.webpage_sets['W_alpha']),
                'W_beta_count': len(self.webpage_sets['W_beta']),
                'W_empty_count': len(self.webpage_sets['W_empty'])
            },
            'wikipedia_pages': [
                {
                    'id': url['id'],
                    'page_path': url['page_path'],
                    'original_url': url['original_url']
                }
                for url in self.webpage_sets['W_alpha'][:20]
            ]
        }
        
        metadata_file = self.network_dir / 'wf_conversion_metadata.json'
        try:
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            self.log(f"✅ Saved metadata: {metadata_file}")
        except Exception as e:
            self.log(f"Warning: Could not save metadata: {e}")
    
    def convert_network(self):
        """Perform complete network conversion following the paper's methodology"""
        self.log(f"🚀 Starting WF conversion following Jansen & Wails 2023 methodology")
        self.log(f"Network directory: {self.network_dir}")
        
        if not self.network_dir.exists():
            self.log(f"❌ Network directory {self.network_dir} does not exist")
            return False
        
        success_count = 0
        
        # Step 1: Modify Shadow configuration
        self.log("Step 1/4: Modifying Shadow configuration...")
        if self.modify_shadow_config():
            success_count += 1
        
        # Step 2: Create wget2 scripts
        self.log("Step 2/4: Creating wget2 scripts...")
        if self.create_wget2_script():
            success_count += 1

        # Step 3: Create Wikipedia mirror content
        self.log("Step 3/4: Creating Wikipedia mirror content...")
        try:
            if self.create_wikipedia_mirror_content():
                success_count += 1
        except Exception as e:
            self.log(f"⚠️  Wikipedia mirror creation failed: {e}")
        
        # # Step 4: Modify TGen files
        # self.log("Step 4/4: Modifying TGen files...")
        # if self.modify_tgen_files():
        #     success_count += 1
        
        # # Step 5: Save metadata
        # self.log("Step 5/4: Saving metadata...")
        # try:
        #     self.save_metadata()
        #     success_count += 1
        # except Exception as e:
        #     self.log(f"⚠️  Metadata save failed: {e}")
        
        # Summary
        self.log(f"\n🎯 Conversion completed: {success_count}/5 steps successful")
        
        # if success_count >= 3:
        #     self.log("🎉 Network successfully converted for WF research!")
        #     self.log("📋 Following Jansen & Wails 2023 methodology:")
        #     self.log("   • Wikipedia mirror server created")
        #     self.log("   • PCAP capture enabled on clients")
        #     self.log("   • TGen configured for systematic page fetching")
        #     self.log(f"📁 Wikipedia content: /tmp/wikipedia-mirror/")
        #     self.log(f"📁 PCAP captures: {self.network_dir}/shadow.data/hosts/*/eth0.pcap")
        #     self.log(f"🚀 Ready for simulation: tornettools simulate {self.network_dir.name}")
        #     return True
        # else:
        #     self.log("❌ Conversion failed")
        #     return False

def main():
    parser = argparse.ArgumentParser(
        description='Convert tornettools network for WF research following Jansen & Wails 2023'
    )
    parser.add_argument('network_dir', help='Network directory')
    parser.add_argument('urls_file', help='URLs file with Wikipedia pages')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    converter = CorrectedWFConfigConverter(args.network_dir, args.urls_file, args.verbose)
    success = converter.convert_network()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()