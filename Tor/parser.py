import os
import tarfile
import numpy as np
from pathlib import Path
import re

# ======================
# CONFIG
# ======================
SHADOW_DATA_TAR = "tornet-0.05/shadow.data.tar.xz"
OUTPUT_DIR = "tik_tok_dataset"
MAX_PKTS = 5000
CLIENT_KEYWORD = "client"
SITE_LABELS = {}
label_counter = 0
conf_hosts_path = "shadow_data/shadow.data/hosts"

# Improved regex patterns - adjust based on your actual log format
# You need to examine your actual log files to determine the correct patterns
OUTGOING_PATTERNS = [
    re.compile(r"(?P<time>\d+\.\d+).*SEND"),
    re.compile(r"(?P<time>\d+\.\d+).*OUT"),
    re.compile(r"(?P<time>\d+\.\d+).*cell.*outgoing", re.IGNORECASE),
    re.compile(r"(?P<time>\d+\.\d+).*\+1"),  # if logs already have direction
]

INCOMING_PATTERNS = [
    re.compile(r"(?P<time>\d+\.\d+).*RECV"),
    re.compile(r"(?P<time>\d+\.\d+).*IN"),
    re.compile(r"(?P<time>\d+\.\d+).*cell.*incoming", re.IGNORECASE),
    re.compile(r"(?P<time>\d+\.\d+).*\-1"),  # if logs already have direction
]

# ======================
# 1. Extract Shadow data
# ======================
print("[*] Extracting Shadow data...")
with tarfile.open(SHADOW_DATA_TAR, "r:xz") as tar:
    tar.extractall("shadow_data")

shadow_path = Path("shadow_data")

# Create Site_labels
print("[*] Creating site labels...")
for client in os.listdir(conf_hosts_path):
    cmd_file = os.path.join(conf_hosts_path, client, "wget-cmd.txt")
    if os.path.exists(cmd_file):
        with open(cmd_file) as f:
            cmd = f.read().strip()
            # Extract domain from URL - improve this parsing
            try:
                parts = cmd.split()
                url = parts[1] if len(parts) > 1 else parts[0]
                # Extract domain from URL
                if "://" in url:
                    domain = url.split("://")[1].split("/")[0]
                else:
                    domain = url.split("/")[0]
                print(f"Client {client} -> {domain}")
                SITE_LABELS[client] = label_counter
                label_counter += 1
            except Exception as e:
                print(f"Warning: Could not parse command for {client}: {cmd}")

print(f"[+] Created labels for {len(SITE_LABELS)} sites")


# ======================
# 2. Find client log files
# ======================
print("[*] Locating client log files...")
log_files = []

# Look for various log file patterns
for pattern in ["*.log", "*.stdout", "*.stderr", "tor.log", "tor.stdout"]:
    for log in shadow_path.rglob(pattern):
        if CLIENT_KEYWORD in str(log):
            log_files.append(log)

print(f"[+] Found {len(log_files)} potential client log files.")

# ======================
# 3. Enhanced log parsing function
# ======================
def reconstruct_packets_from_stream(log_path, debug=False):
    """
    Reconstruct synthetic packet sequence from stream-level Tor logs.
    Each packet is represented by timestamp * direction.
    """
    packets = []
    first_ts = None

    stream_pattern = re.compile(
        r"created-ts=(?P<created>\d+).*?send=(?P<send_start>\d+)-(?P<send_end>\d+).*?"
        r"recv=(?P<recv_start>\d+)-(?P<recv_end>\d+).*?"
        r"payload-send=(?P<send_bytes>\d+).*?payload-recv=(?P<recv_bytes>\d+)",
        re.IGNORECASE
    )

    try:
        with open(log_path, "r", errors="ignore") as f:
            for line in f:
                match = stream_pattern.search(line)
                if not match:
                    continue

                created_ts = int(match.group("created"))
                send_start = int(match.group("send_start"))
                send_end = int(match.group("send_end"))
                recv_start = int(match.group("recv_start"))
                recv_end = int(match.group("recv_end"))
                send_bytes = int(match.group("send_bytes"))
                recv_bytes = int(match.group("recv_bytes"))

                if first_ts is None:
                    first_ts = created_ts

                # Normalize timestamps
                base_ts = created_ts - first_ts

                # Reconstruct sent packets
                if send_bytes > 0 and send_end >= send_start:
                    pkt_size = 512  # Tor cell size
                    num_pkts = max(1, send_bytes // pkt_size)
                    interval = (send_end - send_start) / num_pkts
                    for i in range(num_pkts):
                        ts = base_ts + send_start + i * interval
                        packets.append((ts, +1))

                # Reconstruct received packets
                if recv_bytes > 0 and recv_end >= recv_start:
                    pkt_size = 512
                    num_pkts = max(1, recv_bytes // pkt_size)
                    interval = (recv_end - recv_start) / num_pkts
                    for i in range(num_pkts):
                        ts = base_ts + recv_start + i * interval
                        packets.append((ts, -1))

                if len(packets) >= MAX_PKTS:
                    break

    except Exception as e:
        print(f"Error reading {log_path}: {e}")
        return np.zeros(MAX_PKTS, dtype=np.float32)

    if not packets:
        print(f"Warning: No packets reconstructed from {log_path}")
        return np.zeros(MAX_PKTS, dtype=np.float32)

    # Sort and normalize timestamps
    packets.sort()
    first_pkt_ts = packets[0][0]
    directional_timing = [(ts - first_pkt_ts) * direction for ts, direction in packets]

    # Pad or truncate
    directional_timing = directional_timing[:MAX_PKTS]
    while len(directional_timing) < MAX_PKTS:
        directional_timing.append(0.0)

    return np.array(directional_timing, dtype=np.float32)

# ======================
# 4. Test parsing on a few files first
# ======================
print("[*] Testing log parsing on sample files...")
test_files = log_files[:3] if len(log_files) > 3 else log_files

for test_file in test_files:
    print(f"\nTesting {test_file}")
    result = reconstruct_packets_from_stream(test_file, debug=True)
    non_zero = np.count_nonzero(result)
    print(f"  Non-zero elements: {non_zero}/{MAX_PKTS}")
    if non_zero > 0:
        print(f"  Range: {result[result != 0].min():.3f} to {result[result != 0].max():.3f}")
        print(f"  Sample values: {result[result != 0][:10]}")

# Ask user to continue
response = input("\nDo the parsing results look correct? Continue with full processing? (y/n): ")
if response.lower() != 'y':
    print("Stopping. Please adjust the regex patterns and try again.")
    exit()

# ======================
# 5. Build dataset
# ======================
print("[*] Building full dataset...")
X = []
y = []
processed_count = 0
failed_count = 0

for log in log_files:
    # Extract client name from path
    # Adjust this based on your actual path structure
    path_parts = log.parts
    client_name = None
    
    # Try to find client name in path
    for part in path_parts:
        if part in SITE_LABELS:
            client_name = part
            break
    
    if client_name is None:
        # Try alternative extraction methods
        for part in path_parts:
            if CLIENT_KEYWORD in part:
                client_name = part
                break
    
    if client_name not in SITE_LABELS:
        print(f"Warning: Could not find label for {log}")
        failed_count += 1
        continue
    
    label = SITE_LABELS[client_name]
    vec = reconstruct_packets_from_stream(log)
    
    # Only add if we got some data
    non_zero = np.count_nonzero(vec)
    if non_zero > 10:  # Require at least 10 events
        X.append(vec)
        y.append(label)
        processed_count += 1
    else:
        print(f"Warning: Too few events in {log} ({non_zero} events)")
        failed_count += 1
    
    if processed_count % 100 == 0:
        print(f"  Processed {processed_count} traces...")

if len(X) == 0:
    print("ERROR: No valid traces found! Check your regex patterns and log format.")
    exit()

X = np.stack(X)
y = np.array(y, dtype=np.int64)

# ======================
# 6. Save dataset and metadata
# ======================
os.makedirs(OUTPUT_DIR, exist_ok=True)
np.save(os.path.join(OUTPUT_DIR, "X.npy"), X)
np.save(os.path.join(OUTPUT_DIR, "y.npy"), y)

# Save additional metadata
metadata = {
    'num_traces': X.shape[0],
    'trace_length': X.shape[1],
    'num_sites': len(set(y)),
    'site_labels': SITE_LABELS,
    'processed_files': processed_count,
    'failed_files': failed_count
}

import json
with open(os.path.join(OUTPUT_DIR, "metadata.json"), "w") as f:
    json.dump(metadata, f, indent=2)

print(f"\n[+] Dataset saved successfully!")
print(f"    Shape: {X.shape}")
print(f"    Traces: {X.shape[0]}")
print(f"    Length: {X.shape[1]} each")
print(f"    Unique sites: {len(set(y))}")
print(f"    Processed: {processed_count} files")
print(f"    Failed: {failed_count} files")
print(f"    Output directory: {OUTPUT_DIR}")

# ======================
# 7. Basic validation
# ======================
print("\n[*] Basic dataset validation:")
print(f"    Label distribution: {np.bincount(y)}")
print(f"    Non-zero ratio: {np.mean(X != 0):.3f}")

# Check for potential issues
if np.mean(X != 0) < 0.1:
    print("WARNING: Very sparse data - check if parsing is working correctly")

if len(set(y)) < 2:
    print("WARNING: Only found traces for one site - check site labeling")

print("\n[+] Processing complete!")