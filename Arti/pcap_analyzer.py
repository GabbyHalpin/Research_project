#!/usr/bin/env python3
"""
PCAP Analyzer - Verify that your PCAP files contain the necessary data
for Deep Fingerprinting format conversion.
"""

from scapy.all import rdpcap, IP, TCP
import sys

def analyze_pcap(pcap_path):
    """Analyze a PCAP file to show timing and direction information."""
    
    print(f"Analyzing: {pcap_path}")
    print("=" * 50)
    
    try:
        packets = rdpcap(pcap_path)
        print(f"Total packets: {len(packets)}")
        
        if len(packets) == 0:
            print("No packets found!")
            return
        
        # Analyze first few packets
        tcp_packets = []
        ip_pairs = set()
        
        for i, packet in enumerate(packets[:10]):  # First 10 packets
            print(f"\nPacket {i+1}:")
            print(f"  Timestamp: {packet.time}")
            
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                print(f"  IP: {src_ip} -> {dst_ip}")
                ip_pairs.add((src_ip, dst_ip))
                
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    payload_len = len(packet[TCP].payload)
                    flags = packet[TCP].flags
                    
                    print(f"  TCP: {src_port} -> {dst_port}")
                    print(f"  Payload length: {payload_len}")
                    print(f"  TCP flags: {flags}")
                    
                    tcp_packets.append({
                        'time': packet.time,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'payload_len': payload_len,
                        'flags': flags
                    })
        
        print(f"\nUnique IP pairs found: {len(ip_pairs)}")
        for pair in list(ip_pairs)[:5]:  # Show first 5 pairs
            print(f"  {pair[0]} <-> {pair[1]}")
        
        # Analyze TCP packets
        tcp_count = sum(1 for p in packets if TCP in p)
        print(f"\nTCP packets: {tcp_count} out of {len(packets)} total")
        
        # Determine likely client/server based on connection initiation
        syn_initiators = {}
        for packet in packets:
            if IP in packet and TCP in packet:
                if packet[TCP].flags & 0x02:  # SYN flag
                    src_ip = packet[IP].src
                    syn_initiators[src_ip] = syn_initiators.get(src_ip, 0) + 1
        
        if syn_initiators:
            likely_client = max(syn_initiators, key=syn_initiators.get)
            print(f"\nLikely client IP: {likely_client}")
            print("SYN initiators:")
            for ip, count in syn_initiators.items():
                print(f"  {ip}: {count} connections")
        
        # Show timing analysis
        if len(tcp_packets) > 1:
            print("\nTiming analysis (first few TCP packets):")
            for i in range(min(5, len(tcp_packets)-1)):
                time_diff = tcp_packets[i+1]['time'] - tcp_packets[i]['time']
                print(f"  Packet {i+1} to {i+2}: {time_diff:.6f} seconds")
        
        # Direction analysis
        if syn_initiators:
            client_ip = likely_client
            outgoing = 0
            incoming = 0
            
            for packet in packets:
                if IP in packet and TCP in packet:
                    if packet[IP].src == client_ip:
                        outgoing += 1
                    else:
                        incoming += 1
            
            print(f"\nDirection analysis (using {client_ip} as client):")
            print(f"  Outgoing packets: {outgoing}")
            print(f"  Incoming packets: {incoming}")
            print(f"  Direction ratio: {outgoing/(outgoing+incoming):.2f} out, {incoming/(outgoing+incoming):.2f} in")
        
        # Check for potential issues
        print("\n" + "=" * 50)
        print("SUITABILITY FOR DEEP FINGERPRINTING:")
        
        if tcp_count < 50:
            print("⚠️  WARNING: Less than 50 TCP packets - may be too short for good classification")
        else:
            print("✓ Sufficient packet count")
        
        if len(ip_pairs) > 2:
            print("⚠️  WARNING: Multiple IP pairs detected - may need filtering")
        else:
            print("✓ Clean connection pattern")
        
        if syn_initiators:
            print("✓ Direction can be determined from connection patterns")
        else:
            print("⚠️  WARNING: No SYN packets found - direction detection may be challenging")
        
        print("✓ Timing information available")
        
    except Exception as e:
        print(f"Error analyzing PCAP: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python pcap_analyzer.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    analyze_pcap(pcap_file)