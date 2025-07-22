from scapy.all import rdpcap
import numpy as np

def parse_pcap(path):
    pkts = rdpcap(path)
    seq = []
    client_ip = "10.0.0.1"   # your Shadow client IP
    client_port = 9050
    for p in sorted(pkts, key=lambda p: p.time):
        if p.haslayer("TCP"):
            if p["IP"].src == client_ip and p["TCP"].sport == client_port:
                seq.append(+1)
            elif p["IP"].dst == client_ip and p["TCP"].dport == client_port:
                seq.append(-1)
    # pad or truncate
    if len(seq) >= 5000:
        return np.array(seq[:5000], dtype=np.int8)
    else:
        return np.array(seq + [0]*(5000-len(seq)), dtype=np.int8)
