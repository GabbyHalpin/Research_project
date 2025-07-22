import os, pickle
import numpy as np

def build_dataset(root_dir, split, defense):
    X, y = [], []
    base = os.path.join(root_dir, defense, split)
    for site_id, site in enumerate(sorted(os.listdir(base))):
        site_dir = os.path.join(base, site)
        for pcap in os.listdir(site_dir):
            seq = parse_pcap(os.path.join(site_dir, pcap))
            X.append(seq)
            y.append(site_id)
    X = np.vstack(X)    # shape [n, 5000]
    y = np.array(y)     # shape [n]
    return X, y

# Example for train/NoDef:
X_train_nodef, y_train_nodef = build_dataset("traces", "train", "NoDef")

# Save:
with open("X_train_NoDef.pkl", "wb") as f:
    pickle.dump(X_train_nodef, f)
with open("y_train_NoDef.pkl", "wb") as f:
    pickle.dump(y_train_nodef, f)
