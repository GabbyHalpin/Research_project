import os

SITE_LABELS = {}
label_counter = 0
conf_hosts_path = "conf/hosts"

for client in os.listdir(conf_hosts_path):
    cmd_file = os.path.join(conf_hosts_path, client, "wget-cmd.txt")
    if os.path.exists(cmd_file):
        with open(cmd_file) as f:
            cmd = f.read().strip()
            # extract domain from URL
            domain = cmd.split()[1]  # naive split for "wget URL"
            SITE_LABELS[client] = label_counter
            label_counter += 1
