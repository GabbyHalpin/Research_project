import os
import subprocess
import re
import time
import tempfile
import shutil
from nacl.public import PrivateKey

def gen_rsa_key(filename):
    subprocess.run(
        ["openssl", "genpkey",
         "-algorithm", "RSA",
         "-out", filename,
         "-pkeyopt", "rsa_keygen_bits:1024"],
        check=True
    )

def generate_exit_nodes():
    cwd = os.path.dirname(os.path.abspath(__file__))
    for i in range(7):
        # build paths
        exit_dir = os.path.join(cwd, f"exit{i+3}")
        os.makedirs(exit_dir, exist_ok=True)
        keys_dir = os.path.join(exit_dir, "keys")
        os.makedirs(keys_dir, exist_ok=True)
            
        # compose torrc-defaults
        conf_dir = os.path.abspath(os.path.join(cwd, "../../conf"))
        with open(os.path.join(exit_dir, "torrc-defaults"), "w") as fd:
            fd.write(f"%include {os.path.join(conf_dir, 'tor.common.torrc')}\n")
            fd.write(f"%include {os.path.join(conf_dir, 'tor.relay.torrc')}\n")
            fd.write(f"%include {os.path.join(conf_dir, 'tor.exit.torrc')}\n")

                # write empty torrc (Tor needs the file, even if all config is in torrc-defaults)
        with open(os.path.join(exit_dir, "torrc"), "w") as fd:
            #fd.write(f"UseDefaultConfiguration 0\n")
            fd.write(f"%include {os.path.join(exit_dir, 'torrc-defaults')}\n")

        # launch Tor as an exit relay, printing its fingerprint

        try:
            result = get_fingerprint_from_tor(exit_dir)

        except subprocess.CalledProcessError as e:
            print("=== TOR STDOUT ===")
            print(e.stdout)
            print("=== TOR STDERR ===")
            print(e.stderr)
            raise


        fp_path = os.path.join(exit_dir, "fingerprint")
        if not os.path.exists(fp_path):
            raise RuntimeError(f"No fingerprint file found in {exit_dir}")
        with open(fp_path, "r") as f:
            fp_line = f.read().strip()
            fp = fp_line.split()[1] if ' ' in fp_line else fp_line


        # write out “exitX <FINGERPRINT>”
        with open(os.path.join(exit_dir, "fingerprint"), "w") as f:
            f.write(f"exit{i+3} {fp}")

def generate_relay_nodes():
    cwd = os.path.dirname(os.path.abspath(__file__))
    for i in range(5):
        relay_dir = os.path.join(cwd, f"relay{i+5}")
        os.makedirs(relay_dir, exist_ok=True)
        keys_dir = os.path.join(relay_dir, "keys")
        os.makedirs(keys_dir, exist_ok=True)

        conf_dir = os.path.abspath(os.path.join(relay_dir, "../../../conf"))
        with open(os.path.join(relay_dir, "torrc-defaults"), "w") as fd:
            fd.write(f"%include {os.path.join(conf_dir, 'tor.common.torrc')}\n")
            fd.write(f"%include {os.path.join(conf_dir, 'tor.relay.torrc')}\n")
            fd.write(f"%include {os.path.join(conf_dir, 'tor.non-exit.torrc')}\n")

                        # write empty torrc (Tor needs the file, even if all config is in torrc-defaults)
        with open(os.path.join(relay_dir, "torrc"), "w") as fd:
            #fd.write(f"UseDefaultConfiguration 0\n")
            fd.write(f"%include {os.path.join(relay_dir, 'torrc-defaults')}\n")

        # launch Tor as a non-exit relay
        try:
            result = get_fingerprint_from_tor(relay_dir)

        except subprocess.CalledProcessError as e:
            print("=== TOR STDOUT ===")
            print(e.stdout)
            print("=== TOR STDERR ===")
            print(e.stderr)
            raise

        fp_path = os.path.join(relay_dir, "fingerprint")
        if not os.path.exists(fp_path):
            raise RuntimeError(f"No fingerprint file found in {relay_dir}")
        with open(fp_path, "r") as f:
            fp_line = f.read().strip()
            fp = fp_line.split()[1] if ' ' in fp_line else fp_line


        with open(os.path.join(relay_dir, "fingerprint"), "w") as f:
            f.write(f"relay{i+5} {fp}")


def get_fingerprint_from_tor(datadir: str) -> str:
    torrc_path = os.path.join(datadir, "torrc")
    tor_proc = subprocess.Popen(
        ["tor", "-f", torrc_path, "--DataDirectory", datadir],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    fingerprint = None
    try:
        for _ in range(100):
            time.sleep(0.1)
            if tor_proc.poll() is not None:
                print("Tor exited early with code:", tor_proc.returncode)
                break

            fp_path = os.path.join(datadir, "fingerprint")
            if os.path.exists(fp_path):
                with open(fp_path) as f:
                    line = f.read().strip()
                    fingerprint = line.split()[1] if ' ' in line else line
                    break
    finally:
        tor_proc.terminate()
        try:
            tor_proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            tor_proc.kill()

        if tor_proc.stderr:
            print("=== Tor STDERR ===")
            print(tor_proc.stderr.read())

        if tor_proc.stdout:
            print("=== Tor STDOUT ===")
            print(tor_proc.stdout.read())

    if not fingerprint:
        raise RuntimeError(f"No fingerprint found after launching Tor in {datadir}")
    
    return fingerprint



def main():
    generate_exit_nodes()
    generate_relay_nodes()

if __name__ == "__main__":
    main()
