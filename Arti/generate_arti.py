import os
import subprocess
import re
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
        print(os.path.exists(exit_dir))
        print(exit_dir)
        keys_dir = os.path.join(exit_dir, "keys")
        os.makedirs(keys_dir, exist_ok=True)
        print(os.path.exists(keys_dir))

        # write empty torrc (Tor needs the file, even if all config is in torrc-defaults)
        open(os.path.join(exit_dir, "torrc"), "w").close()

        # compose torrc-defaults
        conf_dir = os.path.abspath(os.path.join(cwd, "../../conf"))
        print(conf_dir)
        print(os.path.exists(conf_dir))
        with open(os.path.join(exit_dir, "torrc-defaults"), "w") as fd:
            fd.write(f"%include {os.path.join(conf_dir, 'tor.common.torrc')}\n")
            fd.write(f"%include {os.path.join(conf_dir, 'tor.relay.torrc')}\n")
            fd.write(f"%include {os.path.join(conf_dir, 'tor.exit.torrc')}\n")

        print(os.path.exists(os.path.join(conf_dir, "tor.common.torrc")))

        print(os.path.exists(os.path.join(exit_dir, "torrc-defaults")))
        
        # generate RSA keys
        gen_rsa_key(os.path.join(keys_dir, "secret_id_key.pem"))
        gen_rsa_key(os.path.join(keys_dir, "secret_onion_key.pem"))

        # generate ntor key
        sk = PrivateKey.generate()
        with open(os.path.join(keys_dir, "secret_onion_key_ntor"), "wb") as f:
            f.write(sk.encode())

        # launch Tor as an exit relay, printing its fingerprint
        
        result = subprocess.run(
        [
            "tor",
            "-f", os.path.join(exit_dir, "torrc-defaults"),
            "--RunAsDaemon", "0",
            "--ClientOnly", "0",
            "--ExitRelay", "1",
            "--ORPort", "auto",
            "--ExitPolicy", "accept *:*",
            "--DataDirectory", exit_dir,
            "--Log", "notice stdout",
        ],
        cwd=exit_dir,
        capture_output=True,
        text=True,
        check=True
        )

        m = re.search(r"[0-9A-F]{40}", result.stdout)
        if not m:
            raise RuntimeError(f"No fingerprint found:\n{result.stdout}")
        fp = m.group(0)

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

        open(os.path.join(relay_dir, "torrc"), "w").close()

        conf_dir = os.path.abspath(os.path.join(relay_dir, "../../../conf"))
        with open(os.path.join(relay_dir, "torrc-defaults"), "w") as fd:
            fd.write(f"%include {os.path.join(conf_dir, 'tor.common.torrc')}\n")
            fd.write(f"%include {os.path.join(conf_dir, 'tor.relay.torrc')}\n")
            fd.write(f"%include {os.path.join(conf_dir, 'tor.exit.torrc')}\n")

        print(os.path.exists(os.path.join(relay_dir, "../../../conf/tor.common.torrc")))


        gen_rsa_key(os.path.join(keys_dir, "secret_id_key.pem"))
        gen_rsa_key(os.path.join(keys_dir, "secret_onion_key.pem"))

        sk = PrivateKey.generate()
        with open(os.path.join(keys_dir, "secret_onion_key_ntor"), "wb") as f:
            f.write(sk.encode())

        # launch Tor as a non-exit relay
        result = subprocess.run(
            [
                "tor",
                "-f", os.path.join(relay_dir, "torrc-defaults"),
                "--RunAsDaemon", "0",
                "--ClientOnly", "0",
                "--ExitRelay", "0",
                "--ORPort", "auto",
                "--DataDirectory", relay_dir,
                "--Log", "notice stdout",
            ],
            cwd=relay_dir,
            capture_output=True,
            text=True,
            check=True
        )

        m = re.search(r"[0-9A-F]{40}", result.stdout)
        if not m:
            raise RuntimeError(f"No fingerprint found:\n{result.stdout}")
        fp = m.group(0)

        with open(os.path.join(relay_dir, "fingerprint"), "w") as f:
            f.write(f"relay{i+5} {fp}")

def main():
    generate_exit_nodes()
    generate_relay_nodes()

if __name__ == "__main__":
    main()
