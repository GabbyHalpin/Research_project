import os
import sys
import subprocess
from nacl.public import PrivateKey

def generate_exit_nodes():
    # Generate the exit nodes (8 additional ones to have a total of 10)
    current_file_directory = os.path.dirname(os.path.abspath(__file__))
    for i in 8:
        exitpath = current_file_directory + "/exit" + (i+2)
        os.mkdir(exitpath)
        os.chdir(exitpath)
        os.open("torrc", "w")

        with open("torrc-defaults", "w") as f:
            f.write('%include ../../../conf/tor.common.torrc\n'
                '%include ../../../conf/tor.relay.torrc\n'
                '%include ../../../conf/tor.exit.torrc')
            
        keyspath = exitpath + "/keys"

        os.mkdir(keyspath)
        os.chdir(keyspath)

        result = subprocess.run(['bash', 'openssl genpkey -algorithm RSA -out secret_id_key.pem -pkeyopt rsa_keygen_bits:1024'], capture_output=True, text=True)
        result = subprocess.run(['bash', 'openssl genpkey -algorithm RSA -out secret_onion_key.pem -pkeyopt rsa_keygen_bits:1024'], capture_output=True, text=True)

        sk = PrivateKey.generate()
        with open("secret_onion_key_ntor", "wb") as f:
            f.write(sk.encode())  # 32 bytes exactly

        os.chdir(exitpath)

        result = subprocess.run(
        "tor --DataDirectory {} --ListFingerprint | grep -oE '[0-9A-F]{{40}}'".format(exitpath),
        shell=True,
        capture_output=True,
        text=True,
        check=True,
        )
        fingerprint = result.stdout.strip()
        
        with open("fingerprint", "w") as f:
            filename = "exit" + (i+2) + " " + fingerprint
            f.write(filename)

        os.chdir(current_file_directory)



def generate_relay_nodes():
    # Generate the relay nodes (8 additional ones to have a total of 10)
    current_file_directory = os.path.dirname(os.path.abspath(__file__))
    for i in 96:
        exitpath = current_file_directory + "/exit" + (i+4)
        os.mkdir(exitpath)
        os.chdir(exitpath)
        os.open("torrc", "w")

        with open("torrc-defaults", "w") as f:
            f.write('%include ../../../conf/tor.common.torrc\n'
                '%include ../../../conf/tor.relay.torrc\n'
                '%include ../../../conf/tor.exit.torrc')
            
        keyspath = exitpath + "/keys"

        os.mkdir(keyspath)
        os.chdir(keyspath)

        result = subprocess.run(['bash', 'openssl genpkey -algorithm RSA -out secret_id_key.pem -pkeyopt rsa_keygen_bits:1024'], capture_output=True, text=True)
        result = subprocess.run(['bash', 'openssl genpkey -algorithm RSA -out secret_onion_key.pem -pkeyopt rsa_keygen_bits:1024'], capture_output=True, text=True)

        sk = PrivateKey.generate()
        with open("secret_onion_key_ntor", "wb") as f:
            f.write(sk.encode())  # 32 bytes exactly

        os.chdir(exitpath)

        result = subprocess.run(
        "tor --DataDirectory {} --ListFingerprint | grep -oE '[0-9A-F]{{40}}'".format(exitpath),
        shell=True,
        capture_output=True,
        text=True,
        check=True,
        )
        fingerprint = result.stdout.strip()
        
        with open("fingerprint", "w") as f:
            filename = "exit" + (i+4) + " " + fingerprint
            f.write(filename)

        os.chdir(current_file_directory)



