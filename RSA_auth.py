# module containig functions used for RSA keys authorisation/authentification/verification

import csv
from Crypto.Hash import SHA256
from security import RSA_key_read

PEERS_FILE_PATH = "./RSA_key_exchange/"


def auth_RSA_public_key(public_key : bytes):
    public_key_hash = SHA256.new(public_key)

    try:
        with open(PEERS_FILE_PATH + "peers.csv", "r", newline="") as peers_file:
            reader = csv.reader(peers_file, delimiter=":")
            for row in reader:
                if row:
                    if row[0] == public_key_hash.hexdigest():   # Key is found in file, hashes are the same
                        index = int(row[1])
                        NV_key = RSA_key_read(index)
                        if NV_key == public_key:    # Both keys are also identical
                            return True
    except FileNotFoundError:
        print("peers.csv not found!")
    
    return False