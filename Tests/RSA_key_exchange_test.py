from Crypto.Hash import SHA256
import csv

import sys
sys.path.insert(1, "../")

from security import RSA_key_read, RSA_key_load, RSA_key_export


PEERS_FILE_NAME = "peers.csv"

id = 1

try:
    with open(PEERS_FILE_NAME, "r", newline="") as peers_file:
        reader = csv.reader(peers_file, delimiter=":")
        for row in reader:
            public_key_hash_file = row[0]
            id = int(row[1])

            print(row[0] + ":" + row[1])
            print()

            encoded_public_key = RSA_key_read(id)

            public_key_hash = SHA256.new(encoded_public_key)
            if public_key_hash_file == public_key_hash.hexdigest():
                print("Hash from file MATCHES with computed hash!")
            else:
                print("Hashes don't match!")

            public_key = RSA_key_load(encoded_public_key)

            if public_key.has_private() == True:
                print("This is an RSA public-private key pair!")
            else:
                print("This is an RSA public key only!")

            print("Public key: " + RSA_key_export(public_key).hex())
            print()

            id += 1
except FileNotFoundError:
    print("File " + PEERS_FILE_NAME + " does not exist! Run RSA_key_exchange first!")