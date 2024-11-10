from security import RSA_key_read, RSA_key_load
from Crypto.Hash import SHA256
import csv

PEERS_FILE_NAME = "peers.csv"

counter = 1

with open(PEERS_FILE_NAME, "r", newline="") as peers_file:
    reader = csv.reader(peers_file, delimiter=":")
    for row in reader:
        public_key_hash_file = row[0]
        id = int(row[1])

        print(row[0] + ":" + row[1])
        print()
        
        encoded_public_key = RSA_key_read(counter)

        public_key_hash = SHA256.new(encoded_public_key)
        if public_key_hash_file == public_key_hash.hexdigest():
            print("Hash from file with computed hash MATCH!")
        else:
            print("Hashes don't match!")

        public_key = RSA_key_load(encoded_public_key)

        if public_key.has_private() == True:
            print("This is an RSA public-private key pair!")
        else:
            print("This is an RSA public key only!")

        print("Public key: " + bytes(public_key).hex())
        print()

        counter += 1