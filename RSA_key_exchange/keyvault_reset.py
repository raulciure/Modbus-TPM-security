from os import remove
import csv

import sys
sys.path.insert(1, "../")
from tpm_security import delete_TPM_nv


PEERS_FILE_NAME = "peers.csv"

# Delete keys from used indexes
try:
    with open(PEERS_FILE_NAME, "r", newline="") as peers_file:
        reader = csv.reader(peers_file, delimiter=":")
        for row in reader:
            if row:
                print("Deleting key from TPM NV index: ", row[1])
                if delete_TPM_nv(int(row[1])) == True:
                    print("\tKey deleted successfully!")
                else:
                    print("\tKey delete ERROR!")
except FileNotFoundError:
    print("peers.csv not found!")

# Remove peers.csv file
remove(PEERS_FILE_NAME)
