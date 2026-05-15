import csv
from os import remove
from src.modbus_tpm_security.tpm_security import delete_TPM_nv
from src.modbus_tpm_security.rsa_key_exchange.rsa_key_exchange_common import PEERS_FILE_FULL_PATH


UPPER_INDEX_RANGE = 10


# Delete keys from used indexes
try:
    with open(PEERS_FILE_FULL_PATH, "r", newline="") as peers_file:
        reader = csv.reader(peers_file, delimiter=":")
        for row in reader:
            if row:
                print("Deleting key from TPM NV index: ", row[1])
                if delete_TPM_nv(int(row[1])) == True:
                    print("\tKey deleted successfully!")
                else:
                    print("\tKey delete ERROR!")

    # Remove peers.csv file
    remove(PEERS_FILE_FULL_PATH)
except FileNotFoundError:
    print("peers.csv not found!")

    print("Do you want to begin serial purge of NV indexes? [Y/n]")
    user_input = input("> ")

    if user_input == "Y" or user_input == "":
        print("Beginning serial purge of NV indexes...")

        for index in range(1, UPPER_INDEX_RANGE + 1):
            print("Deleting key from TPM NV index: ", index)
            if delete_TPM_nv(index) == True:
                print("\tKey deleted successfully!")
            else:
                print("\tKey delete ERROR!")
        
        print()
        
