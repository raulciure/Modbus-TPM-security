import socket
from Crypto.Hash import SHA256
import csv

import sys
sys.path.insert(1, "../")

from parse_args import parse_args_RSA_key_exchange

from tpm_security import store_TPM_nv, OWN_KEY_NV_INDEX
from security import RSA_key_read_and_load, RSA_key_export, RSA_key_serialize
from key_exchange import SOCKET_INT_SIZE, SOCKET_RECEIVE_SIZE


def store_peer_RSA_public_key(peer_public_key_bytes : bytes):
    ID_counter = 1 # NV index starts from 1 for peer keys (host keys on index offset 0)
    max_ID = 0
    found_flag = False

    key_hash = SHA256.new(peer_public_key_bytes)

    # Find how many IDs are already in use
    try:
        with open("peers.csv", "r", newline="") as peers_file:
            # Read peers from file into dictionary & check if peer public key is already in the list
            reader = csv.reader(peers_file, delimiter=":")
            for row in reader:
                if row:
                    if int(row[1]) > max_ID:    # Get max ID in file
                        max_ID = int(row[1])
                    if row[0] == key_hash.hexdigest():
                        found_flag = True
                        break
                    ID_counter += 1
    except FileNotFoundError:
        print("peers.csv not found. Creating file...")

    if found_flag == False:     # Public key is not already known
        new_ID = max_ID + 1
        # Store serialized DER formated peer_public_key in TPM NV memory at next available index
        result = store_TPM_nv(RSA_key_serialize(peer_public_key_bytes), new_ID)
        if result == True:
            print("Peer public key successfully stored in TPM NV memory!")
            # Store the key hash & ID in dictionary CSV list
            with open("peers.csv", "a", newline="") as peers_file:
                # Write new entry into peers_file
                writer = csv.writer(peers_file, delimiter=":")
                writer.writerow((key_hash.hexdigest(), new_ID))
        else:
            print("Error storing peer_public_key in TPM NV!")
    else:
        print("Peer public key is already known!")


def RSA_public_key_exchange(conn_socket : socket.socket):
    source_address = conn_socket.getsockname()[0]
    dest_address = conn_socket.getpeername()[0]

    RSA_key_own = RSA_key_read_and_load(OWN_KEY_NV_INDEX)
    print("RSA key imported")
    RSA_key_bytes_public_own = RSA_key_export(RSA_key_own.public_key())
    print("Extracted public key as bytes from own key")

    # transfer the keys between devices
    if(source_address <= dest_address):  # host sends the key first
        # host sends its public key to peer
        conn_socket.sendall(RSA_key_bytes_public_own)
        print("Sent own RSA public key!")

        # then recieves the public key from peer
        RSA_key_bytes_public_peer = conn_socket.recv(SOCKET_RECEIVE_SIZE)
        print("Recieved peer RSA public key!")
    else:   # peer sends the key first
        # host receives the public key from peer
        RSA_key_bytes_public_peer = conn_socket.recv(SOCKET_RECEIVE_SIZE)
        print("Recieved peer RSA public key!")

        # then sends its public key to peer
        conn_socket.sendall(RSA_key_bytes_public_own)
        print("Sent own RSA public key!")

    # Store peer key in TPM
    store_peer_RSA_public_key(RSA_key_bytes_public_peer)