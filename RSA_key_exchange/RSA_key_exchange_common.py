import socket
from tpm_security import read_TPM_nv, store_TPM_nv, OWN_KEY_NV_INDEX
from security import RSA_key_load, RSA_key_export
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import csv

SOCKET_RECEIVE_SIZE = 4096


def store_peer_RSA_public_key(peer_public_key_bytes):
    ID_counter = 0

    # Find how many IDs are already in use
    with open("peers.csv", "r") as peers_file:
        # Read peers from file into dictionary
        reader = csv.reader(peers_file, delimiter=":")
        for row in reader:
            ID_counter += 1

    # Store DER formated peer_public_key in TPM NV memory at next available index
    result = store_TPM_nv(peer_public_key_bytes, ID_counter)
    if result == True:
        print("Peer public key successfully stored in TPM NV memory!")
        # Store the key ID in dictionary CSV list
        # MAC address CANNOT be obtained easely => an option : use hash of the public key as dictionary key
        with open("peers.csv", "w") as peers_file:
            # Write new entry into peers_file
            key_hash = SHA256.new(peer_public_key_bytes)

            writer = csv.writer(peers_file, delimiter=":")
            writer.writerow((key_hash.hexdigest(), ID_counter))
    else:
        print("Error storing peer_public_key in TPM NV!")


def RSA_public_key_exchange(conn_socket : socket):
    source_address = conn_socket.getsockname()[0]
    dest_address = conn_socket.getpeername()[0]

    RSA_key_own = RSA_key_load(OWN_KEY_NV_INDEX)
    print("RSA key imported")
    RSA_key_bytes_public_own = RSA_key_export(RSA_key_own.public_key())
    print("Extracted public key as bytes from own key")

    # transfer the keys between devices
    if(source_address <= dest_address):  # host sends the key firsts
        # host sends its public key to peer
        conn_socket.send(RSA_key_bytes_public_own)
        print("Sent own RSA public key!")

        # then recieves the public key from peer
        RSA_key_bytes_public_peer = conn_socket.recv(SOCKET_RECEIVE_SIZE)
        print("Recieved peer RSA public key!")

    else:   # peer sends the key first
        # host receives the public key from peer
        RSA_key_bytes_public_peer = conn_socket.recv(SOCKET_RECEIVE_SIZE)
        print("Recieved peer RSA public key!")

        # then sends its public key to peer
        conn_socket.send(RSA_key_bytes_public_own)
        print("Sent own RSA public key!")

    # Store peer key in TPM
    store_peer_RSA_public_key(RSA_key_bytes_public_peer)