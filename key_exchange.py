import socket
from tpm_security import OWN_KEY_NV_INDEX
from security import *
from RSA_auth import auth_RSA_public_key


SOCKET_RECEIVE_SIZE = 4096
SOCKET_INT_SIZE = 4


# Exchanges keys between the two devices
# returns host key and peer public key
def RSA_public_key_exchange(gateway_socket : socket.socket):
    # get IP addresses of devices
    source_address = gateway_socket.getsockname()[0]
    dest_address = gateway_socket.getpeername()[0]

    RSA_key_own = RSA_key_read_and_load(OWN_KEY_NV_INDEX)
    print("RSA key imported")
    RSA_key_bytes_public_own = RSA_key_export(RSA_key_own.public_key())
    print("Extracted public key as bytes from own key")

    # transfer the keys between gateways
    if(source_address <= dest_address):  # source sends the key firsts
        # source sends its public key to dest
        gateway_socket.sendall(RSA_key_bytes_public_own)
        print("Sent \"RSA_key_bytes_public_own\"")
        # then recieves the public key from dest
        RSA_key_bytes_public_peer = gateway_socket.recv(SOCKET_RECEIVE_SIZE)
        print("Recieved \"RSA_key_bytes_public_peer\"")

    else:   # dest sends the key first
        # source recieves the public key from dest
        RSA_key_bytes_public_peer = gateway_socket.recv(SOCKET_RECEIVE_SIZE)
        print("Recieved \"RSA_key_bytes_public_peer\"")
        # then sends its public key to dest
        gateway_socket.sendall(RSA_key_bytes_public_own)
        print("Sent RSA_key_bytes_public_own")

    # VERIFY if RSA_key_public_peer here is known by host (is authorised)
    if auth_RSA_public_key(RSA_key_bytes_public_peer) == True:  # Key is authorized
        RSA_key_public_peer = RSA.import_key(RSA_key_bytes_public_peer)
        print("RSA_peer_public key is authorized!")
        print("Imported \"RSA_key_public_peer\" from \"RSA_key_bytes_public_peer\"")
        return (RSA_key_own, RSA_key_public_peer)
    else:
        print("Peer public key is NOT authorized!. Stopping key exchange protocol.")
        return None
    

# Exchanges public ECC keys (signed with RSA) between devices
# returns established shared secret
def DH_key_exchange(gateway_socket : socket.socket, own_RSA_key : RSA.RsaKey, peer_RSA_public_key : RSA.RsaKey):
    # get IP addresses of devices
    source_address = gateway_socket.getsockname()[0]
    dest_address = gateway_socket.getpeername()[0]

    # Generate ephemeral ECC key
    ECC_key_own =  ECC_key_gen()
    print("ECC key generated!")
    ECC_key_own_public_bytes = ECC_key_export(ECC_key_own.public_key())

    ECC_key_own_public_bytes_signed = RSA_sign(own_RSA_key, ECC_key_own_public_bytes)

    # transfer the keys between gateways
    if(source_address <= dest_address):  # source sends the key firsts
        # source sends its public key to dest
        gateway_socket.sendall(ECC_key_own_public_bytes_signed)
        print("Sent \"ECC_key_own_public_bytes_signed\"")
        # then recieves the public key from dest
        ECC_key_peer_public_bytes_signed = gateway_socket.recv(SOCKET_RECEIVE_SIZE)
        print("Recieved \"ECC_key_peer_public_bytes_signed\"")
    else:   # dest sends the key first
        # source recieves the public key from dest
        ECC_key_peer_public_bytes_signed = gateway_socket.recv(SOCKET_RECEIVE_SIZE)
        print("Recieved \"ECC_key_peer_public_bytes_signed\"")
        # then sends its public key to dest
        gateway_socket.sendall(ECC_key_own_public_bytes_signed)
        print("Sent \"ECC_key_own_public_bytes_signed\"")

    try:
        ECC_key_peer_public_bytes = RSA_verify(peer_RSA_public_key, ECC_key_peer_public_bytes_signed)
    except ValueError:
        print("**** !!! RSA signature is not authentic !!! ****")
        return None

    print("RSA signature is authentic")
    ECC_key_peer_public = ECC_public_key_import(ECC_key_peer_public_bytes)
    print("Imported \"ECC_key_peer_public\"")

    shared_key = ECDHE_key_agreement(ECC_key_own, ECC_key_peer_public)
    print("Established shared key")

    return shared_key


def key_exchange_routine(gateway_socket : socket.socket):
    result = RSA_public_key_exchange(gateway_socket)
    if(result != None):
        return DH_key_exchange(gateway_socket, result[0], result[1])
    else:
        return None
