import socket
from tpm_security import *
from security import *
from sys import byteorder as sys_byteorder


DEFAULT_SOCKET_RECIEVE_SIZE = 2048
SOCKET_RECIEVE_INT_SIZE = 4

RNG_ERROR_CODE = b'00000000'


# Exchange keys between the two devices
# returns host key and peer public key
def RSA_public_key_exchange(gateway_socket : socket.socket):
    # get IP addresses of devices
    source_address = gateway_socket.getsockname()[0]
    dest_address = gateway_socket.getpeername()[0]

    RSA_key_own = RSA_key_load()
    print("RSA key imported")
    RSA_key_bytes_public_own = RSA_key_export(RSA_key_own.public_key())
    print("Extracted public key as bytes from own key")

    # transfer the keys between gateways
    if(source_address <= dest_address):  # source sends the key firsts
        # source sends its public key to dest
        gateway_socket.send(len(RSA_key_bytes_public_own).to_bytes(SOCKET_RECIEVE_INT_SIZE, 'big'))
        gateway_socket.send(RSA_key_bytes_public_own)
        print("Sent \"RSA_key_bytes_public_own\"")
        # then recieves the public key from dest
        RSA_key_bytes_public_peer_size_bytes = gateway_socket.recv(SOCKET_RECIEVE_INT_SIZE)
        RSA_key_bytes_public_peer_size = int.from_bytes(RSA_key_bytes_public_peer_size_bytes, 'big')
        RSA_key_bytes_public_peer = gateway_socket.recv(RSA_key_bytes_public_peer_size)
        print("Recieved \"RSA_key_bytes_public_peer\"")

    else:   # dest sends the key first
        # source recieves the public key from dest
        RSA_key_bytes_public_peer_size_bytes = gateway_socket.recv(SOCKET_RECIEVE_INT_SIZE)
        RSA_key_bytes_public_peer_size = int.from_bytes(RSA_key_bytes_public_peer_size_bytes, 'big')
        RSA_key_bytes_public_peer = gateway_socket.recv(RSA_key_bytes_public_peer_size)
        print("Recieved \"RSA_key_bytes_public_peer\"")
        # then sends its public key to dest
        gateway_socket.send(len(RSA_key_bytes_public_own).to_bytes(SOCKET_RECIEVE_INT_SIZE, 'big'))
        gateway_socket.send(RSA_key_bytes_public_own)
        print("Sent RSA_key_bytes_public_own")

    RSA_key_public_peer = RSA.import_key(RSA_key_bytes_public_peer)
    print("Imported \"RSA_key_public_peer\" from \"RSA_key_bytes_public_peer\"")

    return (RSA_key_own, RSA_key_public_peer)


def random_number_exchange(gateway_socket : socket.socket):
    RANDOM_NUM_SIZE = 4

    # get IP addresses of devices
    source_address = gateway_socket.getsockname()[0]
    dest_address = gateway_socket.getpeername()[0]

    # use RNG to determine who generates the key generated with TPM
    random_num_source = get_random(RANDOM_NUM_SIZE)
    if(random_num_source == None):  # if RNG failed set RNG_ERROR_CODE
        random_num_source = RNG_ERROR_CODE
    print("Generated random number for transfer")

    if(source_address <= dest_address):     # source sends the number first
        gateway_socket.send(random_num_source)
        print("Sent own random number")
        random_num_dest = gateway_socket.recv(RANDOM_NUM_SIZE)
        print("Recieved peer random number")
    else:                                   # dest sends the number first
        random_num_dest = gateway_socket.recv(RANDOM_NUM_SIZE)
        print("Recieved peer random number")
        gateway_socket.send(random_num_source)
        print("Sent own random number")

    return (random_num_source, random_num_dest)


def symmetric_key_exchange(gateway_socket : socket.socket, own_RSA_key : RSA.RsaKey, peer_RSA_public_key : RSA.RsaKey):
    # get IP addresses of devices
    source_address = gateway_socket.getsockname()[0]
    dest_address = gateway_socket.getpeername()[0]

    # exchange random numbers
    (random_num_source, random_num_dest) = random_number_exchange(gateway_socket)
    print("Random numbers exchange successful!")

    if(random_num_source != RNG_ERROR_CODE and random_num_dest != RNG_ERROR_CODE): # Very fine random numbers, on both sides!
        if(int.from_bytes(random_num_source, sys_byteorder) <= int.from_bytes(random_num_dest, sys_byteorder)):     # source generates the key
            # generate symmetric key
            sym_key = AES_key_gen()
            print("AES key generation successful!")

            if(sym_key != None):     # encrypt symmetric key with RSA
                sym_key_enc = RSA_encrypt_and_sign(peer_RSA_public_key, own_RSA_key, sym_key)
                print("AES key encrypted with RSA")
                gateway_socket.send(len(sym_key_enc).to_bytes(SOCKET_RECIEVE_INT_SIZE, 'big')) # send encrypted symmetric key size
                gateway_socket.send(sym_key_enc) # send encrypted symmetric key
                print("AES encrypted key sent")
            else:
                print("*** Host unable to generate AES key")
                return None

        else:   # source recieves the key
            # recieve encrypted symmetric key
            sym_key_enc_size_bytes = gateway_socket.recv(SOCKET_RECIEVE_INT_SIZE)
            sym_key_enc_size = int.from_bytes(sym_key_enc_size_bytes, 'big')
            sym_key_enc = gateway_socket.recv(sym_key_enc_size)
            print("AES encrypted key recieved")
            # decrypt symmetric key with RSA
            try:
                sym_key = RSA_decrypt_and_verify(own_RSA_key, peer_RSA_public_key, sym_key_enc)
                print("AES key decrypted with RSA")
            except (ValueError):
                print("**** !!! Signature is not authentic !!! ****")
                sym_key = None

    else:   # They rigged the RNGs, they're trying to destroy our program! | --> use backup with smaller ip address
        if(random_num_source == RNG_ERROR_CODE):
            print("*** Host unable to generate random number using TPM")
        elif(random_num_dest == RNG_ERROR_CODE):
            print("*** Peer unable to generate random number using TPM")

        print("** Using backup exchange procedure (IP address comparison)")

        if(source_address <= dest_address):     # source generates the key
            # generate symmetric key
            sym_key = AES_key_gen()
            print("AES key generation successful!")

            if(sym_key != None):     # encrypt symmetric key with RSA
                sym_key_enc = RSA_encrypt_and_sign(peer_RSA_public_key, own_RSA_key, sym_key)
                print("AES key encrypted with RSA")
                gateway_socket.send(len(sym_key_enc).to_bytes(SOCKET_RECIEVE_INT_SIZE, 'big')) # send encrypted symmetric key size
                gateway_socket.send(sym_key_enc) # send encrypted symmetric key
                print("AES encrypted key sent")
            else:
                print("*** Host unable to generate AES key")
                return None

        else:   # source recieves the key
            # recieve encrypted symmetric key
            sym_key_enc_size_bytes = gateway_socket.recv(SOCKET_RECIEVE_INT_SIZE)
            sym_key_enc_size = int.from_bytes(sym_key_enc_size_bytes, 'big')
            sym_key_enc = gateway_socket.recv(sym_key_enc_size)
            print("AES encrypted key recieved")
            # decrypt symmetric key with RSA
            try:
                sym_key = RSA_decrypt_and_verify(own_RSA_key, peer_RSA_public_key, sym_key_enc)
                print("AES key decrypted with RSA")
            except (ValueError):
                print("**** !!! Signature is not authentic !!! ****")
                sym_key = None

    return sym_key


def key_exchange_routine(gateway_socket : socket.socket):
    result = RSA_public_key_exchange(gateway_socket)
    if(result != None):
        return symmetric_key_exchange(gateway_socket, result[0], result[1])
    else:
        return None
