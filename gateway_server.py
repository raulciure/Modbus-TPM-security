import socket
import threading
from key_exchange import key_exchange_routine, SOCKET_RECIEVE_INT_SIZE
from security import *


# source is the client gateway | dest is the server
def forward_source_dest(source_socket, dest_socket, sym_key):
    while True:
        # nonce = source_socket.recv(SOCKET_RECIEVE_SIZE)       # recieve nonce
        # ciphertext = source_socket.recv(SOCKET_RECIEVE_SIZE)  # recieve ciphertext
        # MAC_tag = source_socket.recv(SOCKET_RECIEVE_SIZE)     # recieve MAC tag
        # if not nonce or not ciphertext or not MAC_tag:
        #     break
        enc_data_size_bytes = source_socket.recv(SOCKET_RECIEVE_INT_SIZE)
        enc_data_size = int.from_bytes(enc_data_size_bytes, 'big')
        enc_data = source_socket.recv(enc_data_size)
        if not enc_data:
            break

        # decrypt data
        # enc_data = (ciphertext, MAC_tag)
        try:
            # data = AES_decrypt_and_verify(sym_key, nonce, enc_data)
            data = AES_decrypt_and_verify(sym_key, enc_data)
            print(f"Recieved from destination: {data.decode('utf-8')}")

            # dest_socket.send(len(data).to_bytes(SOCKET_RECIEVE_INT_SIZE, 'big'))
            dest_socket.send(data)
        except(ValueError):
            print("**** !!! Message tampered or key is incorrect !!! ****")


# source is the client gateway | dest is the server
def forward_dest_source(source_socket, dest_socket, sym_key):
    while True:
        # data_size = dest_socket.recv(SOCKET_RECIEVE_INT_SIZE)
        data = dest_socket.recv(1024)
        if not data:
            break
        print(f"Recieved from source: {data.decode('utf-8')}")

        # encrypt data
        # (nonce, enc_data) = AES_encrypt_and_digest(sym_key, data)
        enc_data = AES_encrypt_and_digest(sym_key, data)

        # source_socket.send(nonce)       # send nonce
        # source_socket.send(enc_data[0]) # send ciphertext
        # source_socket.send(enc_data[1]) # send MAC tag
        source_socket.send(len(enc_data).to_bytes(SOCKET_RECIEVE_INT_SIZE, 'big')) # enc_data_size
        source_socket.send(enc_data)


def handle_transfer(source_socket, dest_socket, sym_key):
    forward_source_dest_thread = threading.Thread(target = forward_source_dest, args = (source_socket, dest_socket, sym_key))
    forward_dest_source_thread = threading.Thread(target = forward_dest_source, args = (source_socket, dest_socket, sym_key))

    forward_source_dest_thread.start()
    forward_dest_source_thread.start()

    forward_source_dest_thread.join()
    forward_dest_source_thread.join()


def main(): 
    host_ip = '192.168.1.2'
    host_port = 502

    source_ip = '192.168.1.1'
    source_port = 502

    dest_ip = '192.168.1.84'
    dest_port = 502

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host_ip, host_port))
    server_socket.listen(5)

    print(f"[*] Listening on {host_ip}:{host_port}")
    
    while True:
        source_socket, source_addr = server_socket.accept()
        print(f"[*] Accepted connection from client(source): {source_addr}")

        # do key exchange here
        sym_key = key_exchange_routine(source_socket) # for server gateway use 'source_socket' | for client gateway use 'dest_socket'

        dest_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dest_socket.connect((dest_ip, dest_port))
        print(f"[*] Established connection to server(destination): {(dest_ip, dest_port)}")
        
        # If sym_key generated successfully proceed with normal data handling
        if(sym_key != None):
            handle_transfer(source_socket, dest_socket, sym_key)

        source_socket.close()
        dest_socket.close()


if __name__ == "__main__":
    main()