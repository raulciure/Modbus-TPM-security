import socket
import threading
from key_exchange import key_exchange_routine, SOCKET_RECEIVE_SIZE
from security import *


# source is the client gateway | dest is the server
def forward_source_dest(source_socket, dest_socket, sym_key):
    while True:
        enc_data = source_socket.recv(SOCKET_RECEIVE_SIZE)
        if not enc_data:
            break

        try:
            data = AES_decrypt_and_verify(sym_key, enc_data)
            print("Received from destination: ", data)
            
            dest_socket.send(data)
        except(ValueError):
            print("**** !!! Message tampered or key is incorrect !!! ****")


# source is the client gateway | dest is the server
def forward_dest_source(source_socket, dest_socket, sym_key):
    while True:
        data = dest_socket.recv(SOCKET_RECEIVE_SIZE)
        if not data:
            break

        print("Received from source: ", data)

        enc_data = AES_encrypt_and_digest(sym_key, data)
        
        source_socket.send(enc_data)


def handle_transfer(source_socket, dest_socket, sym_key):
    forward_source_dest_thread = threading.Thread(target = forward_source_dest, args = (source_socket, dest_socket, sym_key))
    forward_dest_source_thread = threading.Thread(target = forward_dest_source, args = (source_socket, dest_socket, sym_key))

    forward_source_dest_thread.start()
    forward_dest_source_thread.start()

    forward_source_dest_thread.join()
    forward_dest_source_thread.join()


def main(): 
    host_ip = '192.168.50.81'
    host_port = 502

    source_ip = '192.168.50.80'
    source_port = 502

    dest_ip = '192.168.50.96'
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
        else:
            print("Key exchange error")

        source_socket.close()
        dest_socket.close()


if __name__ == "__main__":
    main()
