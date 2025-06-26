import socket
import threading
import Perf_test.latency_test
from key_exchange import key_exchange_routine, SOCKET_RECEIVE_SIZE
from security import *
from Perf_test import latency_test


# source is the client | dest is the server gateway
def forward_source_dest(source_socket, dest_socket, sym_key):
    while True:
        data = source_socket.recv(SOCKET_RECEIVE_SIZE)
        if not data:
            break
        
        print("Received from source: ", data)

        #### Start measuring latency
        start_time = latency_test.perf_counter()
        enc_data = AES_encrypt_and_digest(sym_key, data)
        #### Stop measuring latency
        stop_time = latency_test.perf_counter()
        [latency_test.encrpyt_average_latency, latency_test.encrypt_average_counter] = latency_test.add_to_average(latency_test.encrpyt_average_latency, latency_test.encrypt_average_counter, stop_time - start_time)

        dest_socket.send(enc_data)


# source is the client | dest is the server gateway
def forward_dest_source(source_socket, dest_socket, sym_key):
    while True:
        enc_data = dest_socket.recv(SOCKET_RECEIVE_SIZE)
        if not enc_data:
            break

        try:
            #### Start measuring latency
            start_time = latency_test.perf_counter()
            data = AES_decrypt_and_verify(sym_key, enc_data)
            #### Stop measuring latency
            stop_time = latency_test.perf_counter()
            [latency_test.decrypt_average_latency, latency_test.decrypt_average_counter] = latency_test.add_to_average(latency_test.decrypt_average_latency, latency_test.decrypt_average_counter, stop_time - start_time)
            print("Received from destination: ", data)

            source_socket.send(data)
        except(ValueError):
            print("**** !!! Message tampered or key is incorrect !!! ****")


def handle_transfer(source_socket, dest_socket, sym_key):
    forward_source_dest_thread = threading.Thread(target = forward_source_dest, args = (source_socket, dest_socket, sym_key))
    forward_dest_source_thread = threading.Thread(target = forward_dest_source, args = (source_socket, dest_socket, sym_key))

    forward_source_dest_thread.start()
    forward_dest_source_thread.start()

    forward_source_dest_thread.join()
    forward_dest_source_thread.join()

    latency_test.export_to_file()


def main(): 
    host_ip = '192.168.50.80'
    host_port = 502

    source_ip = '192.168.1.241'
    source_port = 502

    dest_ip = '192.168.50.81'
    dest_port = 502

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host_ip, host_port))
    server_socket.listen(5)

    print(f"[*] Listening on {host_ip}:{host_port}")
    
    while True:
        source_socket, source_addr = server_socket.accept()
        print(f"[*] Accepted connection from client(source): {source_addr}")

        dest_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dest_socket.connect((dest_ip, dest_port))
        print(f"[*] Established connection to server(destination): {(dest_ip, dest_port)}")
        
        #### Start measuring latency
        start_time = latency_test.perf_counter()
        # do key exchange here
        sym_key = key_exchange_routine(dest_socket) # for server gateway use 'source_socket' | for client gateway use 'dest_socket'
        #### Stop measuring latency
        stop_time = latency_test.perf_counter()
        latency_test.key_exchange_latency = stop_time - start_time
        # If sym_key generated & transferred successfully proceed with normal data handling
        if(sym_key != None):
            handle_transfer(source_socket, dest_socket, sym_key)
        else:
            print("Key exchange error")

        source_socket.close()
        dest_socket.close()


if __name__ == "__main__":
    main()
