import gateway_common
import socket
import threading
import utils
from key_exchange import key_exchange_routine, SOCKET_RECEIVE_SIZE
from security import *
from Perf_test import latency_test
from time import sleep, time
from parse_args import parse_args_main


exit_flag = False
reset_flag = False


# source is the client | dest is the server gateway
def forward_source_dest(args, source_socket : socket.socket, dest_socket : socket.socket, sym_key : bytes):
    global reset_flag

    while not exit_flag and not reset_flag:
        try:
            data = source_socket.recv(SOCKET_RECEIVE_SIZE)
            if not data:
                raise ConnectionError
        except TimeoutError:
            if exit_flag or reset_flag:
                break
            continue
        except ConnectionError:
            reset_flag = True
            print("Source socket (client) error or disconnection. Resetting connection...")
            break

        if not args.disable_rekeying:
            comb_data = gateway_common.rekey_sender(data)
        else:
            comb_data = data

        # Change sym_key with the new key
        if not args.disable_rekeying:
            new_sym_key = gateway_common.rekey_get_new_key()
            if new_sym_key is not None:
                if sym_key != new_sym_key:
                    sym_key = new_sym_key
                    print("\t* New symmetric key applied! *")

        print("\nReceived from source (pre-comb): ", data)
        print("Sent rekey flag: ", comb_data[0])
        print("To send to destination (post-comb): ", comb_data, "\n")

        if args.measure_perf:
            #### Start measuring latency
            start_time = latency_test.perf_counter()
            enc_data = AES_encrypt_and_digest(sym_key, comb_data)
            #### Stop measuring latency
            stop_time = latency_test.perf_counter()
            [latency_test.encrpyt_average_latency, latency_test.encrypt_average_counter] = latency_test.add_to_average(latency_test.encrpyt_average_latency, latency_test.encrypt_average_counter, stop_time - start_time)
        else:
            enc_data = AES_encrypt_and_digest(sym_key, comb_data)

        try:
            dest_socket.sendall(enc_data)
        except(BrokenPipeError):
            reset_flag = True
            print("*** Destination socket (server gateway) is broken (BrokenPipeError). Resetting connection... ***")

    if exit_flag or reset_flag:
        try:
            dest_socket.sendall(AES_encrypt_and_digest(sym_key, gateway_common.SOCKET_RESET_MESSAGE))
        except(BrokenPipeError):
            print("*** Unable to send resset message to destination socket (server gateway) - BrokenPipeError ***")



# source is the client | dest is the server gateway
def forward_dest_source(args, source_socket : socket.socket, dest_socket : socket.socket, sym_key : bytes):
    global reset_flag

    while not exit_flag and not reset_flag:
        try:
            enc_data = dest_socket.recv(SOCKET_RECEIVE_SIZE)
            if not enc_data:
                raise ConnectionError
        except TimeoutError:
            if exit_flag or reset_flag:
                break
            continue
        except ConnectionError:
            reset_flag = True
            print("Destination socket (server gateway) error or disconnection. Resetting connection...")
            dest_socket.sendall(AES_encrypt_and_digest(sym_key, gateway_common.SOCKET_RESET_MESSAGE))
            break

        # Change sym_key with the new key
        if not args.disable_rekeying:
            new_sym_key = gateway_common.rekey_get_new_key()
            if new_sym_key is not None:
                if sym_key != new_sym_key:
                    sym_key = new_sym_key
                    print("\t* New symmetric key applied! *")

        try:
            try:
                if args.measure_perf:
                    #### Start measuring latency
                    start_time = latency_test.perf_counter()
                    comb_data = AES_decrypt_and_verify(args, sym_key, enc_data)
                    #### Stop measuring latency
                    stop_time = latency_test.perf_counter()
                    [latency_test.decrypt_average_latency, latency_test.decrypt_average_counter] = latency_test.add_to_average(latency_test.decrypt_average_latency, latency_test.decrypt_average_counter, stop_time - start_time)
                else:
                    comb_data = AES_decrypt_and_verify(args, sym_key, enc_data)
            except(ValueError):     # Peer might have failed to change to new key => revert to old key as well and try again
                if gateway_common.old_sym_key is not None:
                    comb_data = AES_decrypt_and_verify(args, gateway_common.old_sym_key, enc_data)     # If old_sym_key exists, try to decrypt using it
                    gateway_common.rekey_revert_flag = True
                    print("*** Rekeying failed! Reverting to old key! ***")
                else:
                    raise ValueError
            
            if not args.disable_rekeying:
                try:
                    data = gateway_common.rekey_receiver(sym_key, comb_data)
                except ValueError:
                    print("*** Rekey flag is incorrect! ***\nResetting connection...")
                    data = gateway_common.SOCKET_RESET_MESSAGE  # Reset connection if rekey flag is incorrect (because the nature of the plaintext cannot be determined)
            else:
                data = comb_data
            
            print("\nReceived from destination (pre-slpit): ", comb_data)
            print("Received rekey flag: ", comb_data[0])
            print("Received from destination (post-split): ", data, "\n")

            if(data == gateway_common.SOCKET_RESET_MESSAGE):
                reset_flag = True
                print("Reset message received!")
                break

            source_socket.sendall(data)
        except(ValueError):
            print("**** !!! Message tampered or key is incorrect !!! ****")
        except(BrokenPipeError):
            reset_flag = True
            print("*** Source socket (client) is broken (BrokenPipeError). Resetting connection... ***")


def handle_transfer(args, source_socket : socket.socket, dest_socket : socket.socket, sym_key : bytes):
    forward_source_dest_thread = threading.Thread(target = forward_source_dest, args = (args, source_socket, dest_socket, sym_key))
    forward_dest_source_thread = threading.Thread(target = forward_dest_source, args = (args, source_socket, dest_socket, sym_key))

    forward_source_dest_thread.start()
    forward_dest_source_thread.start()

    # Main thread waits here after starting data forwarding child threads
    # Wait for KeyboardInterrupt (Ctrl+C)
    try:
        while forward_source_dest_thread.is_alive() or forward_dest_source_thread.is_alive():
            sleep(1)
    except(KeyboardInterrupt):
        global exit_flag
        exit_flag = True
        print("Closing program at user request (Ctrl+C)...")

    forward_source_dest_thread.join()
    forward_dest_source_thread.join()

    print("Threads closed successfully.")

    if args.measure_perf:
        latency_test.export_to_file()


def main(): 
    host_ip = utils.get_host_ip()   # host_ip = '192.168.50.80'
    host_port = 502

    source_ip = '192.168.50.241'
    source_port = 502

    dest_ip = '192.168.50.81'
    dest_port = 502

    # Handle run arguments
    args = parse_args_main(__file__)

    if args.host:
        host_ip = args.host
    if args.host_ip:
        host_ip = args.host_ip
    if args.dest:
        dest_ip = args.dest
    if args.dest_ip:
        dest_ip = args.dest_ip
    if args.set_rekey_interval:
        gateway_common.REKEY_TIME = args.set_rekey_interval

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host_ip, host_port))
    server_socket.listen(5)

    while not exit_flag:
        global reset_flag
        reset_flag = False

        print(f"[*] Listening on {host_ip}:{host_port}")

        source_socket, source_addr = server_socket.accept()
        print(f"[*] Accepted connection from client(source): {source_addr}")

        dest_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dest_socket.connect((dest_ip, dest_port))
        print(f"[*] Established connection to server(destination): {(dest_ip, dest_port)}")
        
        if args.measure_perf:
            #### Start measuring latency
            start_time = latency_test.perf_counter()
            # do key exchange here
            sym_key = key_exchange_routine(dest_socket) # for server gateway use 'source_socket' | for client gateway use 'dest_socket'
            #### Stop measuring latency
            stop_time = latency_test.perf_counter()
            latency_test.key_exchange_latency = stop_time - start_time
        else:
            # do key exchange here
            sym_key = key_exchange_routine(dest_socket) # for server gateway use 'source_socket' | for client gateway use 'dest_socket'

        # If sym_key generated & transferred successfully proceed with normal data handling
        if(sym_key != None):
            # Set sockets to non-blocking mode
            source_socket.settimeout(gateway_common.SOCKET_TIMEOUT)
            dest_socket.settimeout(gateway_common.SOCKET_TIMEOUT)

            # Set current time as time for last rekey event
            gateway_common.rekey_switch_time = int(time())

            handle_transfer(args, source_socket, dest_socket, sym_key)
        else:
            print("Key exchange error")
        
        # Try to shutdown sockets and then close them
        try:
            source_socket.shutdown(socket.SHUT_RDWR)
        except(OSError):
            print("*** Source socket (client) already closed at the other end ***")

        try:
            dest_socket.shutdown(socket.SHUT_RDWR)
        except(OSError):
            print("*** Destination socket (server gateway) already closed at the other end ***")

        source_socket.close()
        dest_socket.close()

    print("Program closed successfully!")


if __name__ == "__main__":
    main()
