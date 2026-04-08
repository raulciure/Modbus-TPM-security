from RSA_key_exchange_common import socket, RSA_public_key_exchange, parse_args_RSA_key_exchange
import utils


def RSA_key_exchange_server():
    host_ip = utils.get_host_ip()   # host_ip = '192.168.50.81'
    host_port = 502

    # Handle run arguments
    args = parse_args_RSA_key_exchange(__file__)

    if args.host:
        host_ip = args.host
    if args.host_ip:
        host_ip = args.host_ip

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host_ip, host_port))
    server_socket.listen(20)

    print(f"[*] Listening on {host_ip}:{host_port}")

    try:
        while True:     # Process, in order, all the connections from clients
            print("[*] Waiting for client connection...")

            client_socket, client_address = server_socket.accept()
            print(f"[*] Accepted connection from client: {client_address}")

            # Exchange RSA public key
            RSA_public_key_exchange(client_socket)

            client_socket.close()
    except KeyboardInterrupt:
        server_socket.close()
        print("Program terminated by user")
        exit()
  

if __name__ == "__main__":
    RSA_key_exchange_server()