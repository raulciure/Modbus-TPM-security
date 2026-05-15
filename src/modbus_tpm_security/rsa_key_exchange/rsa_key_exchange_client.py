import socket
from src.modbus_tpm_security.rsa_key_exchange.rsa_key_exchange_common import RSA_public_key_exchange
from src.modbus_tpm_security.parse_args import parse_args_RSA_key_exchange


def RSA_key_exchange_client():
    dest_ip = '192.168.50.81'
    dest_port = 502

    # Handle run arguments
    args = parse_args_RSA_key_exchange(__file__)

    if args.dest:
        dest_ip = args.dest
    if args.dest_ip:
        dest_ip = args.dest_ip

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((dest_ip, dest_port))
    print(f"[*] Established connection to server: {(dest_ip, dest_port)}")

    RSA_public_key_exchange(server_socket)      # Exchange RSA public key

    server_socket.close()


if __name__ == "__main__":
    RSA_key_exchange_client()