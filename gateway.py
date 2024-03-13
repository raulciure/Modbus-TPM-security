import socket
import threading

def forward_source_dest(source_socket, dest_socket):
    while True:
        data = source_socket.recv(1024)
        if not data:
            break
        print(f"Recieved from source: {data.decode('utf-8')}")
        dest_socket.send(data)

def forward_dest_source(source_socket, dest_socket):
    while True:
        data = dest_socket.recv(1024)
        if not data:
            break
        print(f"Recieved from destination: {data.decode('utf-8')}")
        source_socket.send(data)
        
def handle_transfer(source_socket, dest_socket):
    forward_source_dest_thread = threading.Thread(target = forward_source_dest, args = (source_socket, dest_socket))
    forward_dest_source_thread = threading.Thread(target = forward_dest_source, args = (source_socket, dest_socket))

    forward_source_dest_thread.start()
    forward_dest_source_thread.start()

    forward_source_dest_thread.join()
    forward_dest_source_thread.join()

def main(): 
    host_ip = '192.168.1.1'
    host_port = 502

    source_ip = '192.168.1.42'
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

        dest_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dest_socket.connect((dest_ip, dest_port))
        print(f"[*] Established connection to server(destination): {(dest_ip, dest_port)}")
        
        handle_transfer(source_socket, dest_socket)

        source_socket.close()
        dest_socket.close()

main()
