import socket

from message import send_message, receive_message
from exceptions import ProtocolMismatchError

    

## Client

def client_start_connection(host: str, port: int) -> socket.socket:
    # Creo socket
        # AF_INET: indica ipv4
        # SOCK_STREAM: tipo TCP
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((host, port))
        print(f"CLIENT: Connected to server at {host}:{port}...")
    except Exception as e:
        print(f"CLIENT: Error connecting to server at {host}:{port}... : {e}")
        return None
    return client_socket


def client_protocol_identification(client_protocol_id: str, client_socket: socket.socket):
    # 2. Enviar identificación del cliente  
    send_message(client_socket, client_protocol_id.encode())
    # 3. Recibir identificación del servidor
    server_protocol_id = receive_message(client_socket).decode()

    if server_protocol_id != client_protocol_id : raise ProtocolMismatchError(f"Protocol mismatch between: '{server_protocol_id}' != '{client_protocol_id}'")
    print(f"CLIENT: Identificación del servidor: {server_protocol_id}")




## Server

def server_start_running(host: str, port: int) -> socket.socket:
    # Creo socket
        # AF_INET: indica ipv4
        # SOCK_STREAM: tipo TCP
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))    # bind(): asocia el socket con host y port y lo hace publico
    server_socket.listen(1) # listen(1): indica que se establezcan max 1 conexion a la vez

    print(f"Server: Server listening on {host}:{port}...")

    return server_socket


def server_start_connection(server_socket: socket.socket) -> tuple[socket.socket, ]:

    conn, addr = server_socket.accept()

    return conn, addr


def server_protocol_identification(server_protocol_id: str, server_socket: socket):
    # 2. Enviar identificación del cliente  
    send_message(server_socket, server_protocol_id.encode())
    # 3. Recibir identificación del servidor
    client_protocol_id = receive_message(server_socket).decode()

    if client_protocol_id != server_protocol_id : raise ProtocolMismatchError(f"Protocol mismatch between: '{server_protocol_id}' != '{client_protocol_id}'")
    print(f"Server: Identificación del servidor: {client_protocol_id}")








