import socket
from message import send_message, receive_message

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


## Client

def client_classic_exchange(client_socket: socket.socket) -> tuple[ec.EllipticCurvePrivateKey,ec.EllipticCurvePublicKey] :
    
    # Generacion y envio de claves
    client_classic_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    client_classic_public_key = client_classic_private_key.public_key()
    client_classic_public_key_bytes = client_classic_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    send_message(client_socket, client_classic_public_key_bytes)
    print("CLIENT: Client public key sent.")

    server_classic_key_bytes = receive_message(client_socket)
    if len(server_classic_key_bytes) == 0:
        print("Error: Received empty public key from server!")
        return None
    else:
        server_classic_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), server_classic_key_bytes
        )
        print("Client: Received and decoded server public key.")
    
    return client_classic_private_key, server_classic_key


def client_pqc_exchange(client_socket: socket.socket):

    return




## server

def server_classic_exchange(conn: socket.socket) -> tuple[ec.EllipticCurvePrivateKey,ec.EllipticCurvePublicKey]:
    client_classic_key_bytes = receive_message(conn)
    client_classic_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), client_classic_key_bytes
    )
    print("Server: Client public key received.")

    # Generar claves
    server_classic_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    server_classic_public_key = server_classic_private_key.public_key()
    server_classic_public_key_bytes = server_classic_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    print("Server: Server public key generated.")

    # Enviar claves 
    if len(server_classic_public_key_bytes) == 0:
        print("Error: Server public key is empty!")
    else:
        send_message(conn, server_classic_public_key_bytes)
        print("Server: Server public key sent.")
    
    return server_classic_private_key, client_classic_key


def server_pqc_exchange(conn: socket.socket):
    return


