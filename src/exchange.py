import socket
import oqs

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
    """
    Realiza el intercambio de claves PQC en el lado del cliente.
    """
    with oqs.KeyEncapsulation("Kyber768") as kem:
        # Generar clave pública y privada del cliente
        public_key = kem.generate_keypair()
        send_message(client_socket, public_key)
        print("CLIENT: Client pqc public key sent.")
        
        # Recibir la clave encapsulada y un mensaje del servidor
        ciphertext = receive_message(client_socket)
        print("Client: PQC encapsulated key received.")
        shared_secret = kem.decap_secret(ciphertext)  # Decapsular clave secreta
        print("Client: PQC key decapsulated.")
        
        return shared_secret




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
    """
    Realiza el intercambio de claves PQC en el lado del servidor.
    """
    with oqs.KeyEncapsulation("Kyber768") as kem:
        # Recibir la clave pública del cliente
        client_public_key = receive_message(conn)
        print("Server: Client pqc public key received.")
        
        # Encapsular la clave secreta utilizando la clave pública del cliente
        ciphertext, shared_secret = kem.encap_secret(client_public_key)
        print("Server: pqc key encapsulated.")
        send_message(conn, ciphertext)
        print("Server: PQC encapsulated key sent.")
        
        return shared_secret



