import socket
import time
from hybrid_ssh import handle_key_exchange_client
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
from message import send_message, receive_message

def start_client(host='127.0.0.1', port=2222):
    # 1. Crear socket del cliente
    # Creo socket
        # AF_INET: indica ipv4
        # SOCK_STREAM: tipo TCP
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Intento de iniciar conexión
    try:
        client_socket.connect((host, port))
        print(f"CLIENT: Connected to server at {host}:{port}...")
    except Exception as e:
        print(f"CLIENT: Error connecting to server at {host}:{port}... : {e}")
        return

    # 2. Enviar identificación del cliente
    client_id = "SSH-2.0-OpenSSH_Hybrid\n"
    #client_socket.send(client_id.encode())
    send_message(client_socket, client_id.encode())

    # 3. Recibir identificación del servidor
    #server_id = client_socket.recv(1024).decode()
    server_id = receive_message(client_socket).decode()
    print(f"CLIENT: Identificación del servidor: {server_id}")

    # X. Comprobar compatibilidad de versiones
    ## No es necesario

    # 4. Enviar y recibir cipher-suites soportados
    ## No es necesario ambos van a usar : mlkem768nistp256-sha256

    # 6. Generacion y envio de claves
    client_classic_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    client_classic_public_key  = client_classic_private_key.public_key()
    client_classic_public_key_bytes = client_classic_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    print("CLIENT: Client public key generated.")
    #client_socket.send(client_classic_public_key_bytes)
    send_message(client_socket, client_classic_public_key_bytes)
    print("CLIENT: Client public key sent.")
    
    # 7. Recivir clave publica del servidor
    #server_classic_key_bytes = client_socket.recv(1024)
    server_classic_key_bytes = receive_message(client_socket) 
    if len(server_classic_key_bytes) == 0:
        print("Error: Received empty public key from server!")
    else:
        server_classic_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), server_classic_key_bytes
        )
        print("Client: Received and decoded server public key.")

    # 8. Calcular secreto compartido
    shared_classic_key = client_classic_private_key.exchange(ec.ECDH(), server_classic_key)
    print("CLIENT: Shared key calculated.")

    # 9. Derivar claves (KDF)
    symmetric_classic_key = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
        backend=default_backend()
    ).derive(shared_classic_key)

    print(f"CLIENT: Derived key generated: {symmetric_classic_key.hex()}")

    
    print("CLIENT: Handshake complete. Ready for encrypted communication.")

    time.sleep(2)

    client_socket.close()

if __name__ == "__main__":
    start_client()
