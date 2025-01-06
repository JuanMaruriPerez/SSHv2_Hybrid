import time

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend

from connection import client_start_connection,client_protocol_identification
from exchange import client_classic_exchange


def start_client(host: str = '127.0.0.1', port: int = 2222):

    ## Connection
    
    # Crear socket del cliente
    client_socket = client_start_connection(host,port)

    # Enviar identificación del cliente y Recibir identificación del servidor
    client_protocol_identification("SSH-2.0-OpenSSH_Hybrid",client_socket)


    ## Exchange

    # Enviar y recibir cipher-suites soportados
    ## No es necesario ambos van a usar : mlkem768nistp256-sha256

    # Intercambio de claves ECDH
    client_classic_private_key, server_classic_key = client_classic_exchange(client_socket)

    # Calcular secreto compartido
    shared_classic_key = client_classic_private_key.exchange(ec.ECDH(), server_classic_key)
    print("CLIENT: Shared key calculated.")

    # Derivar claves (KDF)
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
