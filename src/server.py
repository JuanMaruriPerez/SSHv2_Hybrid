import time

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend

from connection import server_start_connection,server_protocol_identification, server_start_running
from exchange import server_classic_exchange

def start_server(host: str = '127.0.0.1', port: int = 2222):

    ## Connection

    # Crear socket del servidor
    server_socket = server_start_running(host,port)

    # Crear socket de conexion
    conn, addr = server_start_connection(server_socket)
    print(f"Server: Connection established with {addr}")

    # Enviar identificación del cliente y Recibir identificación del servidor
    server_protocol_identification("SSH-2.0-OpenSSH_Hybrid",conn)


    ## Exchange

    # Enviar y recibir cipher-suites soportados
    ## No es necesario ambos van a usar : mlkem768nistp256-sha256

    # Intercambio de claves ECDH
    server_classic_private_key, client_classic_key = server_classic_exchange(conn)

    # Calcular secreto compartido
    shared_classic_key = server_classic_private_key.exchange(ec.ECDH(), client_classic_key)
    print("Server: Shared key calculated.")

    # Derivar claves (KDF)
    symmetric_classic_key = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
        backend=default_backend()
    ).derive(shared_classic_key)

    print(f"Server: Derived key generated: {symmetric_classic_key.hex()}")

    print("Server: Handshake complete. Ready for encrypted communication.")    

    time.sleep(2)

    conn.close()
    server_socket.close()

if __name__ == "__main__":
    start_server()
