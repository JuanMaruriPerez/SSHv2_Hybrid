import time

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend

from connection import server_start_connection,server_protocol_identification, server_start_running
from exchange import server_classic_exchange,server_pqc_exchange
from hybridation import derive_hybrid_key

def start_server(host: str = '127.0.0.1', port: int = 2222):

    server_protocol_id = "SSH-2.0-OpenSSH_Hybrid"

    ## Connection

    # Crear socket del servidor
    server_socket = server_start_running(host,port)

    # Crear socket de conexion
    conn, addr = server_start_connection(server_socket)
    print(f"Server: Connection established with {addr}")

    # Enviar identificación del cliente y Recibir identificación del servidor
    server_protocol_identification(server_protocol_id,conn)


    ## Exchange

    # Enviar y recibir cipher-suites soportados
    ## No es necesario ambos van a usar : mlkem768nistp256-sha256

    # Intercambio de claves ECDH
    server_classic_private_key, client_classic_key = server_classic_exchange(conn)

    # Intercambio de claves KEM
    symmetric_pqc_key = server_pqc_exchange(conn)

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

    print(f"Server: Derived classic key generated: {symmetric_classic_key.hex()}")
    print(f"Server: Derived PQC key decapsulated: {symmetric_pqc_key.hex()}")

      
    # Waiting for both exchanges to finish . . . 
    time.sleep(2)

    # TO-DO hybridacion de claves
    master_key = derive_hybrid_key(
        symmetric_classic_key,
        symmetric_pqc_key,
        server_protocol_id.encode(), # Pasamos bytes en vez de str
        16
        )
    print(f"Server: Master Key: {master_key.hex()}")
    ##
    

    ## TO_DO encio mensaje encriptado
    ##

    print("Server: Handshake complete. Ready for encrypted communication.")  

    conn.close()
    server_socket.close()

if __name__ == "__main__":
    start_server()
