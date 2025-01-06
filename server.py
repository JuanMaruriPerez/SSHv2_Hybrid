import socket
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
from message import send_message, receive_message

def start_server(host='127.0.0.1', port=2222):
    # 1. Crear socket del servidor
    # Creo socket general que recibe conexiones
        # AF_INET: indica ipv4
        # SOCK_STREAM: tipo TCP
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))    # bind(): asocia el socket con host y port y lo hace publico
    server_socket.listen(1)    # listen(1): indica que se establezcan max 1 conexion a la vez
    print(f"Server: Server listening on {host}:{port}...")

    # 2. Aceptar conexión del cliente y recibir identificación del cliente
    # accept(): bloquea server hasta cliente se conecta
        # conn: es el socket particular con el cliente
        # addr: direccion dir ip y puerto
    conn, addr = server_socket.accept()
    print(f"Server: Connection established with {addr}")

    #client_id = conn.recv(1024).decode()
    client_id = receive_message(conn) 
    print(f"Server: Identificación del cliente: {client_id}")

    # X. Comprobar compatibilidad de versiones
    ## No es necesario
   
    # 3. Enviar identificación del servidor
    server_id = "SSH-2.0-OpenSSH_Hybrid\n"
    #conn.send(server_id.encode())
    send_message(conn, server_id.encode())

    # 5. Envio cipher-suites soportados
    ## No es necesario ambos van a usar : mlkem768nistp256-sha256

    # 6. Recibir claves cliente
    #client_classic_key_bytes = conn.recv(1024)
    client_classic_key_bytes = receive_message(conn)
    client_classic_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), client_classic_key_bytes
    )
    print("Server: Client public key received.")

    # 7a. Generacion claves
    server_classic_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    server_classic_public_key = server_classic_private_key.public_key()
    server_classic_public_key_bytes = server_classic_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    print("Server: Server public key generated.")

    # 7b. Enviar claves 
    #conn.send(server_classic_public_key_bytes)
    if len(server_classic_public_key_bytes) == 0:
        print("Error: Server public key is empty!")
    else:
        send_message(conn, server_classic_public_key_bytes)
        print("Server: Server public key sent.")

    # 8. Calcular secreto compartido
    shared_classic_key = server_classic_private_key.exchange(ec.ECDH(), client_classic_key)
    print("Server: Shared key calculated.")

    # 9. Derivar claves (KDF)
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
