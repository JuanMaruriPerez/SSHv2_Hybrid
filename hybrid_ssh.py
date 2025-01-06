from cryptography.hazmat.primitives.asymmetric import  ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import oqs

# 1 means classical --> ECDH
# 2 means post-cuantic --> KEM

def generate_shared_secrets(C_PK1, S_PK1, S_CT2, client_private_key):
    # Obtener K_CL (intercambio clásico con ECDH)
    K_CL = perform_ecdh(C_PK1, S_PK1)  # Función para hacer ECDH y obtener K_CL

    # Obtener K_PQ (intercambio post-cuántico con KEM)
    K_PQ = decapsulate_pq_kem(S_CT2, client_private_key)  # Función para decapsular S_CT2 con la clave privada PQ
    
    return K_CL, K_PQ


def perform_ecdh(C_PK1, S_PK1):
    # TO-DO: Lógica para el intercambio ECDH y obtención de la clave compartida K_CL
    K_CL = 0
    ##
    return K_CL  # Placeholder para tu implementación real


def decapsulate_pq_kem(S_CT2, client_private_key):
    # TO-DO: Lógica para decapsular la clave post-cuántica a partir de S_CT2
    K_PQ = 0
    ##
    return K_PQ 


def handle_key_exchange_server(conn):
    print("Starting key exchange (server)...")

    # Recibir C_INIT del cliente (C_PK2 || C_PK1)
    C_INIT = conn.recv(2048)  # Tamaño adecuado para C_PK2 + C_PK1
    C_PK2 = C_INIT[:768]  # Asumiendo que ML-KEM-768 tiene 768 bytes
    C_PK1 = C_INIT[768:]

    ## Clásico
    classical_private_key = ec.generate_private_key(ec.SECP256R1())
    classical_public_key = classical_private_key.public_key()

    # Serializa clave publica en formato PEM adecuado para enviarla
    classical_public_bytes = classical_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    with oqs.KeyEncapsulation("MLKEM768") as pqc:
        pqc_public_key = pqc.generate_keypair()
        pqc_private_key = pqc.export_secret_key()  # Usamos export_secret_key() para obtener la clave secreta
        ciphertext = pqc.encapsulate(C_PK2)  # Cifrado del KEM para el cliente

    # Concatenar S_CT2 y S_PK1 como S_REPLY
    S_REPLY = ciphertext + classical_public_bytes

    # Enviar la respuesta al cliente
    conn.sendall(classical_public_bytes)  # Enviar la clave pública del servidor (S_PK1)
    conn.sendall(S_REPLY)  # Enviar la concatenación S_CT2 + S_PK1

    # Hibridación de claves: K_CL y K_PQ
    hybrid_key = hybrid_key_derivation(classical_private_key, C_PK1, pqc_private_key, classical_public_bytes, ciphertext)

    return hybrid_key



def handle_key_exchange_client( conn):
    print("Starting key exchange (client)...")

    # Clásico
    classical_private_key = ec.generate_private_key(ec.SECP256R1())
    classical_public_key = classical_private_key.public_key()

    # Serializa clave publica en formato PEM adecuado para enviarla
    classical_public_bytes = classical_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # PQC
    with oqs.KeyEncapsulation("MLKEM768") as pqc:
        pqc_public_key = pqc.generate_keypair()
        pqc_private_key = pqc.export_secret_key()

    C_INIT = pqc_public_key + classical_public_bytes
    conn.sendall(C_INIT)

    # Recibir claves del servidor
    server_public_key = conn.recv(1024)
    server_ciphertext = conn.recv(1024)

    # Desempaquetar la respuesta del servidor
    S_PK1 = server_public_key  # S_PK1 del servidor (clave pública ECDH del servidor)
    S_CT2 = server_ciphertext  # S_CT2 del servidor (cifrado del KEM)

    # Hibridación de claves: K_CL y K_PQ
    hybrid_key = hybrid_key_derivation(classical_private_key, classical_public_bytes, pqc_private_key, S_PK1, S_CT2)

    return hybrid_key



def hybrid_key_derivation(classical_private_key, classical_client_key, pqc_client_key, classical_server_key, pqc_server_ciphertext):
    # Derivación de K_CL utilizando ECDH
    classical_shared_secret = classical_private_key.exchange(ec.ECDH(), classical_server_key)

    # Derivación de K_PQ utilizando el descifrado del KEM
    with oqs.KeyEncapsulation("MLKEM768") as pqc:
        pqc_private_key = pqc_client_key
        pqc_shared_secret = pqc.decapsulate(pqc_server_ciphertext)

    # Concatenar K_CL y K_PQ
    combined_key_material = classical_shared_secret + pqc_shared_secret

    # Usar SHA-256 para derivar la clave final
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"ssh-hybrid",
        iterations=100000,
    )
    return kdf.derive(combined_key_material)
