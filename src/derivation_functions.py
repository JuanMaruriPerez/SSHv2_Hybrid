"""

## Client

def key_hybridation(client_classic_private_key, server_classic_key):
    shared_classic_key = client_classic_private_key.exchange(ec.ECDH(), server_classic_key)
    print("CLIENT: Shared key calculated.")

    symmetric_classic_key = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
        backend=default_backend()
    ).derive(shared_classic_key)

    print(f"CLIENT: Derived key generated: {symmetric_classic_key}")
    return symmetric_classic_key




## Server 

def key_hybridation(server_classic_private_key, client_classic_key):
    shared_classic_key = server_classic_private_key.exchange(ec.ECDH(), client_classic_key)
    print("Server: Shared key calculated.")

    symmetric_classic_key = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
        backend=default_backend()
    ).derive(shared_classic_key)

    print(f"Server: Derived key generated: {symmetric_classic_key}")
    return symmetric_classic_key

    """