### Message 


## Send 

def send_all(conn, data):
    total_sent = 0
    data_len = len(data)
    
    while total_sent < data_len:
        sent = conn.send(data[total_sent:])
        if sent == 0:
            raise RuntimeError("Connection lost while sending data.")
        total_sent += sent
        #print(f"Enviados {total_sent}/{data_len} bytes")
    
    #print("Todos los datos han sido enviados: {data}")

def send_message(conn, data):
    # Paso 1: Enviar la longitud del mensaje (4 bytes)
    length = len(data).to_bytes(4, 'big')  # Longitud en 4 bytes
    send_all(conn, length)  # Enviar la longitud
    
    # Paso 2: Enviar el mensaje completo
    send_all(conn, data)
    #print("Mensaje enviado correctamente.")




## Receive

def receive_all(conn, expected_length):
    data = b""
    
    while len(data) < expected_length:
        chunk = conn.recv(min(1024, expected_length - len(data)))
        if not chunk:
            raise RuntimeError("Connection lost while receiving data.")
        data += chunk
        #print(f"Recibidos {len(data)}/{expected_length} bytes")
    
    #print("Todos los datos han sido recibidos: {data}")
    return data

def receive_message(conn):
    # Paso 1: Recibir la longitud del mensaje (4 bytes)
    length_data = receive_all(conn, 4)
    expected_length = int.from_bytes(length_data, 'big')
    
    # Paso 2: Recibir los datos reales
    data = receive_all(conn, expected_length)
    #print("Mensaje recibido correctamente.")
    return data