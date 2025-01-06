# Script principal para ejecutar cliente y servidor
import threading
import time
from server import start_server
from client import start_client

def main():
    # Inicia el servidor en un hilo separado
    server_thread = threading.Thread(target=start_server, args=('127.0.0.1', 2223))
    server_thread.start()

    time.sleep(1)

    # Inicia el cliente en el hilo principal
    start_client('127.0.0.1', 2223)

if __name__ == "__main__":
    main()
