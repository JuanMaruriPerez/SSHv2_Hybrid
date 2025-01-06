Este codigo se corresponde a una implementacion en Python de un subconjunto de las operaciones llevadas a cabo por el protoclo SSH hibrido propuesto por el IETF en el siguiente enlace:
https://datatracker.ietf.org/doc/html/draft-kampanakis-curdle-ssh-pq-ke-05#name-message-size


Subconjunto de operacion implementadas: 

- Establecimineto conexion TCP 
- Intercambio de claves clasico 
- Intercambio de claves post-cuantico 
- Calculo de claves 
- Hibridacion de claves simetricas 
- ?Derivación de claves de sesión 
- ?Ejemplo de un intercambio de mensajes cifrados


Cliente                                         Servidor
  |                                                |
  |-------------(1) TCP Connection---------------->|
  |                                                |
  |-----------(2) Client Identification----------->| 'SSH-2.0-OpenSSH_Hybrid'
  |                                                |
  |<-----------(3) Server Identification-----------| 'SSH-2.0-OpenSSH_Hybrid'
  |                                                |
  |----(4) SSH_MSG_KEX_HYBRID_INIT (Client)------->| int:30
  |                                                |
  |<----(5) SSH_MSG_KEX_HYBRID_REPLY (Server)------| int:31
  |                                                |
  |----(6) SSH_MSG_KEX_ECDH_INIT (Client)--------->|
  |                                                |
  |<---(7) SSH_MSG_KEX_ECDH_REPLY (Server)---------|
  |                                                |

  ..................................................

  |------------( ) Shared Secret------------------>|
  |                                                |
  |( ) SSH_MSG_NEWKEYS (Both Parties Exchange Keys)|
  |                                                |

Cipher suites : 

    mlkem768nistp256-sha256 <-- Unico soportado, por ahora
    mlkem1024nistp384-sha384
    mlkem768x25519-sha256

src
│   ├── client.py : Logica del cliente

|   ├── server.py : Logica del servidor


│   ├── connection.py : Conexion TCP

│   ├── exchange.py : Intercambio ECDH  y Kyber

│   ├── hybridation.py : Hybridacion de claves con codigo extendido de un fork de Cryptography.

│   ├── message.py : Control de comunicacion Cliente <--> Servidor


│   ├── exceptions.py : Excepciones



│   ├── main.py : Codigo que pone todo en marcha en entorno de prueba en local