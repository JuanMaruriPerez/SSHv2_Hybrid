Este codigo se corresponde a una implementacion en Python de un subconjunto de las operaciones 
llevadas a cabo por el protoclo SSH hibrido propuesto por el IETF en el siguiente enlace:
https://datatracker.ietf.org/doc/html/draft-kampanakis-curdle-ssh-pq-ke-05#name-message-size


Subconjunto de operacion implementadas: 

- Establecimineto conexion TCP 
- Intercambio de claves clasico 
- Intercambio de claves post-cuantico 
- Calculo de claves 
- Hibridacion de claves simetricas 
- ?Derivación de claves de sesión 
- Ejemplo de un intercambio de mensajes cifrados


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

                -   -   -   -   -   


  |------------( ) Shared Secret------------------>|
  |                                                |
  |( ) SSH_MSG_NEWKEYS (Both Parties Exchange Keys)|
  |                                                |

Cipher suites : 

    mlkem768nistp256-sha256 <-- Unico soportado, por ahora
    mlkem1024nistp384-sha384
    mlkem768x25519-sha256


Desglose del Diagrama
1. TCP Connection:
El cliente inicia una conexión TCP al puerto SSH (por defecto, 22).
El servidor responde con una conexión TCP establecida.

2. Server Identification:
El servidor envía su identificación de protocolo, que incluye la versión de SSH y detalles adicionales (e.g., SSH-2.0-OpenSSH_8.4).

3. Client Identification:
El cliente responde con su propia identificación de protocolo.

4-5. Exchange of KEXINIT Messages:
Ambos lados envían un mensaje SSH_MSG_KEXINIT, que describe los algoritmos soportados para el intercambio de claves, cifrado, autenticación, etc.
Se selecciona un conjunto de algoritmos mutuamente aceptables.

Estas listas incluyen:
  Algoritmos de intercambio de claves (como ecdh-sha2-nistp256).
  Algoritmos de cifrado simétrico (como aes128-ctr).
  Algoritmos de autenticación de mensajes (como hmac-sha2-256).
  Algoritmos de compresión (como none o zlib).

El servidor selecciona, para cada categoría, el primer algoritmo en la lista del cliente que también sea compatible con el servidor.
El servidor informa al cliente de los algoritmos seleccionados enviando un mensaje de confirmación.

6. Enviar y recibir claves públicas
Cada parte genera un par de claves ECDH (privada y pública) utilizando una curva elíptica acordada previamente, como secp256r1.
La clave pública de cada parte es serializada y transmitida al otro extremo.
Este intercambio es fundamental para calcular el secreto compartido, ya que el protocolo ECDH permite que ambas partes generen el mismo secreto sin exponer la clave privada.
Detalles técnicos:

Las claves públicas se serializan en formato PEM (o DER).
Los puntos de la curva elíptica (coordenadas X e Y) se envían como parte de la clave pública.
Antes de usar las claves recibidas, cada lado verifica su validez (como longitud adecuada y estar en la curva esperada).

6. Enviar y recibir claves públicas
Cada parte genera un par de claves ECDH (privada y pública) utilizando una curva elíptica acordada previamente, como secp256r1.
La clave pública de cada parte es serializada y transmitida al otro extremo.
Este intercambio es fundamental para calcular el secreto compartido, ya que el protocolo ECDH permite que ambas partes generen el mismo secreto sin exponer la clave privada.
Las claves públicas se serializan en formato PEM (o DER).
Los puntos de la curva elíptica (coordenadas X e Y) se envían como parte de la clave pública.
Antes de usar las claves recibidas, cada lado verifica su validez (como longitud adecuada y estar en la curva esperada).

7. Cálculo del secreto compartido
Cada lado utiliza su clave privada y la clave pública del otro para calcular el secreto compartido utilizando la función ECDH:
​El secreto compartido 𝐾
K es simplemente un número binario que será transformado en material clave a través de un algoritmo de derivación de claves (KDF)

8. Confirmación del intercambio de claves
Una vez calculado el secreto compartido, ambas partes derivan claves simétricas utilizando un KDF (Key Derivation Function).
Por ejemplo, derivan claves de cifrado, claves de autenticación de mensajes y vectores de inicialización (IVs) si son necesarios.
Ambas partes envían el mensaje SSH_MSG_NEWKEYS para indicar que ahora usarán las claves y algoritmos acordados.
El KDF incluye tanto el secreto compartido como datos adicionales del intercambio, como:
Identificadores de cliente y servidor.
Algoritmos seleccionados.
Nonces (valores aleatorios generados durante la conexión).


9. Canal seguro establecido
Después de recibir y validar SSH_MSG_NEWKEYS, ambas partes configuran sus cifradores simétricos y empiezan a cifrar toda la comunicación.
A partir de este punto, los mensajes enviados son cifrados y autenticados utilizando las claves derivadas.
Detalles técnicos:

Los cifradores típicos son del tipo CTR (Counter Mode) o GCM (Galois Counter Mode), que proporcionan encriptación y, en algunos casos, autenticación.
La autenticación de mensajes se realiza con HMAC (Hash-based Message Authentication Code) para garantizar la integridad de los datos.