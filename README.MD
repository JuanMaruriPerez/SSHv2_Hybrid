Este codigo se corresponde a subconjunto de las operaciones llevadas a cabo por el protoclo SSH hibrido. En concreto:
    - Establecimineto conexion TCP
    - Intercambio de claves clasico
    - Intercambio de claves post-cuantico
    - Calculo de claves 
    - Hibridacion de claves simetricas
    - ?Derivación de claves de sesión
    - Ejemplo de un intercambio de mensajes cifrados

Como algoritmos se siguen las recomendaciones del estandar del IETF : 

    - mlkem768nistp256-sha256
    - mlkem1024nistp384-sha384
    - mlkem768x25519-sha256

El primero de ellos 'mlkem768nistp256-sha256' combina:
    - ML-KEM (Multivariate Key Encapsulation Mechanism): Un esquema post-cuántico para generar una clave compartida segura.
    - NIST P-256 (ECDH): Un esquema de intercambio de claves clásico basado en curvas elípticas.
    - SHA-256: Para derivar una clave híbrida mediante una función hash.