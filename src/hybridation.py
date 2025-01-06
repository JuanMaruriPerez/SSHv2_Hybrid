from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.khf.hybridhash import HybridHASH

def derive_hybrid_key(symmetric_classic_key: bytes, symmetric_pqc_key: bytes, salt: str = '0x00',length: int = 32) -> bytes:
    """
    Deriva una clave híbrida combinando claves clásicas y PQC.
    
    Args:
        symmetric_classic_key (bytes): Clave simétrica derivada del intercambio clásico.
        symmetric_pqc_key (bytes): Clave simétrica derivada del intercambio PQC.
        salt (str) : Valor salt a concatenar entre ambas claves
        length (int): Longitud deseada de la clave derivada (por defecto, 32 bytes).

    Returns:
        bytes: Clave híbrida derivada.
    """
    # Inicializar el algoritmo hash (puedes cambiar a SHA512 u otro si es necesario)
    algorithm = hashes.SHA256()

    # Crear una instancia de HybridHASH
    hybrid_kdf = HybridHASH(
        algorithm=algorithm,
        key_material1=symmetric_classic_key,
        key_material2=symmetric_pqc_key,
        salt=salt,
        length=length
    )

    # Derivar la clave híbrida
    hybrid_key = hybrid_kdf.derive()

    return hybrid_key
