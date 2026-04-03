"""RSA-PSS digital signature module for authenticating Diffie-Hellman public keys."""

import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

logger = logging.getLogger(__name__)


def generateRsaKeypair():
    """Generate a 4096-bit RSA key pair for identity authentication."""
    privateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    publicKey = privateKey.public_key()
    logger.info("Generated 4096-bit RSA key pair")
    return privateKey, publicKey

def serializeRsaPublicKey(rsaPublicKey):
    """Serialize RSA public key to PEM bytes for transport."""
    return rsaPublicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def deserializeRsaPublicKey(pemBytes):
    """Deserialize RSA public key from PEM bytes."""
    return serialization.load_pem_public_key(pemBytes)

def serializeRsaPrivateKey(rsaPrivateKey):
    """Serialize RSA private key to PEM bytes."""
    return rsaPrivateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

def deserializeRsaPrivateKey(pemBytes):
    """Deserialize RSA private key from PEM bytes."""
    return serialization.load_pem_private_key(pemBytes, password=None)

def signPayload(payloadBytes, rsaPrivateKey):
    """Sign payload bytes using RSA-PSS with SHA-256."""
    signature = rsaPrivateKey.sign(
        payloadBytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    logger.info("Signed payload (%d bytes) with RSA-PSS", len(payloadBytes))
    return signature

def verifySignature(payloadBytes, signature, rsaPublicKey):
    """Verify RSA-PSS signature. Raises exception on tampering."""
    try:
        rsaPublicKey.verify(
            signature,
            payloadBytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        logger.info("RSA-PSS signature verified successfully")
    except Exception as e:
        logger.error("RSA-PSS signature verification failed: %s", e)
        raise Exception("MITM detected: DH public key signature is invalid")
