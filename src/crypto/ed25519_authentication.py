"""Ed25519 digital signature module for authenticating X25519 public keys."""

import logging
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)


def generateSigningKeypair():
    """Generate an Ed25519 key pair for identity authentication."""
    privateKey = Ed25519PrivateKey.generate()
    publicKey = privateKey.public_key()
    logger.info("Generated Ed25519 key pair")
    return privateKey, publicKey

def serializePublicKey(publicKey):
    """Serialize Ed25519 public key to PEM bytes for transport."""
    return publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def deserializePublicKey(pemBytes):
    """Deserialize Ed25519 public key from PEM bytes."""
    return serialization.load_pem_public_key(pemBytes)

def signPayload(payloadBytes, privateKey):
    """Sign payload bytes using Ed25519."""
    signature = privateKey.sign(payloadBytes)
    logger.info("Signed payload (%d bytes) with Ed25519", len(payloadBytes))
    return signature

def verifySignature(payloadBytes, signature, publicKey):
    """Verify Ed25519 signature. Raises exception on tampering."""
    try:
        publicKey.verify(signature, payloadBytes)
        logger.info("Ed25519 signature verified successfully")
    except Exception as e:
        logger.error("Ed25519 signature verification failed: %s", e)
        raise Exception("MITM detected: X25519 public key signature is invalid")

def computeFingerprint(publicKey):
    """Return a colon-separated SHA-256 fingerprint of an Ed25519 public key."""
    rawBytes = publicKey.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    digest = hashlib.sha256(rawBytes).digest()
    return ":".join(f"{b:02x}" for b in digest[:16])  # first 16 bytes = 47-char string
