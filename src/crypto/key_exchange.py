"""Curve25519 (X25519) key exchange module with HKDF derivation."""

import logging
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

class EcdhKeyExchange:
    """Implements X25519 Elliptic Curve Diffie-Hellman key exchange with HKDF."""

    def generateKeypair(self):
        """Generate an X25519 keypair."""
        privateKey = X25519PrivateKey.generate()
        publicKey = privateKey.public_key()
        logger.info("Generated X25519 key pair")
        return privateKey, publicKey

    def serializePublicKey(self, publicKey):
        """Serialize public key to raw bytes (32 bytes)."""
        return publicKey.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def deserializePublicKey(self, publicBytes):
        """Deserialize public key from raw bytes (32 bytes)."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        return X25519PublicKey.from_public_bytes(publicBytes)

    def deriveSharedKey(self, ownPrivate, otherPublic):
        """Derive shared secret using HKDF (RFC 5869) with SHA-256."""
        sharedSecret = ownPrivate.exchange(otherPublic)
        logger.info("Derived X25519 shared secret")

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"otp-stream-cipher-v1",
        )
        sharedKey = hkdf.derive(sharedSecret)
        logger.info("Derived shared key via HKDF")
        return sharedKey
