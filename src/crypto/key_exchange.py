"""Diffie-Hellman key exchange module with public key validation and HKDF derivation."""

import os
import logging
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)


class DiffieHellman:
    """Implements Diffie-Hellman key exchange with public key validation and HKDF."""

    def __init__(self, prime, generator):
        """Initialize with DH parameters."""
        self.prime = prime
        self.generator = generator

    def generatePrivate(self):
        """Generate a cryptographically secure random private key."""
        privateKey = int.from_bytes(os.urandom(64), byteorder="big") % (self.prime - 3) + 2
        logger.info("Generated private key")
        return privateKey

    def generatePublic(self, privateKey):
        """Compute public key from private key: g^privateKey mod p."""
        publicKey = pow(self.generator, privateKey, self.prime)
        logger.info("Computed public key")
        return publicKey

    def validatePublicKey(self, publicKey):
        """Validate that a received public key is within safe bounds [2, p-2].

        Prevents small-subgroup confinement attacks by rejecting keys
        outside the valid range.
        """
        if not (2 <= publicKey <= self.prime - 2):
            logger.error("Public key validation failed: key out of range [2, p-2]")
            raise ValueError("Invalid public key: outside safe range [2, p-2]")

    def deriveSharedKey(self, otherPublic, ownPrivate):
        """Derive shared secret using HKDF (RFC 5869) with SHA-256.

        Validates the peer's public key before derivation, then uses
        HKDF to extract and expand the shared secret into a uniform 32-byte key.
        """
        self.validatePublicKey(otherPublic)

        sharedSecret = pow(otherPublic, ownPrivate, self.prime)
        logger.info("Derived shared secret")

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"otp-stream-cipher-v1",
        )
        sharedKey = hkdf.derive(sharedSecret.to_bytes((sharedSecret.bit_length() + 7) // 8, byteorder="big"))
        logger.info("Derived shared key via HKDF")
        return sharedKey
