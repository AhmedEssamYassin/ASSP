"""Cryptographically Secure Pseudorandom Number Generator (CSPRNG) module."""

import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger(__name__)

class CsprngGenerator:
    """Generates cryptographically secure pseudo-random bytes using AES-256-CTR.

    Replaces the insecure LCG. Uses a 256-bit session seed as the AES key.
    Since a fresh key is generated for every session, a static nonce is safe to use.
    """

    def __init__(self, seedBytes):
        """Initialize CSPRNG with a 32-byte seed (key)."""
        if len(seedBytes) != 32:
            raise ValueError("CSPRNG requires a 32-byte seed")

        self.key = seedBytes
        self.nonce = b"\x00" * 16  # Safe because key is ephemeral and never reused
        
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(self.nonce))
        self.encryptor = cipher.encryptor()

    def getNextByte(self):
        """Generate and return the next pseudo-random byte."""
        # Encrypt a single null byte to extract one byte of the keystream
        return self.encryptor.update(b"\x00")[0]
