"""Cryptographically Secure Pseudorandom Number Generator (CSPRNG) module."""

import logging
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger(__name__)

class CsprngGenerator:
    """Generates cryptographically secure pseudo-random bytes using AES-256-CTR.

    Replaces the insecure LCG. Uses a 256-bit session seed as the AES key.
    Applies Defense in Depth by generating a random 16-byte nonce.
    """

    def __init__(self, seedBytes, nonceBytes=None):
        """Initialize CSPRNG with a 32-byte seed (key) and an optional 16-byte nonce."""
        if len(seedBytes) != 32:
            raise ValueError("CSPRNG requires a 32-byte seed")
            
        if nonceBytes is not None and len(nonceBytes) != 16:
            raise ValueError("CSPRNG requires a 16-byte nonce")

        self.key = seedBytes
        self.nonce = nonceBytes if nonceBytes is not None else os.urandom(16)
        
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(self.nonce))
        self.encryptor = cipher.encryptor()

    def getNonce(self):
        """Return the 16-byte nonce used by the CSPRNG."""
        return self.nonce

    def getNextByte(self):
        """Generate and return the next pseudo-random byte."""
        # Encrypt a single null byte to extract one byte of the keystream
        return self.encryptor.update(b"\x00")[0]
