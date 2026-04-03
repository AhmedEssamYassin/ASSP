"""Seed encryption module using AES-256-GCM symmetric encryption."""

import os
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)


def encryptSeed(seed, sharedKey):
    """Encrypt the seed using AES-256-GCM."""
    aesgcm = AESGCM(sharedKey)
    nonce = os.urandom(12)
    seedBytes = seed.to_bytes(8, byteorder="big")
    ciphertext = aesgcm.encrypt(nonce, seedBytes, None)
    return nonce, ciphertext

def decryptSeed(nonce, ciphertext, sharedKey):
    """Decrypt the seed using AES-256-GCM."""
    try:
        aesgcm = AESGCM(sharedKey)
        seedBytes = aesgcm.decrypt(nonce, ciphertext, None)
        seed = int.from_bytes(seedBytes, byteorder="big")
        logger.info("Decrypted seed: %s", seed)
        return seed
    except Exception as e:
        logger.error("Seed decryption failed - authentication error: %s", e)
        raise
