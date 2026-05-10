"""Seed encryption module using AES-256-GCM symmetric encryption."""

import os
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)


def encryptSeed(seedBytes, sharedKey):
    """Encrypt the seed using AES-256-GCM."""
    aesgcm = AESGCM(sharedKey)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, seedBytes, None)
    return nonce, ciphertext

def decryptSeed(nonce, ciphertext, sharedKey):
    """Decrypt the seed using AES-256-GCM."""
    try:
        aesgcm = AESGCM(sharedKey)
        seedBytes = aesgcm.decrypt(nonce, ciphertext, None)
        logger.info("Seed decrypted successfully")
        return seedBytes
    except Exception as e:
        logger.error("Seed decryption failed - authentication error: %s", e)
        raise
