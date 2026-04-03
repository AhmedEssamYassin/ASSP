"""Pytest configuration and shared fixtures for OTP Stream Cipher."""

import json
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.crypto.lcg import LcgGenerator, loadConfig
from src.crypto.key_exchange import DiffieHellman
from src.crypto.stream_cipher import StreamCipher
from src.crypto.seed_encryption import encryptSeed, decryptSeed
from src.crypto.seed_authentication import generateHmac, verifyHmac

@pytest.fixture
def config():
    """Load test configuration."""
    return loadConfig()

@pytest.fixture
def lcgGenerator():
    """Create a standard LCG generator with known parameters."""
    return LcgGenerator(seed=12345, modulus=18446744073709551616, multiplier=6364136223846793005, increment=1442695040888963407)

@pytest.fixture
def streamCipher(lcgGenerator):
    """Create a stream cipher with fixed LCG for deterministic testing."""
    return StreamCipher(lcgGenerator, maxChunkSize=10)

@pytest.fixture
def diffieHellman(config):
    """Create Diffie-Hellman instance from config."""
    return DiffieHellman(config["diffieHellman"]["p"], config["diffieHellman"]["g"])

@pytest.fixture
def sharedKeyPair(diffieHellman):
    """Generate a DH key pair and derive shared key for testing."""
    alicePrivate = diffieHellman.generatePrivate()
    bobPrivate = diffieHellman.generatePrivate()

    alicePublic = diffieHellman.generatePublic(alicePrivate)
    bobPublic = diffieHellman.generatePublic(bobPrivate)

    aliceShared = diffieHellman.deriveSharedKey(bobPublic, alicePrivate)
    bobShared = diffieHellman.deriveSharedKey(alicePublic, bobPrivate)

    return {
        "aliceShared": aliceShared,
        "bobShared": bobShared,
    }
