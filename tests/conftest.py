"""Pytest configuration and shared fixtures for OTP Stream Cipher."""

import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.crypto.csprng import CsprngGenerator
from src.crypto.config import loadConfig
from src.crypto.key_exchange import EcdhKeyExchange
from src.crypto.stream_cipher import StreamCipher
from src.crypto.seed_encryption import encryptSeed, decryptSeed

@pytest.fixture
def config():
    """Load test configuration."""
    return loadConfig()

@pytest.fixture
def csprngGenerator():
    """Create a standard CSPRNG generator with a known 32-byte seed."""
    return CsprngGenerator(seedBytes=b"1" * 32)

@pytest.fixture
def streamCipher(csprngGenerator):
    """Create a stream cipher with fixed CSPRNG for deterministic testing."""
    return StreamCipher(csprngGenerator, maxChunkSize=10)

@pytest.fixture
def ecdhKeyExchange():
    """Create ECDH instance."""
    return EcdhKeyExchange()

@pytest.fixture
def sharedKeyPair(ecdhKeyExchange):
    """Generate an ECDH key pair and derive shared key for testing."""
    alicePrivate, alicePublic = ecdhKeyExchange.generateKeypair()
    bobPrivate, bobPublic = ecdhKeyExchange.generateKeypair()

    aliceShared = ecdhKeyExchange.deriveSharedKey(alicePrivate, bobPublic)
    bobShared = ecdhKeyExchange.deriveSharedKey(bobPrivate, alicePublic)

    return {
        "aliceShared": aliceShared,
        "bobShared": bobShared,
    }
