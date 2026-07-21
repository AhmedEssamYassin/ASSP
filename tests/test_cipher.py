"""A test suite for OTP Stream Cipher modules."""

import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.crypto.csprng import CsprngGenerator
from src.crypto.stream_cipher import StreamCipher
from src.crypto.key_exchange import EcdhKeyExchange
from src.crypto.seed_encryption import encryptSeed, decryptSeed
from src.crypto.ed25519_authentication import generateSigningKeypair, signPayload, verifySignature
from src.communication.pipeline import runCommunication

class TestCsprngGenerator:
    """Tests for CSPRNG (AES-CTR)."""

    def testCsprngDeterministic(self):
        """Verify CSPRNG produces deterministic output with same seed and nonce."""
        gen1 = CsprngGenerator(seedBytes=b"A" * 32)
        gen2 = CsprngGenerator(seedBytes=b"A" * 32, nonceBytes=gen1.getNonce())

        for i in range(100):
            assert gen1.getNextByte() == gen2.getNextByte()

    def testCsprngByteRange(self):
        """Verify CSPRNG output is always in byte range (0-255)."""
        gen = CsprngGenerator(seedBytes=b"B" * 32)

        for i in range(1000):
            byteVal = gen.getNextByte()
            assert 0 <= byteVal <= 255

    def testCsprngInvalidSeed(self):
        """Verify CSPRNG rejects invalid seed length."""
        with pytest.raises(ValueError):
            CsprngGenerator(seedBytes=b"too_short")

class TestStreamCipher:
    """Tests for Stream Cipher encryption/decryption."""

    def testStreamCipherRoundTrip(self):
        """Verify XOR(XOR(plaintext, KEY), KEY) == plaintext."""
        gen1 = CsprngGenerator(seedBytes=b"C" * 32)
        gen2 = CsprngGenerator(seedBytes=b"C" * 32, nonceBytes=gen1.getNonce())
        cipher1 = StreamCipher(gen1, maxChunkSize=10)
        cipher2 = StreamCipher(gen2, maxChunkSize=10)

        plaintext = "Hello World! This is a test message."
        encrypted = cipher1.encrypt(plaintext)
        decrypted = cipher2.decrypt(encrypted)

        assert decrypted == plaintext

    def test10ByteBatching(self):
        """Verify 25-byte text produces exactly 3 chunks (10, 10, 5)."""
        gen = CsprngGenerator(seedBytes=b"C" * 32)
        cipher = StreamCipher(gen, maxChunkSize=10)

        plaintext = "1234567890123456789012345"
        chunks = cipher._splitIntoChunks(plaintext.encode("utf-8"))

        assert len(chunks) == 3
        assert len(chunks[0]) == 10
        assert len(chunks[1]) == 10
        assert len(chunks[2]) == 5

    def testUnicodeSupport(self):
        """Verify multi-byte Unicode characters encrypt/decrypt correctly."""
        gen1 = CsprngGenerator(seedBytes=b"U" * 32)
        gen2 = CsprngGenerator(seedBytes=b"U" * 32, nonceBytes=gen1.getNonce())
        cipher1 = StreamCipher(gen1, maxChunkSize=10)
        cipher2 = StreamCipher(gen2, maxChunkSize=10)

        plaintext = "أهلا و سهلا 🚀"
        encrypted = cipher1.encrypt(plaintext)
        decrypted = cipher2.decrypt(encrypted)

        assert decrypted == plaintext

    def testEmptyPlaintext(self):
        """Verify empty plaintext handling."""
        gen = CsprngGenerator(seedBytes=b"E" * 32)
        cipher = StreamCipher(gen, maxChunkSize=10)

        encrypted = cipher.encrypt("")
        assert encrypted == []

class TestEcdhKeyExchange:
    """Tests for X25519 ECDH key exchange."""

    def testEcdhSymmetry(self):
        """Prove Alice_shared == Bob_shared."""
        ecdh = EcdhKeyExchange()

        alicePrivate, alicePublic = ecdh.generateKeypair()
        bobPrivate, bobPublic = ecdh.generateKeypair()

        aliceShared = ecdh.deriveSharedKey(alicePrivate, bobPublic)
        bobShared = ecdh.deriveSharedKey(bobPrivate, alicePublic)

        assert aliceShared == bobShared

    def testEcdhDifferentKeys(self):
        """Verify different private keys produce different shared secrets."""
        ecdh = EcdhKeyExchange()

        alicePrivate1, _ = ecdh.generateKeypair()
        alicePrivate2, _ = ecdh.generateKeypair()
        _, bobPublic = ecdh.generateKeypair()

        shared1 = ecdh.deriveSharedKey(alicePrivate1, bobPublic)
        shared2 = ecdh.deriveSharedKey(alicePrivate2, bobPublic)

        assert shared1 != shared2

class TestSeedEncryption:
    """Tests for AES-256-GCM seed encryption."""

    def testSeedEncryptionRoundTrip(self):
        """Verify seed can be encrypted and decrypted correctly."""
        sharedKey = b"\x00" * 32
        seedBytes = b"\x11" * 32

        nonce, ciphertext = encryptSeed(seedBytes, sharedKey)
        decrypted = decryptSeed(nonce, ciphertext, sharedKey)

        assert decrypted == seedBytes

    def testSeedEncryptionDifferentKeys(self):
        """Verify decryption fails with wrong key."""
        key1 = b"\x00" * 32
        key2 = b"\xff" * 32
        seedBytes = b"\x11" * 32

        nonce, ciphertext = encryptSeed(seedBytes, key1)

        with pytest.raises(Exception):
            decryptSeed(nonce, ciphertext, key2)

class TestCommunication:
    """Tests for multiprocessing communication."""

    def testEndToEndCommunication(self):
        """Test full sender/receiver communication cycle."""
        plaintext = "Hello secure world!"
        config = {
            "crypto": {"aesKeyLength": 256, "maxChunkSize": 10},
        }

        result = runCommunication(plaintext, config)

        assert result.get("success") is True
        assert result.get("decryptedText") == plaintext

    def testLongMessageCommunication(self):
        """Test communication with a longer message."""
        plaintext = "This is a much longer message that will be split into multiple chunks for transmission testing purposes."
        config = {
            "crypto": {"aesKeyLength": 256, "maxChunkSize": 10},
        }

        result = runCommunication(plaintext, config)

        assert result.get("success") is True
        assert result.get("decryptedText") == plaintext

class TestEd25519Authentication:
    """Tests for Ed25519 digital signature authentication."""

    def testEd25519SignatureValid(self):
        """Verify Ed25519 signature passes for valid signed payload."""
        privateKey, publicKey = generateSigningKeypair()
        payload = b"test payload for signing"

        signature = signPayload(payload, privateKey)
        verifySignature(payload, signature, publicKey)

    def testMitmRejection(self):
        """Verify MITM attack is rejected when X25519 key is tampered."""
        senderPrivate, senderPublic = generateSigningKeypair()

        payloadOriginal = b"original x25519 public key bytes"
        payloadTampered = b"tampered x25519 public key bytes"

        signature = signPayload(payloadOriginal, senderPrivate)

        with pytest.raises(Exception, match="MITM detected"):
            verifySignature(payloadTampered, signature, senderPublic)

    def testWrongPublicKeyRejection(self):
        """Verify signature fails when using wrong Ed25519 public key."""
        senderPrivate, _ = generateSigningKeypair()
        _, receiverPublic = generateSigningKeypair()

        payload = b"x25519 public key bytes"
        signature = signPayload(payload, senderPrivate)

        with pytest.raises(Exception, match="MITM detected"):
            verifySignature(payload, signature, receiverPublic)
