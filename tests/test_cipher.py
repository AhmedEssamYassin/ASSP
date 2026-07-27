"""A test suite for Authenticated Secure Stream Protocol modules."""

import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.crypto.csprng import CsprngGenerator
from src.crypto.stream_cipher import StreamCipher
from src.crypto.key_exchange import EcdhKeyExchange
from src.crypto.seed_encryption import encryptSeed, decryptSeed
from src.crypto.payload_formatter import packPayload, unpackPayload
from src.crypto.ed25519_authentication import generateSigningKeypair, signPayload, verifySignature

class TestCsprngGenerator:
    """Tests for CSPRNG (AES-CTR)."""

    def testCsprngDeterministic(self):
        """Verify CSPRNG produces deterministic output with same seed and nonce."""
        nonce = os.urandom(16)
        gen1 = CsprngGenerator(seedBytes=b"A" * 32, nonceBytes=nonce)
        gen2 = CsprngGenerator(seedBytes=b"A" * 32, nonceBytes=nonce)

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

        plaintext = b"Hello World! This is a test message."
        encrypted = list(cipher1.encryptStream(plaintext))
        decrypted = cipher2.decrypt(encrypted)

        assert decrypted == plaintext

    def test10ByteBatching(self):
        """Verify 25-byte text produces exactly 3 chunks (10, 10, 5)."""
        gen = CsprngGenerator(seedBytes=b"C" * 32)
        cipher = StreamCipher(gen, maxChunkSize=10)

        plaintext = b"1234567890123456789012345"
        chunks = list(cipher._splitIntoChunks(plaintext))

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

        plaintext = "أهلا و سهلا 🚀".encode("utf-8")
        encrypted = list(cipher1.encryptStream(plaintext))
        decrypted = cipher2.decrypt(encrypted)

        assert decrypted == plaintext

    def testEmptyPlaintext(self):
        """Verify empty plaintext handling."""
        gen = CsprngGenerator(seedBytes=b"E" * 32)
        cipher = StreamCipher(gen, maxChunkSize=10)

        encrypted = list(cipher.encryptStream(b""))
        assert encrypted == []

class TestPayloadFormatter:
    """Tests for payload metadata packing/unpacking."""
    
    def testPayloadRoundTrip(self):
        """Verify packing and unpacking returns original metadata and bytes."""
        metadata = {"type": "file", "filename": "test.png"}
        rawBytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        
        packed = packPayload(metadata, rawBytes)
        unpackedMeta, unpackedBytes = unpackPayload(packed)
        
        assert unpackedMeta == metadata
        assert unpackedBytes == rawBytes

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

class TestTcpCommunication:
    """Integration tests for the production TCP client/server transport."""

    def _startServer(self, host, port, config=None):
        """Launch runServer() on a daemon thread and wait for it to bind."""
        import threading
        import time
        from src.communication.server import runServer

        t = threading.Thread(
            target=runServer,
            kwargs={"host": host, "port": port, "config": config},
            daemon=True,  # killed automatically when the test process exits
        )
        t.start()
        time.sleep(0.3)  # give the socket time to bind
        return t

    def testTcpRoundTrip(self):
        """Full handshake + encrypt cycle over a real TCP socket returns success."""
        from src.communication.client import runClient

        config = {
            "crypto": {"maxChunkSize": 10},
            "security": {
                "skipSasVerification": True
            }
        }
        self._startServer("127.0.0.1", 15001, config)

        result = runClient(b"Hello TCP!", {"type": "text"}, config, host="127.0.0.1", port=15001)

        assert result.get("success") is True
        assert isinstance(result.get("cipherChunks"), list)
        assert len(result["cipherChunks"]) > 0

    def testTcpLongMessage(self):
        """Long message produces the correct number of chunks over TCP."""
        from src.communication.client import runClient

        config = {
            "crypto": {"maxChunkSize": 10},
            "security": {
                "skipSasVerification": True
            }
        }
        self._startServer("127.0.0.1", 15002, config)

        plaintext = b"This is a longer message to verify multi-chunk TCP framing works correctly."
        result = runClient(plaintext, {"type": "text"}, config, host="127.0.0.1", port=15002)

        assert result.get("success") is True
        
        # Calculate expected chunks: the client packs the metadata JSON + length prefix before encrypting
        packedPayload = packPayload({"type": "text"}, plaintext)
        expectedChunks = -(-len(packedPayload) // 10)  # ceiling division
        assert len(result["cipherChunks"]) == expectedChunks

    def testTcpConnectionRefused(self):
        """Client returns a clean error dict when no server is listening."""
        from src.communication.client import runClient

        config = {
            "crypto": {"maxChunkSize": 10},
            "security": {
                "skipSasVerification": True
            }
        }

        result = runClient(b"test", {"type": "text"}, config, host="127.0.0.1", port=19999)

        assert result.get("success") is False
        assert "error" in result
