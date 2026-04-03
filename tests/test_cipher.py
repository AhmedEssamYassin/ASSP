"""A test suite for OTP Stream Cipher modules."""

import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.crypto.lcg import LcgGenerator
from src.crypto.stream_cipher import StreamCipher
from src.crypto.key_exchange import DiffieHellman
from src.crypto.seed_encryption import encryptSeed, decryptSeed
from src.crypto.seed_authentication import generateHmac, verifyHmac
from src.crypto.rsa_authentication import generateRsaKeypair, signPayload, verifySignature
from src.communication.pipeline import runCommunication

class TestLcgGenerator:
    """Tests for Linear Congruential Generator."""

    def testLcgDeterministic(self):
        """Verify LCG produces deterministic output with same seed."""
        gen1 = LcgGenerator(seed=12345, modulus=18446744073709551616, multiplier=6364136223846793005, increment=1442695040888963407)
        gen2 = LcgGenerator(seed=12345, modulus=18446744073709551616, multiplier=6364136223846793005, increment=1442695040888963407)

        for i in range(100):
            assert gen1.getNextByte() == gen2.getNextByte()

    def testLcgByteRange(self):
        """Verify LCG output is always in byte range (0-255)."""
        gen = LcgGenerator(seed=99999, modulus=18446744073709551616, multiplier=6364136223846793005, increment=1442695040888963407)

        for i in range(1000):
            byteVal = gen.getNextByte()
            assert 0 <= byteVal <= 255

    def testLcgHighOrderBits(self):
        """Verify LCG uses high-order bits (not low-order) for output."""
        gen = LcgGenerator(seed=1, modulus=18446744073709551616, multiplier=6364136223846793005, increment=1442695040888963407)
        bytesOut = [gen.getNextByte() for i in range(10)]
        lowBitPattern = [b % 2 for b in bytesOut]
        assert not all(lowBitPattern[i] != lowBitPattern[i + 1] for i in range(len(lowBitPattern) - 1))

class TestStreamCipher:
    """Tests for Stream Cipher encryption/decryption."""

    def testStreamCipherRoundTrip(self):
        """Verify XOR(XOR(plaintext, KEY), KEY) == plaintext."""
        lcg1 = LcgGenerator(seed=42, modulus=18446744073709551616, multiplier=6364136223846793005, increment=1442695040888963407)
        lcg2 = LcgGenerator(seed=42, modulus=18446744073709551616, multiplier=6364136223846793005, increment=1442695040888963407)
        cipher1 = StreamCipher(lcg1, maxChunkSize=10)
        cipher2 = StreamCipher(lcg2, maxChunkSize=10)

        plaintext = "Hello World! This is a test message."
        encrypted = cipher1.encrypt(plaintext)
        decrypted = cipher2.decrypt(encrypted)

        assert decrypted == plaintext

    def test10ByteBatching(self):
        """Verify 25-byte text produces exactly 3 chunks (10, 10, 5)."""
        lcg = LcgGenerator(seed=100, modulus=18446744073709551616, multiplier=6364136223846793005, increment=1442695040888963407)
        cipher = StreamCipher(lcg, maxChunkSize=10)

        plaintext = "1234567890123456789012345"
        chunks = cipher._splitIntoChunks(plaintext.encode("utf-8"))

        assert len(chunks) == 3
        assert len(chunks[0]) == 10
        assert len(chunks[1]) == 10
        assert len(chunks[2]) == 5

    def testUnicodeSupport(self):
        """Verify multi-byte Unicode characters encrypt/decrypt correctly."""
        lcg1 = LcgGenerator(seed=55, modulus=18446744073709551616, multiplier=6364136223846793005, increment=1442695040888963407)
        lcg2 = LcgGenerator(seed=55, modulus=18446744073709551616, multiplier=6364136223846793005, increment=1442695040888963407)
        cipher1 = StreamCipher(lcg1, maxChunkSize=10)
        cipher2 = StreamCipher(lcg2, maxChunkSize=10)

        plaintext = "أهلا و سهلا 🚀"
        encrypted = cipher1.encrypt(plaintext)
        decrypted = cipher2.decrypt(encrypted)

        assert decrypted == plaintext

    def testEmptyPlaintext(self):
        """Verify empty plaintext handling."""
        lcg = LcgGenerator(seed=1, modulus=18446744073709551616, multiplier=6364136223846793005, increment=1442695040888963407)
        cipher = StreamCipher(lcg, maxChunkSize=10)

        encrypted = cipher.encrypt("")
        assert encrypted == []

    def testSingleCharacter(self):
        """Verify single character encryption/decryption."""
        lcg1 = LcgGenerator(seed=7, modulus=18446744073709551616, multiplier=6364136223846793005, increment=1442695040888963407)
        lcg2 = LcgGenerator(seed=7, modulus=18446744073709551616, multiplier=6364136223846793005, increment=1442695040888963407)
        cipher1 = StreamCipher(lcg1, maxChunkSize=10)
        cipher2 = StreamCipher(lcg2, maxChunkSize=10)

        plaintext = "A"
        encrypted = cipher1.encrypt(plaintext)
        decrypted = cipher2.decrypt(encrypted)

        assert decrypted == plaintext

    def testDependencyInjection(self):
        """Verify StreamCipher accepts injected LCG instance."""
        lcg = LcgGenerator(seed=999, modulus=18446744073709551616, multiplier=6364136223846793005, increment=1442695040888963407)
        cipher = StreamCipher(lcg, maxChunkSize=10)

        assert cipher.lcg is lcg

class TestDiffieHellman:
    """Tests for Diffie-Hellman key exchange."""

    def testDhSymmetry(self):
        """Prove Alice_shared == Bob_shared."""
        dh = DiffieHellman(prime=25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357, generator=2)

        alicePrivate = dh.generatePrivate()
        bobPrivate = dh.generatePrivate()

        alicePublic = dh.generatePublic(alicePrivate)
        bobPublic = dh.generatePublic(bobPrivate)

        aliceShared = dh.deriveSharedKey(bobPublic, alicePrivate)
        bobShared = dh.deriveSharedKey(alicePublic, bobPrivate)

        assert aliceShared == bobShared

    def testDhDifferentKeys(self):
        """Verify different private keys produce different shared secrets."""
        dh = DiffieHellman(prime=25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357, generator=2)

        alicePrivate1 = dh.generatePrivate()
        alicePrivate2 = dh.generatePrivate()
        bobPrivate = dh.generatePrivate()

        bobPublic = dh.generatePublic(bobPrivate)

        shared1 = dh.deriveSharedKey(bobPublic, alicePrivate1)
        shared2 = dh.deriveSharedKey(bobPublic, alicePrivate2)

        assert shared1 != shared2

    def testDhPublicKeyValidation(self):
        """Verify invalid public keys are rejected."""
        dh = DiffieHellman(prime=25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357, generator=2)

        with pytest.raises(ValueError, match="Invalid public key"):
            dh.validatePublicKey(1)

        with pytest.raises(ValueError, match="Invalid public key"):
            dh.validatePublicKey(dh.prime - 1)

class TestSeedEncryption:
    """Tests for AES-256-GCM seed encryption."""

    def testSeedEncryptionRoundTrip(self):
        """Verify seed can be encrypted and decrypted correctly."""
        sharedKey = b"\x00" * 32
        seed = 12345678901234567890

        nonce, ciphertext = encryptSeed(seed, sharedKey)
        decrypted = decryptSeed(nonce, ciphertext, sharedKey)

        assert decrypted == seed

    def testSeedEncryptionDifferentKeys(self):
        """Verify decryption fails with wrong key."""
        key1 = b"\x00" * 32
        key2 = b"\xff" * 32
        seed = 9876543210

        nonce, ciphertext = encryptSeed(seed, key1)

        with pytest.raises(Exception):
            decryptSeed(nonce, ciphertext, key2)

class TestSeedAuthentication:
    """Tests for HMAC authentication."""

    def testHmacValidMessage(self):
        """Verify HMAC passes for unmodified message."""
        key = b"test_secret_key_1234567890123456"
        message = b"test message content"

        mac = generateHmac(message, key)
        verifyHmac(message, key, mac)

    def testHmacTampering(self):
        """Verify HMAC fails when message is tampered."""
        key = b"test_secret_key_1234567890123456"
        message = b"original message"

        mac = generateHmac(message, key)
        tamperedMessage = b"tampered message"

        with pytest.raises(Exception, match="HMAC verification failed"):
            verifyHmac(tamperedMessage, key, mac)

    def testHmacDifferentKeys(self):
        """Verify HMAC fails with wrong verification key."""
        key1 = b"key_one_____________123456789012"
        key2 = b"key_two_____________123456789012"
        message = b"test message"

        mac = generateHmac(message, key1)

        with pytest.raises(Exception, match="HMAC verification failed"):
            verifyHmac(message, key2, mac)

class TestCommunication:
    """Tests for multiprocessing communication."""

    def testEndToEndCommunication(self):
        """Test full sender/receiver communication cycle."""
        plaintext = "Hello secure world!"
        config = {
            "lcg": {"m": 18446744073709551616, "a": 6364136223846793005, "c": 1442695040888963407},
            "diffieHellman": {
                "p": 25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357,
                "g": 2,
            },
            "crypto": {"aesKeyLength": 256, "hmacAlgorithm": "sha256", "maxChunkSize": 10},
        }

        result = runCommunication(plaintext, config)

        assert result.get("success") is True
        assert result.get("decryptedText") == plaintext

    def testLongMessageCommunication(self):
        """Test communication with a longer message."""
        plaintext = "This is a much longer message that will be split into multiple chunks for transmission testing purposes."
        config = {
            "lcg": {"m": 18446744073709551616, "a": 6364136223846793005, "c": 1442695040888963407},
            "diffieHellman": {
                "p": 25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357,
                "g": 2,
            },
            "crypto": {"aesKeyLength": 256, "hmacAlgorithm": "sha256", "maxChunkSize": 10},
        }

        result = runCommunication(plaintext, config)

        assert result.get("success") is True
        assert result.get("decryptedText") == plaintext

class TestRsaAuthentication:
    """Tests for RSA-PSS digital signature authentication."""

    def testRsaSignatureValid(self):
        """Verify RSA-PSS signature passes for valid signed payload."""
        rsaPrivate, rsaPublic = generateRsaKeypair()
        payload = b"test payload for signing"

        signature = signPayload(payload, rsaPrivate)
        verifySignature(payload, signature, rsaPublic)

    def testMitmRejection(self):
        """Verify MITM attack is rejected when DH key is tampered."""
        senderRsaPrivate, senderRsaPublic = generateRsaKeypair()

        payloadOriginal = b"original dh public key bytes"
        payloadTampered = b"tampered dh public key bytes"

        signature = signPayload(payloadOriginal, senderRsaPrivate)

        with pytest.raises(Exception, match="MITM detected"):
            verifySignature(payloadTampered, signature, senderRsaPublic)

    def testWrongPublicKeyRejection(self):
        """Verify signature fails when using wrong RSA public key."""
        senderRsaPrivate, senderRsaPublic = generateRsaKeypair()
        _, receiverRsaPublic = generateRsaKeypair()

        payload = b"dh public key bytes"
        signature = signPayload(payload, senderRsaPrivate)

        with pytest.raises(Exception, match="MITM detected"):
            verifySignature(payload, signature, receiverRsaPublic)
