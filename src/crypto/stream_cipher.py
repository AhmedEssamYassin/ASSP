"""Stream Cipher module implementing OTP-style XOR encryption with CSPRNG keystream."""

import logging

logger = logging.getLogger(__name__)

class StreamCipher:
    """Stream cipher that XORs plaintext/ciphertext with CSPRNG-generated keystream.

    Operates on raw UTF-8 bytes to safely handle multi-byte Unicode characters
    (Arabic, Japanese, Emoji, etc.) without truncation or overflow.
    """

    def __init__(self, csprng, maxChunkSize=10):
        """Initialize cipher with a CSPRNG generator instance.

        Args:
            csprng: A CsprngGenerator instance (dependency injection)
            maxChunkSize: Maximum bytes per chunk (default 10)
        """
        self.csprng = csprng
        self.maxChunkSize = maxChunkSize

    def encrypt(self, plaintext):
        """Encrypt plaintext by XORing UTF-8 bytes with keystream."""
        plaintextBytes = plaintext.encode("utf-8")
        chunks = self._splitIntoChunks(plaintextBytes)
        cipherChunks = []
        for chunk in chunks:
            cipherBytes = []
            for byteVal in chunk:
                keyByte = self.csprng.getNextByte()
                cipherByte = byteVal ^ keyByte
                cipherBytes.append(cipherByte)
            hexChunk = bytes(cipherBytes).hex()
            cipherChunks.append(hexChunk)
            logger.info("Encrypt chunk: %s -> %s", chunk.hex(), hexChunk)
        return cipherChunks

    def decrypt(self, cipherChunks):
        """Decrypt ciphertext chunks back to plaintext via UTF-8 decode."""
        allBytes = bytearray()
        for chunkHex in cipherChunks:
            cipherBytes = bytes.fromhex(chunkHex)
            for cipherByte in cipherBytes:
                keyByte = self.csprng.getNextByte()
                plainByte = cipherByte ^ keyByte
                allBytes.append(plainByte)
            logger.info("Decrypt chunk: %s -> %s", chunkHex, bytes(allBytes[-len(cipherBytes):]).hex())
        return allBytes.decode("utf-8")

    def _splitIntoChunks(self, data):
        """Split byte data into chunks of maxChunkSize bytes."""
        return [data[i:i + self.maxChunkSize] for i in range(0, len(data), self.maxChunkSize)]

