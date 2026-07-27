"""Stream Cipher module implementing XOR encryption with CSPRNG keystream."""

import logging

logger = logging.getLogger(__name__)

class StreamCipher:
    """Stream cipher that XORs plaintext/ciphertext with CSPRNG-generated keystream.

    Operates on raw bytes to safely handle any binary data (images, PDFs, 
    executables) without being restricted to UTF-8 text.
    """

    def __init__(self, csprng, maxChunkSize=10):
        """Initialize cipher with a CSPRNG generator instance.

        Args:
            csprng: A CsprngGenerator instance (dependency injection)
            maxChunkSize: Maximum bytes per chunk (default 10)
        """
        self.csprng = csprng
        self.maxChunkSize = maxChunkSize


    def encryptStream(self, data):
        """Encrypt data as a generator, yielding one hex-encoded chunk at a time.

        This allows the caller to transmit each chunk immediately after encryption
        rather than buffering the entire ciphertext in memory first.
        """
        for chunk in self._splitIntoChunks(data):
            cipherBytes = []
            for byteVal in chunk:
                keyByte = self.csprng.getNextByte()
                cipherBytes.append(byteVal ^ keyByte)
            hexChunk = bytes(cipherBytes).hex()
            logger.debug("Encrypt chunk (%d bytes)", len(hexChunk) // 2)
            yield hexChunk

    def decrypt(self, cipherChunks):
        """Decrypt ciphertext chunks back to raw bytes."""
        allBytes = bytearray()
        for chunkHex in cipherChunks:
            cipherBytes = bytes.fromhex(chunkHex)
            for cipherByte in cipherBytes:
                keyByte = self.csprng.getNextByte()
                plainByte = cipherByte ^ keyByte
                allBytes.append(plainByte)
            logger.debug("Decrypt chunk received (%d bytes)", len(cipherBytes))
        return bytes(allBytes)

    def _splitIntoChunks(self, data):
        """Split byte data into chunks of maxChunkSize bytes."""
        for i in range(0, len(data), self.maxChunkSize):
            yield data[i:i + self.maxChunkSize]

