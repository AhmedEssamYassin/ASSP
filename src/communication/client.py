"""TCP Client component for encrypting and sending the Authenticated Secure Stream Protocol."""

import socket
import logging
import os

from src.crypto.csprng import CsprngGenerator
from src.crypto.key_exchange import EcdhKeyExchange
from src.crypto.seed_encryption import encryptSeed
from src.crypto.stream_cipher import StreamCipher
from src.crypto.payload_formatter import packPayload
from src.crypto.config import getNetworkTimeout
from src.crypto.sas import deriveSas, formatSas
from src.crypto.known_servers import saveKnownServer, isTrusted
from src.crypto.ed25519_authentication import (
    deserializePublicKey,
    generateSigningKeypair,
    serializePublicKey,
    signPayload,
    verifySignature,
    computeFingerprint,
)
from src.communication.framing import recvFramed, sendFramed

logger = logging.getLogger(__name__)

def runClient(payloadBytes, metadata, config, host="127.0.0.1", port=5000, onProgress=None, askSas=None):
    """Run the TCP sender client."""
    def emit(event):
        """ Emit a progress event if a callback is registered. """
        if onProgress:
            onProgress(event)
    logger.info("=== SENDER CLIENT STARTED ===")
    
    logger.info("Generating Client Ed25519 Keypair...")
    senderEd25519Private, senderEd25519Public = generateSigningKeypair()

    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSocket.settimeout(getNetworkTimeout(config))
    try:
        clientSocket.connect((host, port))
        logger.info("Connected to Server at %s:%s", host, port)
        emit({"stage": "connected"})
    except Exception as e:
        logger.error("Failed to connect to Server: %s", e)
        clientSocket.close()
        return {"success": False, "error": f"Connection failed: {e}"}

    try:
        ecdh = EcdhKeyExchange()
        senderPrivate, senderPublic = ecdh.generateKeypair()

        # 1. Send Sender's Ed25519 Public Key and signed X25519 Public Key
        emit({"stage": "handshake"})
        senderEd25519PublicPemBytes = serializePublicKey(senderEd25519Public)
        senderPublicBytes = ecdh.serializePublicKey(senderPublic)
        senderSignature = signPayload(senderPublicBytes, senderEd25519Private)

        sendFramed(clientSocket, senderEd25519PublicPemBytes)
        sendFramed(clientSocket, senderPublicBytes)
        sendFramed(clientSocket, senderSignature)
        logger.info("Sender sent signed public key")

        # 2. Receive Receiver's Ed25519 Public Key and signed X25519 Public Key
        receiverEd25519PublicPemBytes = recvFramed(clientSocket)
        receiverPublicBytes = recvFramed(clientSocket)
        receiverSignature = recvFramed(clientSocket)

        if not all([receiverEd25519PublicPemBytes, receiverPublicBytes, receiverSignature]):
            raise Exception("Failed to receive receiver's handshake data.")

        receiverEd25519Public = deserializePublicKey(receiverEd25519PublicPemBytes)

        logger.info("Verifying receiver's signature...")
        verifySignature(receiverPublicBytes, receiverSignature, receiverEd25519Public)
        logger.info("Receiver signature verified successfully.")

        # 3. Derive Shared Key
        receiverPublic = ecdh.deserializePublicKey(receiverPublicBytes)
        sharedKey = ecdh.deriveSharedKey(senderPrivate, receiverPublic)
        logger.info("Derived X25519 shared key")

        # 3.5 SAS Verification
        receiverFingerprint = computeFingerprint(receiverEd25519Public)

        skipSas = config.get("security", {}).get("skipSasVerification", False)
        if skipSas:
            clientSocket.sendall(b'\x01')
            emit({"stage": "sas_verified"})
        elif isTrusted(receiverFingerprint):
            emit({"stage": "sas_cached"})
            clientSocket.sendall(b'\x01')
        else:
            sasWords = deriveSas(sharedKey)
            sasString = formatSas(sasWords)
            
            if askSas:
                approved = askSas(sasString)
            else:
                approved = False

            if not approved:
                clientSocket.sendall(b'\x00')
                raise Exception("User rejected SAS verification.")
            
            clientSocket.sendall(b'\x01')
            saveKnownServer(receiverFingerprint)
            emit({"stage": "sas_verified"})

        # 4. Generate & Encrypt Seed Vault
        seedBytes = os.urandom(32)
        logger.info("Generated random 32-byte seed")

        gcmNonce, encryptedSeed = encryptSeed(seedBytes, sharedKey)

        csprng = CsprngGenerator(seedBytes)
        csprngNonce = csprng.getNonce()

        vault = gcmNonce + encryptedSeed + csprngNonce
        sendFramed(clientSocket, vault)
        logger.info("Sender transmitted encrypted seed vault and CSPRNG nonce")
        emit({"stage": "handshake_done"})

        # 5. Stream: encrypt each chunk and send it immediately
        maxChunkSize = config.get("crypto", {}).get("maxChunkSize", 10)
        cipher = StreamCipher(csprng, maxChunkSize)

        logger.info("Encrypting and transmitting payload (streaming)")
        packedPayload = packPayload(metadata, payloadBytes)

        # Pre-compute total chunk count for progress tracking
        total = -(-len(packedPayload) // maxChunkSize) if packedPayload else 0
        progressStep = max(1, total // 200)  # ~200 UI updates max

        emit({"stage": "stream_start", "total_chunks": total, "total_bytes": len(packedPayload)})

        cipherChunks = []
        for i, hexChunk in enumerate(cipher.encryptStream(packedPayload)):
            cipherChunks.append(hexChunk)
            sendFramed(clientSocket, hexChunk.encode("utf-8"))
            if i % progressStep == 0 or i == total - 1:
                emit({"stage": "stream_progress", "sent": i + 1, "total": total})

        # Signal end of transmission
        sendFramed(clientSocket, b"__END__")
        emit({"stage": "stream_done", "total_chunks": len(cipherChunks)})

        logger.info("=== SENDER CLIENT COMPLETED ===")
        return {"cipherChunks": cipherChunks, "success": True}

    except Exception as e:
        logger.error("Error during client transmission: %s", e)
        return {"success": False, "error": str(e)}
    finally:
        clientSocket.close()
