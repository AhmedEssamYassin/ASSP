"""TCP Server component for receiving and decrypting the Authenticated Secure Stream Protocol."""

import socket
import logging
import sys
import os
import argparse
import re

# Add the project root to the python path so we can run this directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.crypto.config import loadConfig, getNetworkTimeout
from src.crypto.csprng import CsprngGenerator
from src.crypto.key_exchange import EcdhKeyExchange
from src.crypto.seed_encryption import decryptSeed
from src.crypto.stream_cipher import StreamCipher
from src.crypto.payload_formatter import unpackPayload
from src.crypto.sas import deriveSas, formatSas
from src.crypto.known_servers import saveKnownServer, isTrusted
from src.crypto.ed25519_authentication import (
    deserializePublicKey,
    serializePublicKey,
    signPayload,
    verifySignature,
    computeFingerprint,
    generateSigningKeypair,
)
from src.communication.framing import recvExact, recvFramed, sendFramed
from src.communication.server_callbacks import TerminalCallbacks

# Keep file-level logging at WARNING so it doesn't pollute the pretty output
logger = logging.getLogger("Server")

VAULT_GCM_NONCE_LEN      = 12
VAULT_ENCRYPTED_SEED_LEN = 48   # 32-byte seed + 16-byte GCM tag
VAULT_CSPRNG_NONCE_LEN   = 16
VAULT_TOTAL_LEN          = VAULT_GCM_NONCE_LEN + VAULT_ENCRYPTED_SEED_LEN + VAULT_CSPRNG_NONCE_LEN

def runServer(host="0.0.0.0", port=5000, config=None, callbacks=None):
    """Run the TCP receiver server."""
    if config is None:
        config = loadConfig()
    
    if callbacks is None:
        callbacks = TerminalCallbacks()

    receiverEd25519Private, receiverEd25519Public = generateSigningKeypair()
    fingerprint = computeFingerprint(receiverEd25519Public)

    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serverSocket.bind((host, port))
    serverSocket.listen(1)
    serverSocket.settimeout(1.0)

    callbacks.onBanner(host, port, fingerprint)

    try:
        while True:
            try:
                conn, addr = serverSocket.accept()
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                raise

            callbacks.onConnectionStart(addr)
            try:
                handleConnection(conn, addr, config, receiverEd25519Private, callbacks)
            except Exception as e:
                callbacks.onError(f"Unhandled connection error: {e}")
                logger.exception("Connection error")
            finally:
                conn.close()
                callbacks.onConnectionClosed()
    except KeyboardInterrupt:
        print("\n  [SERVER SHUTTING DOWN]")
    finally:
        serverSocket.close()

def handleConnection(conn, addr, config, receiverEd25519Private, callbacks):
    """Handle a full key exchange, seed reception, and data decryption for a single TCP client."""
    conn.settimeout(getNetworkTimeout(config))
    ecdh = EcdhKeyExchange()
    receiverPrivate, receiverPublic = ecdh.generateKeypair()

    # 1. Receive Sender's Ed25519 Public Key and signed X25519 Public Key
    senderEd25519PublicPemBytes = recvFramed(conn)
    senderPublicBytes = recvFramed(conn)
    senderSignature = recvFramed(conn)

    if not all([senderEd25519PublicPemBytes, senderPublicBytes, senderSignature]):
        callbacks.onError("Handshake incomplete — connection dropped.")
        return

    senderEd25519Public = deserializePublicKey(senderEd25519PublicPemBytes)

    # 2. Verify sender's identity
    try:
        verifySignature(senderPublicBytes, senderSignature, senderEd25519Public)
        callbacks.onStep("Ed25519 signature", "ok")
    except Exception as e:
        logger.exception("Ed25519 signature verification error")
        callbacks.onError("Ed25519 signature verification failed — possible MITM!")
        return

    # 3. Send Receiver's signed public key back
    receiverEd25519PublicPemBytes = serializePublicKey(receiverEd25519Private.public_key())
    receiverPublicBytes = ecdh.serializePublicKey(receiverPublic)
    receiverSignature = signPayload(receiverPublicBytes, receiverEd25519Private)

    sendFramed(conn, receiverEd25519PublicPemBytes)
    sendFramed(conn, receiverPublicBytes)
    sendFramed(conn, receiverSignature)

    # 4. Derive Shared Key
    senderPublic = ecdh.deserializePublicKey(senderPublicBytes)
    sharedKey = ecdh.deriveSharedKey(receiverPrivate, senderPublic)
    callbacks.onStep("X25519 shared key", "derived")

    # 4.5. SAS Verification
    senderFingerprint = computeFingerprint(senderEd25519Public)
    
    skipSas = config.get("security", {}).get("skipSasVerification", False)
    if skipSas:
        callbacks.onStep("SAS Verification", "ok", detail="(Skipped by config)")
    elif isTrusted(senderFingerprint):
        callbacks.onStep("SAS Verification", "ok", detail="(Cached from previous)")
    else:
        sasWords = deriveSas(sharedKey)
        callbacks.onSasVerification(formatSas(sasWords))
        
        callbacks.onStep("Waiting for client confirmation...", "working")
        confByte = recvExact(conn, 1)
        if confByte != b'\x01':
            callbacks.onError("Client rejected SAS or timeout.")
            return
            
        callbacks.onStep("SAS Verification", "ok", detail="(Client confirmed)")
        saveKnownServer(senderFingerprint)

    # 5. Receive and decrypt seed vault
    vault = recvFramed(conn)
    if not vault:
        callbacks.onError("Seed vault not received.")
        return

    if len(vault) != VAULT_TOTAL_LEN:
        callbacks.onError(f"Malformed seed vault: expected {VAULT_TOTAL_LEN} bytes, got {len(vault)}.")
        return

    gcmNonce      = vault[:VAULT_GCM_NONCE_LEN]
    encryptedSeed = vault[VAULT_GCM_NONCE_LEN : VAULT_GCM_NONCE_LEN + VAULT_ENCRYPTED_SEED_LEN]
    csprngNonce   = vault[VAULT_GCM_NONCE_LEN + VAULT_ENCRYPTED_SEED_LEN:]

    try:
        seedBytes = decryptSeed(gcmNonce, encryptedSeed, sharedKey)
        callbacks.onStep("AES-GCM seed vault", "decrypted")
    except Exception as e:
        logger.warning("AES-GCM decryption failed: %s", e, exc_info=True)
        callbacks.onError("AES-GCM tag mismatch — aborting.")
        return

    # 6. Initialize CSPRNG & Stream Cipher
    csprng = CsprngGenerator(seedBytes, nonceBytes=csprngNonce)
    cipher = StreamCipher(csprng, config["crypto"]["maxChunkSize"])

    # 7. Receive and decrypt ciphertext chunks
    cipherChunks = []
    while True:
        chunk = recvFramed(conn)
        if chunk is None:
            break
        if chunk == b"__END__":
            break
        cipherChunks.append(chunk.decode('utf-8'))

    callbacks.onStep(f"Ciphertext stream ({len(cipherChunks)} frames)", "working")

    try:
        decryptedBytes = cipher.decrypt(cipherChunks)
        metadata, rawBytes = unpackPayload(decryptedBytes)
        
        if metadata.get("type") == "text":
            callbacks.onDecrypted(rawBytes.decode("utf-8", errors="replace"))
        elif metadata.get("type") == "file":
            filename = os.path.basename(metadata.get("filename", "received_file.bin")) or "received_file.bin"
            filename = re.sub(r'[^\w\-. ]', '_', filename)
            downloadsDir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "downloads"))
            os.makedirs(downloadsDir, exist_ok=True)
            savePath = os.path.join(downloadsDir, filename)
            with open(savePath, "wb") as f:
                f.write(rawBytes)
            callbacks.onFileSaved(filename, len(rawBytes), savePath)
        else:
            callbacks.onError(f"Unknown payload type: {metadata.get('type')}")
            
    except Exception as e:
        callbacks.onError(f"Decryption or unpacking failed: {e}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)  # Keep at WARNING so it doesn't pollute the pretty output
    parser = argparse.ArgumentParser(description="Authenticated Secure Stream Protocol Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (use 0.0.0.0 for network access)")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on")
    parser.add_argument("--no-tui", action="store_true", help="Disable the Textual UI and use basic print output")
    args = parser.parse_args()

    if args.no_tui:
        runServer(host=args.host, port=args.port)
    else:
        # Import Textual app only when needed
        from src.tui.app import ServerApp
        app = ServerApp(host=args.host, port=args.port)
        app.run()
