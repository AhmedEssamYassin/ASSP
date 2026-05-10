"""Parallel communication simulator using multiprocessing for sender/receiver."""

import multiprocessing
import os
import logging

from src.crypto.config import loadConfig
from src.crypto.csprng import CsprngGenerator
from src.crypto.key_exchange import EcdhKeyExchange
from src.crypto.seed_encryption import encryptSeed, decryptSeed
from src.crypto.stream_cipher import StreamCipher
from src.crypto.ed25519_authentication import (
    deserializePrivateKey,
    deserializePublicKey,
    signPayload,
    verifySignature,
)

logger = logging.getLogger(__name__)

def senderProcess(pipeConn, plaintext, config, senderEd25519PrivatePem, receiverEd25519PublicPem, resultQueue):
    """Sender process: performs Ed25519-signed X25519 key exchange, encrypts seed, sends ciphertext chunks."""
    logger.info("=== SENDER PROCESS STARTED ===")

    senderEd25519Private = deserializePrivateKey(senderEd25519PrivatePem)
    receiverEd25519Public = deserializePublicKey(receiverEd25519PublicPem)

    ecdh = EcdhKeyExchange()
    senderPrivate, senderPublic = ecdh.generateKeypair()

    senderPublicBytes = ecdh.serializePublicKey(senderPublic)
    senderSignature = signPayload(senderPublicBytes, senderEd25519Private)

    pipeConn.send((senderPublicBytes, senderSignature))
    logger.info("Sender sent signed public key")

    receiverPublicBytes, receiverSignature = pipeConn.recv()
    logger.info("Sender received receiver public key")

    verifySignature(receiverPublicBytes, receiverSignature, receiverEd25519Public)
    logger.info("Sender verified receiver public key signature")

    receiverPublic = ecdh.deserializePublicKey(receiverPublicBytes)
    sharedKey = ecdh.deriveSharedKey(senderPrivate, receiverPublic)
    logger.info("Sender derived shared key")

    seedBytes = os.urandom(32)
    logger.info("Generated random 32-byte seed")

    nonce, encryptedSeed = encryptSeed(seedBytes, sharedKey)

    vault = nonce + encryptedSeed
    pipeConn.send(vault)
    logger.info("Sender transmitted encrypted seed vault")

    csprng = CsprngGenerator(seedBytes)
    cipher = StreamCipher(csprng, config["crypto"]["maxChunkSize"])

    logger.info("Encrypting plaintext")
    cipherChunks = cipher.encrypt(plaintext)

    for chunk in cipherChunks:
        pipeConn.send(chunk)

    pipeConn.send("__END__")

    resultQueue.put({"cipherChunks": cipherChunks, "success": True})
    logger.info("=== SENDER PROCESS COMPLETED ===")
    pipeConn.close()

def receiverProcess(pipeConn, config, receiverEd25519PrivatePem, senderEd25519PublicPem, resultQueue):
    """Receiver process: verifies Ed25519-signed X25519 keys, decrypts ciphertext."""
    logger.info("=== RECEIVER PROCESS STARTED ===")

    receiverEd25519Private = deserializePrivateKey(receiverEd25519PrivatePem)
    senderEd25519Public = deserializePublicKey(senderEd25519PublicPem)

    ecdh = EcdhKeyExchange()
    receiverPrivate, receiverPublic = ecdh.generateKeypair()

    senderPublicBytes, senderSignature = pipeConn.recv()
    logger.info("Receiver received sender public key")

    verifySignature(senderPublicBytes, senderSignature, senderEd25519Public)
    logger.info("Receiver verified sender public key signature")

    receiverPublicBytes = ecdh.serializePublicKey(receiverPublic)
    receiverSignature = signPayload(receiverPublicBytes, receiverEd25519Private)

    pipeConn.send((receiverPublicBytes, receiverSignature))
    logger.info("Receiver sent signed public key")

    senderPublic = ecdh.deserializePublicKey(senderPublicBytes)
    sharedKey = ecdh.deriveSharedKey(receiverPrivate, senderPublic)
    logger.info("Receiver derived shared key")

    vault = pipeConn.recv()
    nonce = vault[:12]
    encryptedSeed = vault[12:]

    try:
        seedBytes = decryptSeed(nonce, encryptedSeed, sharedKey)
        logger.info("Receiver recovered seed")
    except Exception:
        logger.error("Receiver: Aborting - AES-GCM tag verification failed")
        resultQueue.put({"decryptedText": "", "success": False, "error": "AES-GCM tag verification failed"})
        pipeConn.close()
        return

    csprng = CsprngGenerator(seedBytes)
    cipher = StreamCipher(csprng, config["crypto"]["maxChunkSize"])

    cipherChunks = []
    while True:
        if not pipeConn.poll(timeout=5.0):
            logger.error("Receiver: Connection timed out waiting for data")
            break
        chunk = pipeConn.recv()
        if chunk == "__END__":
            break
        cipherChunks.append(chunk)

    logger.info("Decrypting %s chunks...", len(cipherChunks))
    decryptedText = cipher.decrypt(cipherChunks)

    resultQueue.put({"decryptedText": decryptedText, "success": True})
    logger.info("Decryption completed")
    logger.info("=== RECEIVER PROCESS COMPLETED ===")
    pipeConn.close()


def runCommunication(plaintext, config=None):
    """Run sender and receiver processes in parallel with Ed25519-signed X25519 key exchange."""
    from src.crypto.ed25519_authentication import (
        generateSigningKeypair,
        serializePrivateKey,
        serializePublicKey,
    )

    if config is None:
        config = loadConfig()

    senderEd25519Private, senderEd25519Public = generateSigningKeypair()
    receiverEd25519Private, receiverEd25519Public = generateSigningKeypair()

    senderEd25519PrivatePem = serializePrivateKey(senderEd25519Private)
    receiverEd25519PrivatePem = serializePrivateKey(receiverEd25519Private)
    senderEd25519PublicPem = serializePublicKey(senderEd25519Public)
    receiverEd25519PublicPem = serializePublicKey(receiverEd25519Public)

    parentConn, childConn = multiprocessing.Pipe()
    resultQueue = multiprocessing.Queue()

    sender = multiprocessing.Process(
        target=senderProcess,
        args=(parentConn, plaintext, config, senderEd25519PrivatePem, receiverEd25519PublicPem, resultQueue),
    )
    receiver = multiprocessing.Process(
        target=receiverProcess,
        args=(childConn, config, receiverEd25519PrivatePem, senderEd25519PublicPem, resultQueue),
    )

    receiver.start()
    sender.start()

    sender.join()
    receiver.join()

    results = {}
    while not resultQueue.empty():
        results.update(resultQueue.get())

    return results
