"""Parallel communication simulator using multiprocessing for sender/receiver."""

import multiprocessing
import os
import logging

from src.crypto.lcg import loadConfig, LcgGenerator
from src.crypto.key_exchange import DiffieHellman
from src.crypto.seed_encryption import encryptSeed, decryptSeed
from src.crypto.seed_authentication import generateHmac, verifyHmac
from src.crypto.stream_cipher import StreamCipher
from src.crypto.rsa_authentication import (
    deserializeRsaPrivateKey,
    deserializeRsaPublicKey,
    signPayload,
    verifySignature,
)

logger = logging.getLogger(__name__)


def intToBytes(intVal):
    """Convert integer to bytes for signing."""
    return intVal.to_bytes((intVal.bit_length() + 7) // 8, byteorder="big")

def intToBytesFixed(intVal, length):
    """Convert integer to fixed-length bytes."""
    return intVal.to_bytes(length, byteorder="big")

def bytesToInt(byteVal):
    """Convert bytes back to integer."""
    return int.from_bytes(byteVal, byteorder="big")

def senderProcess(pipeConn, plaintext, config, senderRsaPrivatePem, receiverRsaPublicPem, resultQueue):
    """Sender process: performs RSA-signed DH key exchange, encrypts seed, sends ciphertext chunks."""
    logger.info("=== SENDER PROCESS STARTED ===")

    senderRsaPrivate = deserializeRsaPrivateKey(senderRsaPrivatePem)
    receiverRsaPublic = deserializeRsaPublicKey(receiverRsaPublicPem)

    dhParams = config["diffieHellman"]
    dh = DiffieHellman(dhParams["p"], dhParams["g"])

    senderPrivate = dh.generatePrivate()
    senderPublic = dh.generatePublic(senderPrivate)

    senderPublicBytes = intToBytesFixed(senderPublic, 256)
    senderSignature = signPayload(senderPublicBytes, senderRsaPrivate)

    pipeConn.send((senderPublic, senderSignature))
    logger.info("Sender sent signed public key")

    receiverPublic, receiverSignature = pipeConn.recv()
    logger.info("Sender received receiver public key")

    receiverPublicBytes = intToBytesFixed(receiverPublic, 256)
    verifySignature(receiverPublicBytes, receiverSignature, receiverRsaPublic)
    logger.info("Sender verified receiver public key signature")

    sharedKey = dh.deriveSharedKey(receiverPublic, senderPrivate)
    logger.info("Sender derived shared key")

    seed = int.from_bytes(os.urandom(8), byteorder="big")
    logger.info("Generated random seed")

    nonce, encryptedSeed = encryptSeed(seed, sharedKey)

    vault = nonce + encryptedSeed
    vaultHmac = generateHmac(vault, sharedKey)
    payload = vaultHmac + vault
    pipeConn.send(payload)
    logger.info("Sender transmitted encrypted seed payload")

    lcgParams = config["lcg"]
    lcg = LcgGenerator(seed, lcgParams["m"], lcgParams["a"], lcgParams["c"])
    cipher = StreamCipher(lcg, config["crypto"]["maxChunkSize"])

    logger.info("Encrypting plaintext")
    cipherChunks = cipher.encrypt(plaintext)

    for chunk in cipherChunks:
        pipeConn.send(chunk)

    pipeConn.send("__END__")

    resultQueue.put({"cipherChunks": cipherChunks, "success": True})
    logger.info("=== SENDER PROCESS COMPLETED ===")
    pipeConn.close()


def receiverProcess(pipeConn, config, receiverRsaPrivatePem, senderRsaPublicPem, resultQueue):
    """Receiver process: verifies RSA-signed DH keys, receives encrypted seed, verifies HMAC, decrypts ciphertext."""
    logger.info("=== RECEIVER PROCESS STARTED ===")

    receiverRsaPrivate = deserializeRsaPrivateKey(receiverRsaPrivatePem)
    senderRsaPublic = deserializeRsaPublicKey(senderRsaPublicPem)

    dhParams = config["diffieHellman"]
    dh = DiffieHellman(dhParams["p"], dhParams["g"])

    receiverPrivate = dh.generatePrivate()
    receiverPublic = dh.generatePublic(receiverPrivate)

    senderPublic, senderSignature = pipeConn.recv()
    logger.info("Receiver received sender public key")

    senderPublicBytes = intToBytesFixed(senderPublic, 256)
    verifySignature(senderPublicBytes, senderSignature, senderRsaPublic)
    logger.info("Receiver verified sender public key signature")

    receiverPublicBytes = intToBytesFixed(receiverPublic, 256)
    receiverSignature = signPayload(receiverPublicBytes, receiverRsaPrivate)

    pipeConn.send((receiverPublic, receiverSignature))
    logger.info("Receiver sent signed public key")

    sharedKey = dh.deriveSharedKey(senderPublic, receiverPrivate)
    logger.info("Receiver derived shared key")

    payload = pipeConn.recv()
    receivedHmac = payload[:32]
    vault = payload[32:]

    try:
        verifyHmac(vault, sharedKey, receivedHmac)
    except Exception:
        logger.error("Receiver: Aborting - HMAC verification failed")
        resultQueue.put({"decryptedText": "", "success": False, "error": "HMAC verification failed"})
        pipeConn.close()
        return

    nonce = vault[:12]
    encryptedSeed = vault[12:]

    seed = decryptSeed(nonce, encryptedSeed, sharedKey)
    logger.info("Receiver recovered seed")

    lcgParams = config["lcg"]
    lcg = LcgGenerator(seed, lcgParams["m"], lcgParams["a"], lcgParams["c"])
    cipher = StreamCipher(lcg, config["crypto"]["maxChunkSize"])

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
    """Run sender and receiver processes in parallel with RSA-signed DH key exchange."""
    from src.crypto.rsa_authentication import (
        generateRsaKeypair,
        serializeRsaPrivateKey,
        serializeRsaPublicKey,
    )

    if config is None:
        config = loadConfig()

    senderRsaPrivate, senderRsaPublic = generateRsaKeypair()
    receiverRsaPrivate, receiverRsaPublic = generateRsaKeypair()

    senderRsaPrivatePem = serializeRsaPrivateKey(senderRsaPrivate)
    receiverRsaPrivatePem = serializeRsaPrivateKey(receiverRsaPrivate)
    senderRsaPublicPem = serializeRsaPublicKey(senderRsaPublic)
    receiverRsaPublicPem = serializeRsaPublicKey(receiverRsaPublic)

    parentConn, childConn = multiprocessing.Pipe()
    resultQueue = multiprocessing.Queue()

    sender = multiprocessing.Process(
        target=senderProcess,
        args=(parentConn, plaintext, config, senderRsaPrivatePem, receiverRsaPublicPem, resultQueue),
    )
    receiver = multiprocessing.Process(
        target=receiverProcess,
        args=(childConn, config, receiverRsaPrivatePem, senderRsaPublicPem, resultQueue),
    )

    receiver.start()
    sender.start()

    sender.join()
    receiver.join()

    results = {}
    while not resultQueue.empty():
        results.update(resultQueue.get())

    return results
