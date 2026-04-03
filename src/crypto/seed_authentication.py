"""Seed authentication module using HMAC-SHA256 for integrity verification."""

import hmac
import hashlib
import logging

logger = logging.getLogger(__name__)


def generateHmac(message, key):
    """Generate HMAC-SHA256 for a message."""
    mac = hmac.new(key, message, hashlib.sha256).digest()
    logger.info("Generated HMAC: %s", mac.hex())
    return mac

def verifyHmac(message, key, providedHmac):
    """Verify HMAC-SHA256 using constant-time comparison to prevent timing attacks."""
    expectedHmac = hmac.new(key, message, hashlib.sha256).digest()
    if not hmac.compare_digest(expectedHmac, providedHmac):
        logger.error("HMAC verification failed - message may be tampered")
        raise Exception("HMAC verification failed: message integrity compromised")
    logger.info("HMAC verification: PASSED")
