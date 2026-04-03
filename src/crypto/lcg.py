"""Linear Congruential Generator (LCG) module for pseudo-random keystream generation."""

import json
import logging
import os

logger = logging.getLogger(__name__)


class LcgGenerator:
    """Generates pseudo-random bytes using the Linear Congruential Generator algorithm.

    Uses 64-bit Knuth parameters and extracts high-order bits to avoid
    the short-period vulnerability of low-bit extraction on power-of-2 moduli.
    """

    def __init__(self, seed, modulus, multiplier, increment):
        """Initialize LCG with seed and parameters."""
        self.state = seed
        self.modulus = modulus
        self.multiplier = multiplier
        self.increment = increment

    def getNextByte(self):
        """Compute next LCG state and return a byte from the high-order bits.

        Extracts bits 56-63 to avoid the periodicity vulnerability of
        low-order bits when modulus is a power of 2.
        """
        self.state = (self.multiplier * self.state + self.increment) % self.modulus
        return (self.state >> 56) & 0xFF

def loadConfig(configPath=None):
    """Load configuration from JSON file. Fails hard on missing/invalid config."""
    if configPath is None:
        configPath = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "config", "default_config.json")
    try:
        with open(configPath, "r") as f:
            config = json.load(f)
        logger.info("Configuration loaded from %s", configPath)
        return config
    except Exception as e:
        logger.critical("FATAL: Could not load config from %s: %s", configPath, e)
        raise SystemExit(f"Failed to load config: {e}")
