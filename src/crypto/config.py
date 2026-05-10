"""Configuration loader module."""

import json
import logging
import os

logger = logging.getLogger(__name__)

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
