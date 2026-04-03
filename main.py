"""Main entry point for the OTP Stream Cipher application using pywebview."""

import os
import sys
import json
import logging
from concurrent.futures import ThreadPoolExecutor

from src.communication.pipeline import runCommunication

logger = logging.getLogger(__name__)


class ApiBridge:
    """Bridge class exposing backend functions to the pywebview frontend."""

    def __init__(self):
        """Initialize the API bridge with configuration."""
        from src.crypto.lcg import loadConfig

        self.config = loadConfig()
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.logs = []

    def runTransmission(self, plaintext):
        """Run a full transmission cycle from the frontend (non-blocking)."""
        try:
            self.logs = []

            result = runCommunication(plaintext, self.config)

            if result.get("success"):
                cipherChunks = result.get("cipherChunks", [])
                decryptedText = result.get("decryptedText", "")

                formattedChunks = []
                maxChunkSize = self.config["crypto"]["maxChunkSize"]
                for i, chunk in enumerate(cipherChunks):
                    startIdx = i * maxChunkSize
                    endIdx = min(startIdx + maxChunkSize, len(plaintext))
                    formattedChunks.append({
                        "index": i + 1,
                        "plain": plaintext[startIdx:endIdx],
                        "cipher": chunk,
                    })

                return {
                    "success": True,
                    "cipherChunks": formattedChunks,
                    "decryptedText": decryptedText,
                }
            else:
                return {
                    "success": False,
                    "error": result.get("error", "Unknown error"),
                }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
            }

    def fetchLogs(self):
        """Retrieve accumulated logs."""
        return self.logs


def setupEnvironment():
    """Set up environment variables and paths."""
    os.environ["PYWEBVIEW_LOG_LEVEL"] = "error"


def main():
    """Initialize and run the pywebview application."""
    import webview

    api = ApiBridge()

    uiPath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src", "ui", "views", "index.html")

    window = webview.create_window(
        title="One-Time Pad Stream Cipher",
        url=uiPath,
        js_api=api,
        width=1200,
        height=800,
        resizable=True,
        background_color="#111111",
    )

    webview.start(debug=False)


if __name__ == "__main__":
    setupEnvironment()
    main()
