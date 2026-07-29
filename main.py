"""Main entry point for the Authenticated Secure Stream Protocol application using pywebview."""

import os
import logging
import threading
import queue
import datetime
import re

from src.communication.client import runClient

logger = logging.getLogger(__name__)

class ApiBridge:
    """Bridge class exposing backend functions to the pywebview frontend."""

    def __init__(self):
        """Initialize the API bridge with configuration."""
        from src.crypto.config import loadConfig

        self.config = loadConfig()
        self.history = []
        self._progressQueue = queue.Queue()
        self._sasQueue = queue.Queue()
        self.metrics = {
            "total_transmissions": 0,
            "total_bytes_encrypted": 0,
            "failed_transmissions": 0
        }
        self._metricsLock = threading.Lock()

    def fetchProgress(self):
        """Return and clear all pending progress events for JS polling."""
        events = []
        while not self._progressQueue.empty():
            try:
                events.append(self._progressQueue.get_nowait())
            except queue.Empty:
                break
        return events

    def submitSas(self, approved):
        """Submit the SAS verification result from the UI."""
        self._sasQueue.put(approved)

    def runTransmission(self, plaintext, host="127.0.0.1", port=5000):
        """Run a full transmission cycle from the frontend (blocking — runs on the caller's thread)."""
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        transmissionCounted = False
        try:
            while not self._sasQueue.empty():
                try:
                    self._sasQueue.get_nowait()
                except queue.Empty:
                    break
            def askSas(sasStr):
                self._progressQueue.put({"stage": "sas_verification", "sas": sasStr})
                return self._sasQueue.get()

            payloadBytes = plaintext.encode("utf-8")
            result = runClient(
                payloadBytes, 
                {"type": "text"}, 
                self.config, 
                host, 
                int(port),
                onProgress=lambda e: self._progressQueue.put(e),
                askSas=askSas
            )
            
            with self._metricsLock:
                self.metrics["total_transmissions"] += 1
            transmissionCounted = True

            if result.get("success"):
                cipherChunks = result.get("cipherChunks", [])
                
                payloadBytesCount = len(plaintext.encode('utf-8'))
                with self._metricsLock:
                    self.metrics["total_bytes_encrypted"] += payloadBytesCount
                
                self.history.insert(0, {
                    "id": f"TX-{self.metrics['total_transmissions']:04d}",
                    "timestamp": ts,
                    "target": f"{host}:{port}",
                    "status": "Success",
                    "bytes": payloadBytesCount
                })

                from src.crypto.payload_formatter import packPayload
                
                packedBytes = packPayload({"type": "text"}, payloadBytes)
                formattedChunks = []
                maxChunkSize = self.config["crypto"]["maxChunkSize"]
                
                for i, chunk in enumerate(cipherChunks):
                    startIdx = i * maxChunkSize
                    endIdx = min(startIdx + maxChunkSize, len(packedBytes))
                    
                    chunkSlice = packedBytes[startIdx:endIdx]
                    plainStr = chunkSlice.decode("utf-8", errors="replace")
                    plainStr = re.sub(r'[\x00-\x1f\x7f-\x9f]', '·', plainStr)
                    
                    formattedChunks.append({
                        "index": i + 1,
                        "plain": plainStr,
                        "cipher": chunk,
                    })

                return {
                    "success": True,
                    "cipherChunks": formattedChunks,
                }
            else:
                with self._metricsLock:
                    self.metrics["failed_transmissions"] += 1
                    self.history.insert(0, {
                        "id": f"TX-{self.metrics['total_transmissions']:04d}",
                        "timestamp": ts,
                        "target": f"{host}:{port}",
                        "status": "Failed",
                        "bytes": 0
                    })
                
                return {
                    "success": False,
                    "error": result.get("error", "Unknown error"),
                }
        except Exception as e:
            with self._metricsLock:
                if not transmissionCounted:
                    self.metrics["total_transmissions"] += 1
                self.metrics["failed_transmissions"] += 1
                self.history.insert(0, {
                    "id": f"TX-{self.metrics['total_transmissions']:04d}",
                    "timestamp": ts,
                    "target": f"{host}:{port}",
                    "status": "Error",
                    "bytes": 0
                })
            return {
                "success": False,
                "error": str(e),
            }

    def sendLongText(self, text, host="127.0.0.1", port=5000):
        """Transmit a very long pasted text using the file streaming pipeline."""
        while not self._progressQueue.empty():
            try:
                self._progressQueue.get_nowait()
            except queue.Empty:
                break

        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        filename = "pasted_text.txt"
        payloadBytes = text.encode("utf-8")
        fileSize = len(payloadBytes)

        def transmitWorker():
            transmissionCounted = False
            try:
                self._progressQueue.put({"stage": "reading"})
                self._progressQueue.put({"stage": "reading_done", "bytes": fileSize})

                def onProgress(event):
                    self._progressQueue.put(event)

                while not self._sasQueue.empty():
                    try:
                        self._sasQueue.get_nowait()
                    except queue.Empty:
                        break
                def askSas(sasStr):
                    self._progressQueue.put({"stage": "sas_verification", "sas": sasStr})
                    return self._sasQueue.get()

                metadata = {"type": "file", "filename": filename}
                res = runClient(
                    payloadBytes, 
                    metadata, 
                    self.config, 
                    host, 
                    int(port), 
                    onProgress=onProgress,
                    askSas=askSas
                )

                with self._metricsLock:
                    self.metrics["total_transmissions"] += 1
                transmissionCounted = True
                if res.get("success"):
                    with self._metricsLock:
                        self.metrics["total_bytes_encrypted"] += fileSize
                    self.history.insert(0, {
                        "id": f"TX-{self.metrics['total_transmissions']:04d}",
                        "timestamp": ts,
                        "target": f"{host}:{port}",
                        "status": "Success",
                        "bytes": fileSize
                    })
                    self._progressQueue.put({
                        "stage": "complete",
                        "success": True,
                        "filename": filename,
                        "total_chunks": len(res.get("cipherChunks", []))
                    })
                else:
                    with self._metricsLock:
                        self.metrics["failed_transmissions"] += 1
                        self.history.insert(0, {
                            "id": f"TX-{self.metrics['total_transmissions']:04d}",
                            "timestamp": ts,
                            "target": f"{host}:{port}",
                            "status": "Failed",
                            "bytes": 0
                        })
                    self._progressQueue.put({
                        "stage": "complete",
                        "success": False,
                        "error": res.get("error", "Unknown error")
                    })
            except Exception as e:
                with self._metricsLock:
                    if not transmissionCounted:
                        self.metrics["total_transmissions"] += 1
                    self.metrics["failed_transmissions"] += 1
                    self.history.insert(0, {
                        "id": f"TX-{self.metrics['total_transmissions']:04d}",
                        "timestamp": ts,
                        "target": f"{host}:{port}",
                        "status": "Error",
                        "bytes": 0
                    })
                self._progressQueue.put({
                    "stage": "complete",
                    "success": False,
                    "error": str(e)
                })

        thread = threading.Thread(target=transmitWorker, daemon=True)
        thread.start()
        return {"status": "polling", "filename": filename, "size": fileSize}

    def selectAndSendFile(self, host="127.0.0.1", port=5000):
        """Open file dialog on main thread, then transmit on background thread."""
        import webview

        fileTypes = ('All files (*.*)',)
        result = webview.windows[0].create_file_dialog(webview.FileDialog.OPEN, allow_multiple=False, file_types=fileTypes)

        if not result:
            return {"status": "cancelled"}

        filePath = result[0]
        filename = os.path.basename(filePath)
        fileSize = os.path.getsize(filePath)

        # Reset progress queue for this new transmission
        while not self._progressQueue.empty():
            try:
                self._progressQueue.get_nowait()
            except queue.Empty:
                break

        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        def transmitWorker():
            transmissionCounted = False
            try:
                self._progressQueue.put({"stage": "reading"})
                with open(filePath, "rb") as f:
                    payloadBytes = f.read()
                self._progressQueue.put({"stage": "reading_done", "bytes": len(payloadBytes)})

                def onProgress(event):
                    self._progressQueue.put(event)

                while not self._sasQueue.empty():
                    try:
                        self._sasQueue.get_nowait()
                    except queue.Empty:
                        break
                def askSas(sasStr):
                    self._progressQueue.put({"stage": "sas_verification", "sas": sasStr})
                    return self._sasQueue.get()

                metadata = {"type": "file", "filename": filename}
                res = runClient(
                    payloadBytes, 
                    metadata, 
                    self.config, 
                    host, 
                    int(port), 
                    onProgress=onProgress,
                    askSas=askSas
                )

                with self._metricsLock:
                    self.metrics["total_transmissions"] += 1
                transmissionCounted = True
                if res.get("success"):
                    with self._metricsLock:
                        self.metrics["total_bytes_encrypted"] += len(payloadBytes)
                    self.history.insert(0, {
                        "id": f"TX-{self.metrics['total_transmissions']:04d}",
                        "timestamp": ts,
                        "target": f"{host}:{port}",
                        "status": "Success",
                        "bytes": len(payloadBytes)
                    })
                    self._progressQueue.put({
                        "stage": "complete",
                        "success": True,
                        "filename": filename,
                        "total_chunks": len(res.get("cipherChunks", []))
                    })
                else:
                    with self._metricsLock:
                        self.metrics["failed_transmissions"] += 1
                        self.history.insert(0, {
                            "id": f"TX-{self.metrics['total_transmissions']:04d}",
                            "timestamp": ts,
                            "target": f"{host}:{port}",
                            "status": "Failed",
                            "bytes": 0
                        })
                    self._progressQueue.put({
                        "stage": "complete",
                        "success": False,
                        "error": res.get("error", "Unknown error")
                    })
            except Exception as e:
                with self._metricsLock:
                    if not transmissionCounted:
                        self.metrics["total_transmissions"] += 1
                    self.metrics["failed_transmissions"] += 1
                    self.history.insert(0, {
                        "id": f"TX-{self.metrics['total_transmissions']:04d}",
                        "timestamp": ts,
                        "target": f"{host}:{port}",
                        "status": "Error",
                        "bytes": 0
                    })
                self._progressQueue.put({
                    "stage": "complete",
                    "success": False,
                    "error": str(e)
                })

        thread = threading.Thread(target=transmitWorker, daemon=True)
        thread.start()

        return {"status": "polling", "filename": filename, "size": fileSize}

    def fetchMonitorData(self):
        """Fetch metrics and transmission history for the Monitor tab."""
        return {
            "metrics": self.metrics,
            "history": self.history
        }

def setupEnvironment():
    """Set up environment variables and paths."""
    os.environ["PYWEBVIEW_LOG_LEVEL"] = "error"

def main():
    """Initialize and run the pywebview application."""
    import webview

    api = ApiBridge()

    uiPath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src", "ui", "views", "index.html")
    iconPath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src", "ui", "views", "assets", "app-icon.ico")
    
    if not os.path.exists(iconPath):
        print("[Warning] App icon not found, launching without icon.")
        iconPath = None

    window = webview.create_window(
        title="Authenticated Secure Stream Protocol",
        url=uiPath,
        js_api=api,
        width=1200,
        height=800,
        resizable=True,
        background_color="#111111",
    )

    webview.start(debug=False, icon=iconPath)


if __name__ == "__main__":
    setupEnvironment()
    main()
