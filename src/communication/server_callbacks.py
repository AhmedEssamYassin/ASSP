"""Server callback interfaces for decoupling server.py from its output targets.

Provides a base class (ServerCallbacks) and two concrete implementations:
- TerminalCallbacks: forwards events to terminal_ui.py for --no-tui mode.
- TuiCallbacks (in src/tui/app.py): forwards events to the Textual TUI.
"""


class ServerCallbacks:
    """Base class for server event callbacks."""
    def onBanner(self, host, port, fingerprint): pass
    def onConnectionStart(self, addr): pass
    def onStep(self, label, status="ok", detail=""): pass
    def onDecrypted(self, plaintext): pass
    def onSasVerification(self, sasString): pass
    def onFileSaved(self, filename, size, path): pass
    def onConnectionClosed(self): pass
    def onError(self, message): pass

class TerminalCallbacks(ServerCallbacks):
    """Callbacks that print to the standard terminal UI."""
    def onBanner(self, host, port, fingerprint):
        from src.terminal_ui import printBanner
        printBanner(host, port, fingerprint)
        
    def onConnectionStart(self, addr):
        from src.terminal_ui import printConnectionStart
        printConnectionStart(addr)
        
    def onStep(self, label, status="ok", detail=""):
        from src.terminal_ui import printStep
        printStep(label, status, detail)
        
    def onDecrypted(self, plaintext):
        from src.terminal_ui import printDecrypted
        printDecrypted(plaintext)
        
    def onSasVerification(self, sasString):
        from src.terminal_ui import printSasVerification
        printSasVerification(sasString)
        
    def onFileSaved(self, filename, size, path):
        from src.terminal_ui import printFileSaved
        printFileSaved(filename, size, path)
        
    def onConnectionClosed(self):
        from src.terminal_ui import printConnectionClosed
        printConnectionClosed()
        
    def onError(self, message):
        from src.terminal_ui import printError
        printError(message)
