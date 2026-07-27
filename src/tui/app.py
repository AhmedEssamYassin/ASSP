"""Textual TUI application for the Authenticated Secure Stream Protocol Server."""

from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, RichLog
from textual.containers import Vertical
import threading
import queue

from src.communication.server import runServer
from src.communication.server_callbacks import ServerCallbacks

class TuiCallbacks(ServerCallbacks):
    """Callbacks that post messages to the Textual app's message queue."""
    def __init__(self, messageQueue):
        self.q = messageQueue
    
    def onBanner(self, host, port, fingerprint):
        self.q.put({"type": "banner", "host": host, "port": port, "fingerprint": fingerprint})
        
    def onConnectionStart(self, addr):
        self.q.put({"type": "connection", "addr": addr})
        
    def onStep(self, label, status="ok", detail=""):
        self.q.put({"type": "step", "label": label, "status": status, "detail": detail})
        
    def onDecrypted(self, plaintext):
        self.q.put({"type": "decrypted", "plaintext": plaintext})
        
    def onSasVerification(self, sasString):
        self.q.put({"type": "sas", "sasString": sasString})
        
    def onFileSaved(self, filename, size, path):
        self.q.put({"type": "file", "filename": filename, "size": size, "path": path})
        
    def onConnectionClosed(self):
        self.q.put({"type": "closed"})
        
    def onError(self, message):
        self.q.put({"type": "error", "message": message})

class ServerApp(App):
    """A Textual-based TUI for the Authenticated Secure Stream Protocol Server."""
    
    BINDINGS = [
        ("ctrl+c", "quit", "Quit")
    ]

    CSS = """
    RichLog {
        height: 1fr;
        border: solid cyan;
        background: $surface;
        padding: 0 2;
    }
    """
    
    def __init__(self, host="0.0.0.0", port=5000):
        super().__init__()
        self.host = host
        self.port = port
        self.msgQueue = queue.Queue()

    def compose(self) -> ComposeResult:
        yield Header("Authenticated Secure Stream Protocol - Secure Network Server")
        self.logWidget = RichLog(highlight=True, markup=True, wrap=True)
        yield self.logWidget
        yield Footer()

    def on_mount(self) -> None:
        """Start the background server thread and UI poller."""
        self.set_interval(0.1, self.pollQueue)
        callbacks = TuiCallbacks(self.msgQueue)
        self.serverThread = threading.Thread(target=runServer, args=(self.host, self.port, None, callbacks), daemon=True)
        self.serverThread.start()

    def pollQueue(self):
        """Poll the message queue and update the RichLog."""
        while not self.msgQueue.empty():
            msg = self.msgQueue.get()
            t = msg.get("type")
            
            if t == "banner":
                self.logWidget.write("[bold cyan]AUTHENTICATED SECURE STREAM PROTOCOL[/] - Secure Network Server")
                self.logWidget.write("[dim white]CSPRNG AES-256-CTR     KEX X25519 ECDH[/]")
                self.logWidget.write("[dim white]AUTH Ed25519 EdDSA     KDF HKDF-SHA256[/]")
                self.logWidget.write(f"\n[green]◉[/] Listening on [bold white]{msg['host']}:{msg['port']}[/]")
                if msg.get("fingerprint"):
                    self.logWidget.write(f"Key Fingerprint: [cyan]{msg['fingerprint']}[/]")
                self.logWidget.write("─" * 62)
                
            elif t == "connection":
                addr = msg['addr']
                self.logWidget.write(f"\n[bold white]◈ Incoming Connection[/] from [cyan]{addr[0]}:{addr[1]}[/]")
                
            elif t == "step":
                status = msg["status"]
                color = "green" if status in ("ok", "derived", "decrypted") else "yellow" if status == "working" else "red"
                detail = f" [dim]{msg['detail']}[/]" if msg.get("detail") else ""
                self.logWidget.write(f"  [gray]·[/] {msg['label']} [{color}]{status}[/]{detail}")
                
            elif t == "sas":
                self.logWidget.write(f"\n[bold yellow]SECURITY VERIFICATION[/]")
                self.logWidget.write(f"[gray]Compare these words with the sender:[/]")
                self.logWidget.write(f"  [bold cyan]{msg['sasString']}[/]")
                
            elif t == "decrypted":
                self.logWidget.write(f"\n[bold cyan]PLAINTEXT RECOVERED[/]")
                self.logWidget.write(f"[bold white]{msg['plaintext']}[/]")
                
            elif t == "file":
                self.logWidget.write(f"\n[cyan]▼[/] [white]Decrypted Payload (Binary File)[/]")
                self.logWidget.write(f"  [gray]Filename:[/] {msg['filename']}")
                self.logWidget.write(f"  [gray]Size:[/] {msg['size']} bytes")
                self.logWidget.write(f"  [gray]Saved To:[/] [green]{msg['path']}[/]")
                
            elif t == "closed":
                self.logWidget.write(f"\n[gray]◌ Connection closed · Waiting for next client...[/]")
                self.logWidget.write("─" * 62)
                
            elif t == "error":
                self.logWidget.write(f"[bold red]✗ Error: {msg['message']}[/]")
