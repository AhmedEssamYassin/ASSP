"""Terminal UI printer for the Authenticated Secure Stream Protocol server.

Provides rich, structured output using UTF-8 box-drawing characters
and ANSI color codes. All formatting is self-contained here so that
server.py stays clean.
"""

import sys
import datetime
import re
import socket

# ── ANSI color codes ──────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"


RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
GRAY   = "\033[90m"



# ── Width ─────────────────────────────────────────────────────────────────────
W = 62   # inner content width (between the border chars)

# ── Box primitives ────────────────────────────────────────────────────────────
def _top(style="double"):
    if style == "double":
        return f"  {GRAY}╔{'═' * W}╗{RESET}"
    return f"  {GRAY}┌{'─' * W}┐{RESET}"

def _bot(style="double"):
    if style == "double":
        return f"  {GRAY}╚{'═' * W}╝{RESET}"
    return f"  {GRAY}└{'─' * W}┘{RESET}"

def _div():
    return f"  {GRAY}╠{'═' * W}╣{RESET}"

def _row(text="", style="double"):
    """A bordered row. text is pre-colored; we strip ANSI for length calc."""
    visible = _stripAnsi(text)
    pad = W - len(visible)
    border = ("║" if style == "double" else "│")
    return f"  {GRAY}{border}{RESET}{text}{' ' * pad}{GRAY}{border}{RESET}"

def _sep():
    return f"  {GRAY}{'─' * (W + 2)}{RESET}"

def _blank(style="double"):
    return _row("", style)

def _stripAnsi(s):
    """Remove ANSI escape sequences for length calculation."""
    return re.sub(r"\033\[[0-9;]*m", "", s)

# ── Public API ────────────────────────────────────────────────────────────────

def printBanner(host, port, fingerprint=""):
    """Print the startup banner with protocol stack."""
    title = f"{BOLD}{CYAN}AUTHENTICATED SECURE STREAM PROTOCOL{RESET}  {DIM}{WHITE}·  Secure Network Server{RESET}"
    specLine1 = f"  {GRAY}CSPRNG{RESET}  {CYAN}AES-256-CTR{RESET}     {GRAY}KEX{RESET}   {CYAN}X25519 ECDH{RESET}"
    specLine2 = f"  {GRAY}AUTH  {RESET}  {CYAN}Ed25519 EdDSA{RESET}   {GRAY}KDF{RESET}   {CYAN}HKDF-SHA256{RESET}"
    specLine3 = f"  {GRAY}SEED  {RESET}  {CYAN}AES-256-GCM{RESET}"
    fpLine = f"  {GRAY}KEY   {RESET}  {CYAN}{fingerprint}{RESET}"
    addr = f"  {BOLD}{WHITE}{host}{RESET}{GRAY}:{RESET}{BOLD}{CYAN}{port}{RESET}"

    print()
    print(_top("double"))
    print(_row(""))
    print(_row(f"  {title}"))
    print(_row(""))
    print(_div())
    print(_row(f"  {specLine1}"))
    print(_row(f"  {specLine2}"))
    print(_row(f"  {specLine3}"))
    if fingerprint:
        print(_row(f"  {fpLine}"))
    print(_bot("double"))
    print()
    print(f"  {GREEN}◉{RESET}  Listening on  {addr}")
    if host in ("0.0.0.0", ""):
        try:
            ips = set(ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127."))
            for ip in sorted(ips):
                print(f"     {GRAY}Reachable at:{RESET} {BOLD}{WHITE}{ip}{RESET}{GRAY}:{RESET}{BOLD}{CYAN}{port}{RESET}")
        except Exception:
            print(f"     {GRAY}(Could not resolve local IP){RESET}")
    print(_sep())
    print()
    sys.stdout.flush()

def printConnectionStart(addr):
    """Print the start of a new connection block."""
    ip, port = addr
    ts = datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    heading = f" {BOLD}{WHITE}◈  Incoming Connection{RESET}"
    detail  = f"   {CYAN}{ip}{RESET}{GRAY}:{RESET}{CYAN}{port}{RESET}  {DIM}·  {ts}{RESET}"
    print()
    print(_top("single"))
    print(_row(heading, "single"))
    print(_row(detail, "single"))
    print(_bot("single"))
    print()
    sys.stdout.flush()

def printStep(label, status="ok", detail=""):
    """Print a single handshake step with a status indicator."""
    DOTS = 38
    visible_label = _stripAnsi(label)
    dots = "·" * max(2, DOTS - len(visible_label))
    if status == "ok":
        indicator = f"{GREEN}✓  verified{RESET}"
    elif status == "derived":
        indicator = f"{GREEN}✓  derived{RESET}"
    elif status == "decrypted":
        indicator = f"{GREEN}✓  decrypted{RESET}"
    elif status == "working":
        indicator = f"{YELLOW}…  working{RESET}"
    elif status == "fail":
        indicator = f"{RED}✗  failed{RESET}"
    else:
        indicator = f"{GRAY}{status}{RESET}"

    suffix = f"  {DIM}{detail}{RESET}" if detail else ""
    print(f"  {GRAY}  {label} {DIM}{dots}{RESET} {indicator}{suffix}")
    sys.stdout.flush()

def printDecrypted(plaintext):
    """Print the decrypted message in a highlighted box."""
    print()
    label = f"  {BOLD}{CYAN}PLAINTEXT RECOVERED{RESET}"
    print(_top("single"))
    print(_row(label, "single"))
    print(_blank("single"))

    # Word-wrap the message to fit inside the box
    maxInner = W - 4
    words = plaintext.split()
    lines = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 <= maxInner:
            current += ("" if not current else " ") + word
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)

    for line in lines:
        print(_row(f"    {BOLD}{WHITE}{line}{RESET}", "single"))

    print(_blank("single"))
    print(_bot("single"))
    print()
    sys.stdout.flush()

def printSasVerification(sasString):
    """Print the SAS words for manual verification."""
    print()
    label = f"  {BOLD}{YELLOW}SECURITY VERIFICATION{RESET}"
    print(_top("single"))
    print(_row(label, "single"))
    print(_blank("single"))
    print(_row(f"    {GRAY}Compare these words with the sender:{RESET}", "single"))
    print(_blank("single"))
    print(_row(f"    {BOLD}{CYAN}{sasString}{RESET}", "single"))
    print(_blank("single"))
    print(_bot("single"))
    print()
    sys.stdout.flush()

def printFileSaved(filename, size, path):
    """Print the final received file summary."""
    print(f"  {CYAN}▼{RESET}  {WHITE}Decrypted Payload (Binary File){RESET}")
    print(_top())
    print(_row(f"    {GRAY}Filename:{RESET} {WHITE}{filename}{RESET}"))
    print(_row(f"    {GRAY}Size:    {RESET} {WHITE}{size} bytes{RESET}"))
    print(_row(f"    {GRAY}Saved To:{RESET} {GREEN}{path}{RESET}"))
    print(_bot())
    print()
    sys.stdout.flush()

def printConnectionClosed():
    """Print the connection-closed footer."""
    print(f"  {GRAY}◌{RESET}  Connection closed  {GRAY}·  Waiting for next client...{RESET}")
    print(_sep())
    print()
    sys.stdout.flush()

def printError(message):
    """Print a formatted error."""
    print(f"  {RED}✗  {message}{RESET}")
    sys.stdout.flush()
