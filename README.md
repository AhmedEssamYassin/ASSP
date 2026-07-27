# ASSP - Authenticated Secure Stream Protocol

**Authenticated Secure Stream Protocol** — *An end-to-end encrypted communication system using X25519 key exchange, AES-256-GCM seed encapsulation, and AES-CTR keystream generation with Ed25519 MITM prevention.*

A secure stream cipher implementation based on AES-CTR acting as a Cryptographically Secure Pseudorandom Number Generator (CSPRNG). The application provides a desktop GUI for encrypting and decrypting messages using cryptographically secure techniques including X25519 Elliptic Curve Diffie-Hellman key exchange, AES-256-GCM seed encapsulation, and Ed25519 digital signatures for MITM prevention.

## Project Overview

This project implements a complete secure communication pipeline where:
1. Two processes (sender and receiver) establish a shared secret using X25519 (Curve25519) key exchange.
2. Ed25519 signatures prevent man-in-the-middle attacks during the key exchange.
3. A 256-bit random seed for the keystream is encrypted and authenticated over the wire with AES-256-GCM.
4. The message is encrypted using XOR with an AES-CTR generated keystream.
5. The decrypted result is displayed in a PyWebView desktop GUI; the server renders a live **Textual TUI** (or a plain ANSI terminal readout with `--no-tui`).

## Technology Stack

| Layer                 | Technology                             |
| --------------------- | -------------------------------------- |
| Language              | Python 3.10+                           |
| GUI Framework         | PyWebView                              |
| Cryptographic Library | cryptography (PyCA)                    |
| Testing               | pytest                                 |
| Key Exchange          | X25519 (Curve25519 ECDH)               |
| Digital Signatures    | Ed25519 (EdDSA)                        |
| Key Derivation        | HKDF-SHA256 (RFC 5869)                 |
| Keystream Generator   | AES-256-CTR (CSPRNG)                   |
| Seed Encapsulation    | AES-256-GCM (Authenticated Encryption) |

## Architecture Overview

### System Design (UML Diagram)
![UML Diagram](./docs/system%20design%20UML.svg)

## Cryptographic Specifications

### Keystream Generator (AES-256-CTR)
- **Algorithm**: AES in Counter (CTR) mode
- **Seed/Key**: 256-bit ephemeral key generated via `os.urandom(32)`
- **Nonce**: 16-byte randomly generated nonce (via `os.urandom(16)`). Even though the seed is strictly ephemeral and unique per session, generating a random nonce is standard cryptographic "Defense in Depth" to definitively prevent the catastrophic "Two-Time Pad" vulnerability if a key is ever reused.
- **Operation**: Used as a CSPRNG to generate raw pseudo-random bytes for the XOR stream cipher.

### X25519 Key Exchange (ECDH)
- **Curve**: Curve25519
- **Key Size**: 256-bit (Equivalent to ~3072-bit RSA)
- **Operation**: Elliptic Curve Diffie-Hellman
- **Key Derivation**: HKDF-SHA256 expands the shared secret to a 32-byte uniform key.

### Ed25519 Digital Signatures
- **Curve**: Edwards25519
- **Key Size**: 256-bit
- **Purpose**: Authenticate X25519 public keys to prevent MITM attacks. Ed25519 is constant-time and immune to padding or timing attacks by design.

### AES-256-GCM
- **Key Length**: 256 bits (derived from X25519 shared secret via HKDF)
- **Mode**: Galois/Counter Mode (AEAD)
- **Nonce**: 12 bytes (96 bits), randomly generated per encryption.
- **Purpose**: Encrypt and authenticate the 256-bit keystream seed during transmission. GCM inherently provides integrity validation, discarding tampered ciphertext without needing a secondary HMAC.

### Short Authentication String (SAS)
- **Algorithm**: HKDF-SHA256 expanding the X25519 shared secret
- **Info String**: `b"assp-cipher-sas-v1"`
- **Operation**: Derives a cryptographic hash from the shared secret, using 4 bytes to map to a 256-word English dictionary. The resulting 4-word phrase is displayed to both users for out-of-band manual verification to definitively thwart Man-in-the-Middle (MITM) attacks if the Ed25519 trust-on-first-use (TOFU) keys are unverified.

## Installation

```bash
pip install -r requirements.txt
```

## Security: Key Exchange & Verification

To solve the "First-Use" problem without relying on a centralized Certificate Authority (CA) or physically exchanging keys on a USB drive, this application uses a **Trust-On-First-Use (TOFU)** model augmented by a **Short Authentication String (SAS)**.

1. **Ephemeral Keys:** Every time you connect, new Ed25519 identity keys and X25519 session keys are generated in-memory. No keys are saved to disk.
2. **SAS Generation:** Both the sender and receiver independently derive a 4-word Short Authentication String using HKDF-SHA256 on the shared secret.
3. **Out-of-Band Verification:** On the first connection to a new peer, the application will pause and display the SAS words. You must verbally confirm these words with your recipient over a separate, authenticated channel (like a phone call).
4. **Caching:** Once verified, the server's identity fingerprint is temporarily cached in-memory for the duration of the session. If you reconnect, the SAS step is automatically bypassed. The cache is cleared when the application closes.

## Running the Application

The application has two components that must run simultaneously: the **server** (receiver) and the **GUI client** (sender).

**Step 1 — Start the server** in one terminal:
```bash
# Default: Textual TUI (recommended)
python src/communication/server.py

# Plain ANSI terminal output (no TUI dependency)
python src/communication/server.py --no-tui

# Optional flags
python src/communication/server.py --host 0.0.0.0 --port 5000
```

**Step 2 — Launch the GUI** in a second terminal:
```bash
python main.py
```

Enter a plaintext message in the GUI, set the server address (`127.0.0.1:5000` by default), and click **Encrypt & Transmit**.
On the first connection to a new server, the UI will prompt you with a **Short Authentication String (SAS)**. You must verbally verify these words with the recipient over a separate channel (e.g. phone call) to guarantee no Man-in-the-Middle is present.

The GUI displays the plaintext split into chunks alongside their ciphertext hex. The server TUI renders a live log of the full handshake trace and the decrypted plaintext.

## Running Tests

```bash
python -m pytest tests/test_cipher.py -v
```

The test suite covers:
- CSPRNG determinism and valid byte range
- Stream cipher round-trip encryption/decryption handling Unicode properly
- X25519 key symmetry and generation
- AES-256-GCM seed encryption and authentication
- Ed25519 signature verification and SAS MITM rejection
- End-to-end communication pipeline

## API Usage

```python
from src.communication.client import runClient
from src.crypto.config import loadConfig

config = loadConfig()
result = runClient(b"Your message here", {"type": "text"}, config, host="127.0.0.1", port=5000)
# Returns: {
#     "cipherChunks": [...],   # list of hex strings, one per chunk
#     "success": True
# }
# Note: requires a running server (python src/communication/server.py)
```

## Security Notes

- **All session keys are ephemeral.** X25519 keypairs, AES-GCM seeds, and Ed25519 identity keypairs are all generated fresh in-memory on each run — nothing is written to or read from disk during normal operation.
- Private keys and plaintexts are never logged.
- The stream cipher is backed by AES-CTR, completely immune to the structural prediction vulnerabilities found in naive generators like LCG.
- Ed25519 signatures combined with Short Authentication Strings (SAS) prevent man-in-the-middle attacks during key exchange without needing a centralized Certificate Authority (CA) or physically exchanging keys on a USB drive.
- AES-GCM guarantees the integrity of the seed without needing a redundant HMAC wrapper.

## Configuration

Edit `config/default_config.json` to adjust:
- `crypto.maxChunkSize` — number of bytes per encrypted chunk (default: 10)
- `network.timeoutSeconds` — TCP socket timeout in seconds (default: 30)
- `security.skipSasVerification` — set to `true` to bypass SAS prompts (useful for automated testing)

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
