# CSPRNG Stream Cipher

A secure stream cipher implementation based on AES-CTR acting as a Cryptographically Secure Pseudorandom Number Generator (CSPRNG). The application provides a desktop GUI for encrypting and decrypting messages using cryptographically secure techniques including X25519 Elliptic Curve Diffie-Hellman key exchange, AES-256-GCM seed encapsulation, and Ed25519 digital signatures for MITM prevention.

## Project Overview

This project implements a complete secure communication pipeline where:
1. Two processes (sender and receiver) establish a shared secret using X25519 (Curve25519) key exchange.
2. Ed25519 signatures prevent man-in-the-middle attacks during the key exchange.
3. A 256-bit random seed for the keystream is encrypted and authenticated over the wire with AES-256-GCM.
4. The message is encrypted using XOR with an AES-CTR generated keystream.
5. Results are displayed in a brutalist terminal-style desktop GUI.

## Technology Stack

| Layer | Technology |
|-------|------------|
| Language | Python 3.10+ |
| GUI Framework | PyWebView |
| Cryptographic Library | cryptography (PyCA) |
| Testing | pytest |
| Key Exchange | X25519 (Curve25519 ECDH) |
| Digital Signatures | Ed25519 (EdDSA) |
| Key Derivation | HKDF-SHA256 (RFC 5869) |
| Keystream Generator | AES-256-CTR (CSPRNG) |
| Seed Encapsulation | AES-256-GCM (Authenticated Encryption) |

## Architecture Overview

### System Design (UML Diagram)
![UML Diagram](./docs/system%20design%20UML.svg)

## Cryptographic Specifications

### Keystream Generator (AES-256-CTR)
- **Algorithm**: AES in Counter (CTR) mode
- **Seed/Key**: 256-bit ephemeral key generated via `os.urandom(32)`
- **Nonce**: 16-byte zeroed nonce (safe because the 256-bit key is strictly ephemeral and never reused across sessions)
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

## Installation

```bash
pip install -r requirements.txt
```

## Running the Application

```bash
py -3.13 main.py
```

This opens a desktop window with the brutalist terminal UI. Enter a plaintext message and click "Transmit" to see:
- The plaintext split into chunks
- Each chunk's ciphertext representation
- The decrypted result

## Running Tests

```bash
py -3.13 -m pytest tests/test_cipher.py -v
```

All 16 tests cover:
- CSPRNG determinism and valid byte range
- Stream cipher round-trip encryption/decryption handling Unicode properly
- X25519 key symmetry and generation
- AES-256-GCM seed encryption and authentication
- Ed25519 signature verification and MITM rejection
- End-to-end communication pipeline

## API Usage

```python
from src.communication.pipeline import runCommunication

result = runCommunication("Your message here")
# Returns: {
#     "cipherChunks": [...],
#     "decryptedText": "Your message here",
#     "success": True
# }
```

## Security Notes

- Keys are generated in-memory per session (no persistent storage).
- Private keys and plaintexts are never logged.
- The stream cipher is backed by AES-CTR, completely immune to the structural prediction vulnerabilities found in naive generators like LCG.
- Ed25519 signatures prevent man-in-the-middle attacks during key exchange.
- AES-GCM guarantees the integrity of the seed without needing a redundant HMAC wrapper.

## Configuration

Edit `config/default_config.json` to adjust:
- Cryptographic parameters (AES key length, chunk size)

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
