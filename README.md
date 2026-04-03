# One-Time Pad Stream Cipher

A secure stream cipher implementation based on One-Time Pad (OTP) methodology. The application provides a desktop GUI for encrypting and decrypting messages using cryptographically secure techniques including Diffie-Hellman key exchange, AES-256-GCM seed encryption, HMAC-SHA256 authentication, and RSA-PSS digital signatures for MITM prevention.

## Project Overview

This project implements a complete secure communication pipeline where:
1. Two processes (sender and receiver) establish a shared secret using Diffie-Hellman key exchange
2. RSA-PSS signatures prevent man-in-the-middle attacks during key exchange
3. The seed for the pseudo-random keystream is encrypted with AES-256-GCM and authenticated with HMAC-SHA256
4. The message is encrypted using XOR with the LCG-generated keystream (OTP methodology)
5. Results are displayed in a brutalist terminal-style desktop GUI

## Technology Stack

| Layer | Technology |
|-------|------------|
| Language | Python 3.10+ |
| GUI Framework | PyWebView |
| Cryptographic Library | cryptography (PyCA) |
| Testing | pytest |
| Key Exchange | Diffie-Hellman (RFC 3526 Group 14, 2048-bit) |
| Digital Signatures | RSA-PSS (4096-bit, SHA-256) |
| Key Derivation | HKDF-SHA256 (RFC 5869) |
| Symmetric Encryption | AES-256-GCM |
| Message Authentication | HMAC-SHA256 |
| PRNG | Linear Congruential Generator (64-bit Knuth params) |

## Architecture Overview

### System Design (UML Diagram)
![UML Diagram](./docs/system%20design%20UML.svg)

## Cryptographic Specifications

### Linear Congruential Generator (LCG)
- **Modulus (m)**: 2^64 (18446744073709551616)
- **Multiplier (a)**: 6364136223846793005
- **Increment (c)**: 1442695040888963407
- **Output**: High-order bits (not low-order) for better entropy
- **State**: 64-bit unsigned integer

### Diffie-Hellman Key Exchange
- **Group**: RFC 3526 Group 14 (2048-bit)
- **Prime (p)**: 25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357
- **Generator (g)**: 2
- **Key Derivation**: HKDF-SHA256

### RSA-PSS Digital Signatures
- **Key Size**: 4096-bit
- **Hash Function**: SHA-256
- **Salt Length**: Maximum (PSS.MAX_LENGTH)
- **Purpose**: Authenticate DH public keys to prevent MITM attacks

### AES-256-GCM
- **Key Length**: 256 bits
- **Mode**: Galois/Counter Mode (AEAD)
- **Nonce**: 12 bytes (96 bits)
- **Purpose**: Encrypt the LCG seed

### HMAC-SHA256
- **Key**: Derived from DH shared secret
- **Purpose**: Authenticate encrypted seed data

## Installation

```bash
pip install -r requirements.txt
```

## Running the Application

```bash
py main.py
```

This opens a desktop window with the brutalist terminal UI. Enter a plaintext message and click "Transmit" to see:
- The plaintext split into chunks
- Each chunk's ciphertext representation
- The decrypted result

## Running Tests

```bash
py -m pytest tests/test_cipher.py -v
```

All 22 tests cover:
- LCG determinism and byte range
- High-order bit extraction quality
- Stream cipher round-trip encryption/decryption
- Diffie-Hellman key symmetry
- AES-256-GCM seed encryption
- HMAC-SHA256 authentication
- RSA-PSS signature verification
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

- Keys are generated in-memory per session (no persistent storage)
- Private keys are never logged or written to disk
- Log output does not contain plaintext, seeds, or derived keys
- RSA-PSS signatures prevent man-in-the-middle attacks during key exchange
- HMAC provides integrity verification for the encrypted seed
- AES-GCM provides both confidentiality and authenticity

## Configuration

Edit `config/default_config.json` to adjust:
- LCG parameters (modulus, multiplier, increment)
- DH parameters (prime, generator)
- Cryptographic parameters (AES key length, HMAC algorithm, chunk size)

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
