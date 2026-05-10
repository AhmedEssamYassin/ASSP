# Project Workflow & Algorithm Documentation: OTP Stream Cipher

---

## Before We Start: What Are We Actually Building?

Imagine Alice wants to send the word `"Hello"` to Bob over the internet. Simple enough, right? The problem is that the internet is not a private telephone line between two people. It is more like shouting across a crowded room. Every router, ISP, and potentially every curious actor between Alice and Bob can see the raw bytes flying through the wire.

So the goal is clear: Alice needs to scramble `"Hello"` into unreadable noise before sending it, and Bob needs a way to unscramble it back on the other side. What's *not* clear is how to make that happen securely when literally anyone can watch the conversation. That problem turns out to be surprisingly deep, and solving it requires layering several algorithms on top of each other, each one patching a specific hole the previous one leaves open.

This document is split into two halves. **Part 1** works *backwards* from the goal — it starts with what we want and walks backwards through every obstacle that makes it hard, introducing each algorithm as a direct answer to the specific problem it solves. This way, no algorithm appears out of nowhere. **Part 2** then replays the whole thing *forward* in time, tracing the exact journey of the word `"Hello"` from Alice's keyboard to Bob's screen, step by step.

---

## Security Layer Reference Map

Before diving into the details, here is a single reference you can return to at any point. Every algorithm in this system operates at a specific phase, protects a specific piece of data, and provides a specific guarantee. Nothing overlaps, and nothing is redundant.

```
PHASE                │ ALGORITHM          │ PROTECTS                  │ GUARANTEE
─────────────────────┼────────────────────┼───────────────────────────┼──────────────────────────
Pre-session (once)   │ Ed25519 Key Gen    │ Identity                  │ Permanent identity anchor
─────────────────────┼────────────────────┼───────────────────────────┼──────────────────────────
Handshake (once)     │ X25519 (ECDH)      │ The shared secret         │ Key agreement without
                     │                   │                           │ transmitting the secret
                     ├────────────────────┼───────────────────────────┼──────────────────────────
                     │ Ed25519 Signatures │ The X25519 public values  │ Identity verification —
                     │                   │                           │ proves who sent them
                     ├────────────────────┼───────────────────────────┼──────────────────────────
                     │ HKDF               │ The raw shared secret     │ Converts it into a
                     │                   │                           │ proper 32-byte AES key
─────────────────────┼────────────────────┼───────────────────────────┼──────────────────────────
Seed exchange (once) │ AES-256-GCM        │ The Seed value itself     │ Confidentiality & Integrity
                     │                   │                           │ — encrypts and authenticates
─────────────────────┼────────────────────┼───────────────────────────┼──────────────────────────
Streaming (repeated) │ AES-256-CTR        │ Keystream synchronisation │ Both sides produce the
                     │ (CSPRNG)          │                           │ same bytes independently
                     ├────────────────────┼───────────────────────────┼──────────────────────────
                     │ XOR                │ Each message byte         │ Encrypts and decrypts
                     │                   │                           │ using the keystream
```

---

## Part 1: The Problem-Solving Architecture

### 1. The Ultimate Target: Fast, Secure Data Streaming

**The Goal:** Scramble and transmit `"Hello"` (or any stream of data) over the internet so that only the intended recipient can read it, and do it fast enough that it doesn't bottleneck the system.

**The Solution — XOR Cipher:**

The scrambling operation at the heart of this system is the humble XOR gate (`^`), and it turns out to be almost perfect for streaming data.

XOR is perfectly reversible. Apply a random byte to scramble a plaintext byte, and you get ciphertext. Apply the exact same random byte to that ciphertext, and you recover the original. The same operation encrypts and decrypts. 

XOR is secure *if and only if* the random bytes are entirely unpredictable. If the random byte is truly random and unknown to the eavesdropper, the ciphertext is statistically indistinguishable from random noise. 

The catch, however, is the phrase "truly random." That's where the next problem begins.

---

### 2. Obstacle: Predictability — Where Do the Random Bytes Come From?

**The Problem:**

If Bob needs to decrypt Alice's message, he must produce the exact same sequence of random bytes that Alice used to encrypt it. True randomness, by definition, has no pattern to synchronise. You also cannot send the random bytes over the network, because they effectively *are* the key.

**The Solution — AES-CTR as a CSPRNG:**

Instead of true randomness, we use a **Cryptographically Secure Pseudorandom Number Generator (CSPRNG)**. Both sides use the AES block cipher in Counter (CTR) mode.

**How Synchronization Works:**
To produce identical keystreams, Alice and Bob do not need to send the entire infinite stream of random bytes to each other. They only need to share a single starting point. 
1. Alice uses her operating system's true random number generator (`os.urandom(32)`) to create a perfectly random 256-bit (32-byte) **Seed**. 
2. She securely transmits this Seed to Bob (we'll explain how in the next section).
3. Once Bob receives the Seed, both Alice and Bob load it into their local AES-CTR engines as the internal AES encryption key.
4. They both set their AES Counter to zero and begin encrypting a sequence of null bytes. 

Because AES is a deterministic algorithm, giving it the exact same 32-byte key (the Seed) and the exact same input (null bytes) guarantees that both Alice and Bob's machines will produce the exact same sequence of pseudo-random bytes in perfect lockstep, forever.

Unlike basic mathematical formulas like an LCG (Linear Congruential Generator) used in older systems, AES-CTR is cryptographically secure. It is a one-way mathematical trapdoor. It is impossible to predict the next byte or reconstruct the internal state even if an attacker manages to observe millions of bytes of the keystream. 

So instead of synchronising an infinite stream of random bytes, Alice and Bob only need to synchronise a single 32-byte Seed.

---

### 3. Obstacle: Syncing the Seed Securely

**The Problem:**

Alice has generated a 32-byte random Seed. Bob needs that exact Seed to synchronise his CSPRNG. If Alice sends it over the network in plaintext, an eavesdropper intercepts it, spins up their own AES-CTR generator, and decrypts the entire conversation.

**The Solution — AES-256-GCM:**

We need to encrypt the Seed before transmission. To do this, Alice uses the Advanced Encryption Standard (AES) in GCM (Galois/Counter Mode).

The Advanced Encryption Standard (AES) in GCM (Galois/Counter Mode) is the industry-standard symmetric cipher. It takes a plaintext input and a 32-byte key, and produces ciphertext that is computationally infeasible to break without that key. AES-256 specifically uses a 256-bit (32-byte) key, which gives 2²⁵⁶ possible keys — a number so astronomically large that brute-forcing it is beyond any realistic computation.

AES-GCM is an **Authenticated Encryption with Associated Data (AEAD)** cipher. This means it solves two problems simultaneously:
1. **Confidentiality**: It encrypts the Seed so an eavesdropper sees only noise.
2. **Integrity**: GCM inherently computes a 16-byte authentication tag (using polynomial arithmetic over a Galois field) over the ciphertext. 

If a malicious actor (a Man-in-the-Middle) attempts to flip a single bit of the encrypted Seed in transit, Bob's AES-GCM decryption will mathematically fail and raise an `InvalidTag` exception. Bob immediately knows the data was tampered with and discards it. **No secondary HMAC wrapper is needed** because GCM provides structural integrity guarantees natively.

So Alice encrypts the Seed with AES-GCM and sends it. But wait — AES requires a key. Where does the 32-byte key for *this* AES-GCM encryption come from?

---

### 4. Obstacle: The Chicken-and-Egg Key Problem

**The Problem:**

To transmit the Seed securely, Alice needs an AES key. But she can't transmit the AES key securely without already having a secure channel.

**The Solution — X25519 (Elliptic Curve Diffie-Hellman):**

To establish a shared secret without transmitting it, Alice and Bob use **X25519**, a fast and highly secure implementation of Elliptic Curve Diffie-Hellman (ECDH) operating on **Curve25519**.

**How the Trapdoor Works:**
Standard DH relies on modular exponentiation. Elliptic Curve Cryptography (ECC) relies on the geometry of curves defined by `y² = x³ + ax + b`. On this curve, you can define "addition" of two points. If you add a point `G` to itself `k` times, you get a new point `P`. This is called scalar multiplication: `P = k * G`.

The trapdoor (the one-way mathematical function) here is the **Elliptic Curve Discrete Logarithm Problem (ECDLP)**:
- **Easy**: Given a point `G` and a massive integer `k`, it is extremely fast to compute `P = k * G`.
- **Hard (The Trapdoor)**: Given `G` and the resulting point `P`, it is computationally infeasible to work backwards to find `k`. There is no known algorithm (short of a sufficiently large quantum computer) that can reverse this operation efficiently.

**The Exchange:**
1. Alice picks a random private key `a` (her scalar) and computes her public key `A = a * G`.
2. Bob picks a random private key `b` and computes his public key `B = b * G`.
3. They exchange `A` and `B` publicly.
4. Alice computes: `SharedSecret = a * B`
5. Bob computes: `SharedSecret = b * A`

Because of the associative property of scalar multiplication, `a * (b * G)` is identical to `b * (a * G)`. Both Alice and Bob end up at the exact same point on the elliptic curve. An eavesdropper who sees `A` and `B` cannot find `a` or `b` (due to the ECDLP trapdoor) and therefore cannot compute the shared point.

A 256-bit X25519 key provides security equivalent to roughly a 3072-bit RSA key, but operates orders of magnitude faster and requires only 32 bytes of public key data instead of hundreds.

Finally, the raw X-coordinate of this shared point is passed through **HKDF (Hash-based Key Derivation Function)** to stretch and uniformly distribute it into a perfect 32-byte AES key.

---

### 5. Obstacle: The Man-in-the-Middle (MITM) Attack

**The Problem:**

X25519 completely defeats a *passive* eavesdropper. But an *active* attacker (Mallory) can intercept Alice's public key `A` and send Bob her own key `M`, then intercept Bob's key `B` and send Alice `M`. 

Mallory then computes two separate shared secrets — one with Alice and one with Bob. Alice and Bob think they are talking to each other, but Mallory is sitting in the middle, decrypting and re-encrypting every message. 

**The Solution — Ed25519 Digital Signatures:**

To prevent this, we must prove *identity*. Alice and Bob must prove that the X25519 keys they are exchanging actually belong to them.

Long before the chat begins, Alice and Bob generate permanent identity keys using **Ed25519**, an Elliptic Curve Digital Signature Algorithm (EdDSA) operating on the Edwards25519 curve. They exchange their public keys out-of-band (e.g., in person or via a trusted registry).

**How the Ed25519 Trapdoor Works:**
Like X25519, Ed25519 relies on the ECDLP trapdoor, but it uses it for proving knowledge rather than exchanging secrets.
When Alice wants to sign her X25519 public key `A`, she uses her Ed25519 Private Key to generate a mathematical proof. The math guarantees that:
1. The signature could only have been created by someone who holds the Private Key.
2. The signature is mathematically bound specifically to the message `A`. 

If Mallory tries to substitute `A` with `M`, she must also generate a new signature for `M`. But she doesn't have Alice's Private Key. Because the ECDLP trapdoor prevents her from deriving the Private Key from the Public Key, she cannot forge the signature. 

When Bob receives `A` and the signature, he verifies it against Alice's pre-loaded Ed25519 Public Key. If it matches, he knows with mathematical certainty that `A` was generated by Alice and was not modified in transit.

---

### 6. Obstacle: Malicious Payload Tampering

**The Problem:**

If an attacker intercepts the encrypted stream, they cannot decrypt it without the key. However, if we simply used an unauthenticated cipher, the attacker could blindly flip bits in the ciphertext as it travels over the wire. Because the XOR cipher is malleable, flipping a bit in the ciphertext causes the exact corresponding bit in the decrypted plaintext to flip when Bob receives it. The attacker can corrupt or alter the message in predictable ways without ever knowing what the message says.

**The Old Solution — HMAC (Hash-based Message Authentication Code):**

In older cryptographic designs, developers used **HMAC** to solve this. HMAC acts like a tamper-evident cryptographic seal. You encrypt the data, then compute a cryptographic hash over the ciphertext using a shared secret. You send both the ciphertext and the HMAC tag. When Bob receives the package, he computes his own HMAC over the ciphertext. If it matches the tag he received, he knows the data wasn't tampered with. While HMAC is highly secure, manually applying an HMAC on top of an encryption cipher (Encrypt-then-MAC architecture) is notoriously prone to dangerous implementation flaws.

**Our Modern Solution — AES-256-GCM (AEAD):**

Instead of manually bolting an HMAC onto our cipher, we use **AES in GCM mode** to securely transmit our 32-byte keystream Seed. AES-GCM is an **Authenticated Encryption with Associated Data (AEAD)** cipher. It simultaneously encrypts the Seed *and* mathematically computes a 16-byte authentication tag over it natively. 

If a malicious actor (a Man-in-the-Middle) attempts to flip a single bit of the encrypted Seed in transit, GCM's internal polynomial arithmetic instantly detects it and raises an `InvalidTag` exception. Bob immediately knows the data was tampered with and discards it. **No secondary HMAC wrapper is needed** because AES-GCM achieves perfect integrity verification natively.

---

## Part 2: The End-to-End Execution Flow

Here is the exact chronological walkthrough of encrypting `"Hello"`.

### Phase 1: Key Exchange & Authentication (X25519 + Ed25519)

1. **Identity**: Alice and Bob have already exchanged their permanent 32-byte Ed25519 Public Keys.
2. **Keypair Generation**: Alice generates a fresh X25519 private key and derives her 32-byte public key `A`.
3. **Signing**: Alice uses her Ed25519 private key to digitally sign `A`. She sends `(A, Alice_Signature)`.
4. **Verification**: Bob receives the payload. He uses Alice's known Ed25519 Public Key to verify the signature over `A`. It passes.
5. **Response**: Bob generates his own X25519 public key `B`, signs it with his Ed25519 private key, and sends `(B, Bob_Signature)`.
6. **Verification**: Alice verifies Bob's signature.

### Phase 2: Shared Key Derivation

Alice and Bob perform the ECDH scalar multiplication:
- Alice multiplies Bob's public key `B` by her private key `a`.
- Bob multiplies Alice's public key `A` by his private key `b`.

They both arrive at the exact same 32-byte shared secret. They pass this secret through HKDF-SHA256 to derive the symmetric `sharedKey`.

### Phase 3: Seed Encapsulation (AES-256-GCM)

1. **Seed Generation**: Alice generates a fresh, highly secure 32-byte random `Seed` via `os.urandom(32)`. This will be the CSPRNG keystream key.
2. **Encryption**: Alice encrypts the `Seed` using AES-256-GCM, keyed with the `sharedKey` from Phase 2. GCM requires a 12-byte random nonce.
3. **Transmission**: Alice sends the `Nonce` and the `Ciphertext` (which inherently includes the 16-byte GCM authentication tag) to Bob.
4. **Decryption & Integrity**: Bob receives the payload and decrypts it with AES-256-GCM. GCM validates the tag internally. If the packet was altered by a MITM, GCM rejects it. Bob recovers the 32-byte `Seed`.

### Phase 4: Keystream Generation (AES-CTR)

Alice and Bob both instantiate their CSPRNG (AES-CTR) using the 32-byte `Seed` as the encryption key. Because they have the same key, their AES engines will produce the identical sequence of pseudo-random bytes when encrypting a stream of null bytes.

### Phase 5: Stream Payload Transmission (XOR)

The ASCII encoding of `"Hello"` is `[72, 101, 108, 108, 111]`.

**Encrypting 'H' (72):**
1. Alice's CSPRNG produces its first byte: e.g., `104`.
2. She XORs them: `72 ^ 104 = 32`.
3. She transmits `32`. To anyone watching, this is meaningless noise.

**Decrypting 'H' on Bob's side:**
1. Bob's CSPRNG produces its first byte. Since it has the same Seed, it yields exactly `104`.
2. He XORs the ciphertext: `32 ^ 104 = 72`.
3. He recovers `'H'`.

This repeats for every byte. The CSPRNG state advances identically on both machines, keeping them in perfect lockstep.

### Phase 6: Real-Time UI Synchronization

Alice and Bob run in isolated Python subprocesses. To display the real-time encryption and decryption in the brutalist terminal UI, the main application uses `multiprocessing.Queue`. 

As Alice encrypts a byte, she pushes a copy of the ciphertext to her queue. As Bob decrypts a byte, he pushes the plaintext to his queue. The PyWebView frontend polls these queues and updates the screen. The UI is a faithful, real-time mirror of the underlying cryptography — every byte shown on screen actually traveled through the entire X25519/AES-GCM/XOR pipeline.
