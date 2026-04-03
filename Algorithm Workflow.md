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
Pre-session (once)   │ RSA Key Generation │ Identity                  │ Permanent identity anchor
─────────────────────┼────────────────────┼───────────────────────────┼──────────────────────────
Handshake (once)     │ Diffie-Hellman     │ The shared secret         │ Key agreement without
                     │                   │                           │ transmitting the secret
                     ├────────────────────┼───────────────────────────┼──────────────────────────
                     │ RSA Signatures     │ The DH public values      │ Identity verification —
                     │                   │ (A and B)                 │ proves who sent A and B
                     ├────────────────────┼───────────────────────────┼──────────────────────────
                     │ HKDF               │ The raw shared secret     │ Converts it into a
                     │                   │                           │ proper 32-byte AES key
─────────────────────┼────────────────────┼───────────────────────────┼──────────────────────────
Seed exchange (once) │ AES-256-GCM        │ The Seed value itself     │ Confidentiality —
                     │                   │                           │ hides the Seed's value
                     ├────────────────────┼───────────────────────────┼──────────────────────────
                     │ HMAC-SHA256        │ The encrypted Seed vault  │ Integrity — detects if
                     │                   │ (the AES blob as a whole) │ the vault was tampered
─────────────────────┼────────────────────┼───────────────────────────┼──────────────────────────
Streaming (repeated) │ LCG                │ Keystream synchronisation │ Both sides produce the
                     │                   │                           │ same bytes independently
                     ├────────────────────┼───────────────────────────┼──────────────────────────
                     │ XOR                │ Each message byte         │ Encrypts and decrypts
                     │                   │                           │ using the keystream
```

A few things this table makes immediately clear:

**RSA Signatures and HMAC are in completely different phases.** RSA operates during the handshake, before any shared secret exists. HMAC operates during the Seed exchange, after the shared secret has been established. They cannot swap places — HMAC requires a shared key that doesn't exist yet during the handshake, and RSA would be needlessly expensive and architecturally wrong during the Seed exchange.

**AES and HMAC protect the same vault but answer different questions.** AES answers "can anyone read the Seed?" — it hides the value. HMAC answers "can anyone silently corrupt the vault?" — it detects tampering. Encryption alone does not guarantee integrity, which is why both are needed on the same payload.

**The XOR ciphertext has no explicit integrity protection.** This is a deliberate design tradeoff. If a bit is flipped in the XOR stream, only that one byte decrypts incorrectly — the damage is localised and bounded. The LCGs on both sides are completely unaffected. Contrast this with the Seed: if the Seed is corrupted, the entire session is destroyed. The HMAC protection is proportional to the severity of what tampering would cause.

---

## Part 1: The Problem-Solving Architecture

### 1. The Ultimate Target: Fast, Secure Data Streaming

**The Goal:** Scramble and transmit `"Hello"` (or any stream of data) over the internet so that only the intended recipient can read it, and do it fast enough that it doesn't bottleneck the system.

**The Solution — XOR Cipher:**

The scrambling operation at the heart of this system is the humble XOR gate (`^`), and it turns out to be almost perfect for streaming data.

XOR, or *Exclusive-OR*, is a bitwise operation that takes two bits and outputs `1` if they differ, and `0` if they match. When you apply that logic byte-by-byte to two sequences of data, you get a mathematically elegant result:

```
Plaintext  ^ RandomByte = Ciphertext
Ciphertext ^ RandomByte = Plaintext
```

In other words, XOR is perfectly reversible. Apply a random byte to scramble a plaintext byte, and you get ciphertext. Apply the exact same random byte to that ciphertext, and you recover the original. The same operation encrypts and decrypts. There is no separate algorithm for each direction.

More importantly, XOR executes natively at the hardware level. Modern CPUs perform XOR operations in a single clock cycle. There is no complex multiplication, no modular arithmetic, no table lookups. When you need to encrypt a stream of data in real time — think a live video feed, a voice call, or a continuous message stream — XOR is the clear choice because everything more sophisticated is simply too slow.

The mathematical reason XOR is *secure* (when used correctly) is equally clean. If the random byte is truly random and unknown to the eavesdropper, the ciphertext is statistically indistinguishable from random noise. An attacker looking at the encrypted byte `32` has no information at all about whether the original was `72` or `50` or anything else, because every possible plaintext would map to `32` for *some* random byte. This is called *perfect secrecy* — the same property that makes the theoretical One-Time Pad completely unbreakable.

The catch, however, is the phrase "truly random." That's where the next problem begins.

---

### 2. Obstacle: Predictability — Where Do the Random Bytes Come From?

**The Problem:**

XOR is secure only if the random bytes are entirely unpredictable. But here's the fundamental contradiction: if Bob needs to decrypt Alice's message, he must produce the exact same sequence of random bytes that Alice used to encrypt it. If Alice and Bob are in different locations generating bytes independently, they can't produce the same sequence — true randomness by definition has no pattern to synchronise.

You can't solve this by having Alice generate the bytes and send them to Bob in advance, either. Those random bytes effectively become the key, and sending the key over the network is the very problem you're trying to avoid.

**The Solution — Linear Congruential Generator (LCG):**

The trick is to use *pseudorandomness* instead of true randomness. A Linear Congruential Generator is a deterministic mathematical engine that produces a long sequence of numbers that *look* random but are entirely reproducible if you know the starting point.

The formula is a simple recurrence relation:

```
X(n+1) = (multiplier × X(n) + increment) mod modulus
```

Each value in the sequence is derived from the previous one using three fixed constants (`multiplier`, `increment`, `modulus`). The starting value, `X(0)`, is called the **Seed**. This is the critical insight: if Alice and Bob both run the same LCG formula with the same Seed, they will produce the exact same sequence of numbers, forever, in lockstep.

So instead of synchronising an infinite stream of random bytes, you only need to synchronise a single 64-bit integer — the Seed — and both sides can independently regenerate the entire keystream from that one number.

**A note on LCG quality:**

A naive LCG has a well-known flaw: the lower-order bits of the output (the ones representing small values) tend to cycle in short, predictable patterns. If you use the raw 64-bit output directly, the least significant bits are much weaker than the most significant bits.

The fix used here is to bit-shift the 64-bit state 56 positions to the right before yielding a byte. This discards the weak lower 56 bits entirely and keeps only the top 8 bits, which gives a value in the range 0–255 (a clean, strong byte) with far better statistical properties. The shift looks like this:

```
output_byte = (X >> 56) & 0xFF
```

The LCG state still advances using the full 64-bit math — you're just being selective about which bits you trust.

---

### 3. Obstacle: Syncing the Seed Securely

**The Problem:**

Alice has generated a random 64-bit Seed (let's say it's the integer `42`). Bob needs that exact Seed to synchronise his LCG. So Alice transmits it over the network.

An eavesdropper intercepts it. Now they have `42`. They spin up their own LCG with that Seed, and they can decrypt every single byte of the conversation. Game over.

The Seed must be transmitted, but it must be transmitted *secretly*. To send it secretly, you need to encrypt it. But to encrypt it, you need a key. And you're back to the same problem — how do you share a key securely?

This is the classic key-distribution problem, and for decades it was considered unsolvable. The immediate answer is to use a strong symmetric cipher to *lock* the Seed before transmitting it.

**The Solution — AES-256-GCM:**

The Advanced Encryption Standard (AES) in GCM (Galois/Counter Mode) is the industry-standard symmetric cipher. It takes a plaintext input and a 32-byte key, and produces ciphertext that is computationally infeasible to break without that key. AES-256 specifically uses a 256-bit (32-byte) key, which gives 2²⁵⁶ possible keys — a number so astronomically large that brute-forcing it is beyond any realistic computation.

Alice encrypts the Seed using a 32-byte AES key and sends the resulting ciphertext (the "vault") over the network. Even if the eavesdropper intercepts it, they see nothing but random-looking bytes. The Seed is safe — as long as the AES key itself is safe.

GCM mode specifically is chosen because it provides not just *confidentiality* (the data is hidden) but also *authenticity* (any tampering with the ciphertext is detectable). This distinction matters and will come up again later.

So now the question shifts: where does the 32-byte AES key come from, and how do Alice and Bob both end up with the same one without transmitting it?

---

### 4. Obstacle: The Chicken-and-Egg Key Problem

**The Problem:**

AES is a *symmetric* cipher. The same key locks and unlocks the vault. Alice needs to get that 32-byte AES key to Bob so he can decrypt the Seed, but if she sends the key over the network, the eavesdropper steals the key instead and uses it to open the vault themselves. You've solved nothing.

This is sometimes called the *bootstrap problem*: to establish secure communication, you need a shared secret, but sharing a secret requires secure communication. For a long time, the only solution was physical key distribution — you'd literally hand-deliver the key on a floppy disk. That doesn't scale.

**The Solution — Diffie-Hellman Key Exchange (DHKE) + HKDF:**

In 1976, Whitfield Diffie and Martin Hellman published a method that sounds impossible: two parties can independently compute the same secret number without ever transmitting it. An eavesdropper who sees every single message exchanged between them still cannot compute that number. It works through the mathematics of modular exponentiation.

Here's the simplified version. Alice and Bob agree up front on two public numbers: a large prime `p` and a generator `g`. These are not secret — they're embedded in the protocol and can be known by anyone.

- Alice picks a random private integer `a` and computes: `A = g^a mod p`
- Bob picks a random private integer `b` and computes: `B = g^b mod p`

They exchange `A` and `B` over the network in plain view of any eavesdropper. Now:

- Alice computes: `S = B^a mod p`
- Bob computes: `S = A^b mod p`

Both of these equal `g^(ab) mod p` because of the commutative property of exponents. Alice and Bob have arrived at the same Shared Secret `S` without ever transmitting it.

Why can't the eavesdropper compute `S`? They know `p`, `g`, `A`, and `B`. To recover `a` from `A = g^a mod p`, they'd need to solve the *Discrete Logarithm Problem* — essentially, figure out what exponent was used. For a carefully chosen large prime (the system uses a 2048-bit prime), this is computationally intractable. The best known algorithms would take longer than the age of the universe.

**Why HKDF?**

The raw Shared Secret `S = g^(ab) mod p` is a valid shared integer, but it's not a key yet. It has structural properties — it comes from a specific mathematical distribution — that make it unsuitable to feed directly into AES.

HKDF (Hash-based Key Derivation Function) takes this integer, mixes it with some context information, and passes it through a cryptographic hash function. The output is a uniformly random-looking 32-byte value — structurally perfect for use as an AES-256 key. This step is sometimes called "key stretching" or "key derivation," and skipping it would be a subtle but real security flaw.

---

### 5. Obstacle: The Man-in-the-Middle (MITM) Attack

**The Problem:**

Diffie-Hellman completely defeats a *passive* eavesdropper — someone who watches the wire but doesn't interfere. But there's a more dangerous kind of attacker: an *active* one who can not only read messages but intercept and modify them.

Here's how a Man-in-the-Middle attack breaks DHKE:

1. Alice sends her public value `A` over the network.
2. The attacker (let's call them Mallory) intercepts `A` before it reaches Bob, then sends Bob their own fake value `A'` instead, pretending to be Alice.
3. Bob sends his public value `B` back. Mallory intercepts it and sends Alice a fake `B'` instead.
4. Alice computes a Shared Secret with Mallory (thinking it's with Bob). Bob computes a different Shared Secret with Mallory (thinking it's with Alice).
5. Mallory sits in the middle, decrypting everything from Alice, reading it, re-encrypting it for Bob, and vice versa.

Neither Alice nor Bob detects anything unusual. The connection *works* — data flows back and forth — but Mallory sees every message in plaintext.

The root problem is that Alice has no way to verify that the `B` she received actually came from Bob and not from someone impersonating Bob.

**The Solution — RSA Digital Signatures:**

> **Before reading this section, a note on terminology:** Later in the document, you'll encounter something called HMAC, which also involves hashing and also produces an authentication tag. RSA signatures and HMAC are easy to conflate because both use hashing and both prove "this message is genuine." The distinction is fundamental and worth stating upfront:
>
> - **RSA Digital Signatures** use *asymmetric* keys — a Private Key to sign and a different Public Key to verify. Alice is the *only* person in the world who can produce the signature, but *anyone* who has her Public Key can verify it. This is what makes it useful for proving identity to someone you've never shared a secret with.
>
> - **HMAC** uses a *symmetric* shared key — the same key both produces and verifies the tag. It proves that a message came from someone who already knows the shared key, but it cannot tell you *which* of the two parties produced it.
>
> In this system, RSA signatures are used during the *handshake* — when Alice and Bob are strangers on the network trying to establish trust for the first time. HMAC is used *after* the handshake, once a Shared Key already exists between them. Each tool is solving a structurally different problem, which is why both exist.

Long before any chat begins, Alice and Bob each generate a permanent RSA key pair: a **Private Key** (which they never share with anyone) and a **Public Key** (which they distribute freely — everyone can have it). Bob pre-loads Alice's RSA Public Key, and Alice pre-loads Bob's. These are stored permanently on each machine — this is the one step in the entire protocol that requires a prior trusted exchange, done once, offline.

RSA has an asymmetric property that is the entire basis for digital signatures: data signed (encrypted) with the Private Key can only be verified (decrypted) with the corresponding Public Key. Since Alice's Private Key never leaves her machine, only she could have produced a signature that Alice's Public Key unlocks. That mathematical guarantee is what lets Bob trust that a message came from Alice specifically.

Here's how Alice signs her DH public value `A`:

1. **Hashing:** Alice feeds `A` through SHA-256, producing a fixed-length 32-byte "fingerprint." The fingerprint is deterministic (same input always gives the same output) and one-directional (you cannot reconstruct `A` from the fingerprint alone). Hashing first is important because RSA can only sign a fixed small input — it can't directly sign an arbitrary-length integer like `A`.

2. **Signing:** Alice encrypts that 32-byte fingerprint using her **RSA Private Key**. The output is her digital signature. The signature is mathematically bound to both the content (the fingerprint of `A`) and the key used (her Private Key). Change either one, and the signature breaks.

3. **Verification:** Bob receives `A` and Alice's signature. He uses Alice's **pre-loaded Public Key** to decrypt the signature, which yields the fingerprint Alice originally computed. He then independently computes SHA-256 of the `A` he just received and compares the two fingerprints side by side. If they match exactly, the signature is valid — the `A` he holds is the same `A` Alice originally signed, and it genuinely came from Alice.

**Why does this stop Mallory?**

Mallory intercepts `A` and wants to swap it for their own `A'`. To do that convincingly, they need to also provide a valid signature for `A'`. But producing a valid signature requires Alice's Private Key, which only Alice possesses. Mallory cannot compute it. RSA's security guarantees that generating a valid signature without the Private Key is computationally infeasible — it would require factoring a 4096-bit semiprime, which no known algorithm can do in any practical amount of time.

So Mallory faces an inescapable choice: forward Alice's original `A` unchanged (in which case Mallory loses the ability to intercept communications), or swap in `A'` without a valid signature (in which case Bob's verification fails and he immediately drops the connection).

The PSS (Probabilistic Signature Scheme) padding used in this system adds one more layer of robustness: each signing operation introduces randomness, so signing the same `A` twice produces two different-looking signatures. This prevents Mallory from learning anything useful by collecting multiple signatures for the same message over time.

---

### 6. Obstacle: Malicious Payload Tampering

**The Problem:**

RSA signatures have locked Mallory out of the key exchange completely. She can't impersonate Alice or Bob without their Private Keys. But she hasn't given up — she has one more move available that requires neither identity nor decryption: she can blindly *corrupt* data in transit.

Specifically, consider what happens to the AES-encrypted Seed vault while it travels over the wire. Mallory doesn't know the Seed, can't read the vault's contents, and can't produce a new one. But she *can* flip a handful of bits in the ciphertext — changing a `1` to a `0` in a byte here or there — without knowing what any of it means.

When Bob receives the corrupted vault and decrypts it, AES produces garbled output — not the integer `42`, but some meaningless garbage. Bob feeds that garbage into his LCG as the Seed. His LCG now starts from a completely different state than Alice's. Every keystream byte he generates from that point forward is wrong, and every plaintext byte he attempts to decrypt comes out as noise. The stream cipher is irreparably desynchronised for the entire conversation, and there is no way to recover without restarting the entire handshake.

This attack requires no cryptographic knowledge. Mallory is just vandalising bits.

**The Solution — HMAC-SHA256:**

> **Comparing this to RSA Signatures:** RSA signatures and HMAC both answer the question "was this message tampered with?" but they answer it using completely different tools and for completely different situations.
>
> RSA signatures work between strangers. Bob can verify Alice's signature because he has her Public Key — a key that was distributed publicly, not secretly. No prior shared secret is needed.
>
> HMAC works between parties who *already share a secret*. The same `sharedKey` — the one Alice and Bob derived from Diffie-Hellman and HKDF — is used to both produce and verify the HMAC tag. Anyone without the `sharedKey` cannot produce a valid HMAC, and cannot even verify one. It's a mutual seal between two parties who already trust each other.
>
> At this point in the protocol, Alice and Bob *do* share a secret (the `sharedKey`), so HMAC is the right tool. RSA signatures are not used here — they were the right tool earlier when no shared secret existed yet.

HMAC (Hash-based Message Authentication Code) takes two inputs: a message and a secret key. It runs them together through SHA-256 in a specific two-pass construction (designed to be resistant to length-extension attacks that would break a naive `hash(key || message)` approach). The output is a fixed 32-byte tag.

The critical property of HMAC is that the tag is only reproducible by someone who knows the secret key. Mallory, who does not know the `sharedKey`, cannot compute what the correct HMAC for any given payload should be. She cannot produce a valid tag for her corrupted vault, and she cannot modify the existing tag to match her modifications — the hash output would change entirely in an unpredictable way.

Here's how it's applied to the Seed vault:

Alice takes the entire payload — the nonce, the AES-GCM tag, and the encrypted Seed bytes — and computes HMAC-SHA256 over all of it using the `sharedKey`. She prepends the resulting 32-byte HMAC to the payload and transmits everything together.

Bob receives the structure. Before doing anything else — before even touching the AES decryption — he strips off the first 32 bytes as the received HMAC, then recomputes HMAC-SHA256 over the remainder using his identical `sharedKey`. He compares his computed tag against the received tag using a constant-time comparison function. (A regular equality check is avoided here because it returns early as soon as it finds a differing byte, which leaks timing information that a sophisticated attacker could exploit to gradually learn the correct tag one byte at a time. A constant-time comparison always takes the same amount of time regardless of where the first difference appears.)

If the tags match, Bob proceeds to decryption. If they don't match — even by a single bit — Bob immediately discards the entire payload and raises an error. He never feeds the corrupted data into AES. The desynchronised keystream scenario never happens.

---

## Part 2: The End-to-End Execution Flow

Now that you understand *why* each algorithm exists, here is a precise chronological walkthrough of encrypting the string `"Hello"` from Alice's machine to Bob's.

---

### Pre-Phase: Identity Pinning (RSA)

Before any chat session, both parties perform a one-time setup step: generating their permanent cryptographic identities.

Alice generates an RSA-4096 key pair — a Private Key and a Public Key. She keeps the Private Key completely secret, stored only on her machine. She distributes her Public Key to Bob through a trusted, out-of-band channel (think: exchanged in person, or retrieved from a verified server). Bob stores Alice's Public Key locally.

Bob does the same. Alice pre-loads Bob's RSA Public Key.

This "identity pinning" is the foundation that makes RSA signature verification possible during the handshake. If this step were skipped, neither party would have a trusted reference to verify signatures against, and the MITM defence would be meaningless.

---

### Phase 1: Key Exchange & Authentication (Diffie-Hellman + RSA Signatures)

Alice and Bob need to agree on a Shared Secret over the public network. They use a 2048-bit Diffie-Hellman exchange, where both parties already know and agree on the public parameters: a 2048-bit prime `p` and generator `g = 2`. These values are embedded in the protocol.

**Step 1 — Private exponents:**
Alice generates a random 2048-bit private integer `a`. Bob independently generates a random 2048-bit private integer `b`. Neither shares their private integer with anyone.

**Step 2 — Public values:**
Alice computes `A = g^a mod p`. Bob computes `B = g^b mod p`. These are the values they'll exchange.

**Step 3 — Alice signs and sends:**
Alice computes SHA-256 of the integer `A` to produce a 32-byte fingerprint. She then encrypts that fingerprint with her RSA Private Key using PSS padding, creating her digital signature. She transmits the pair `(A, Alice_Signature)` over the network.

**Step 4 — Bob verifies Alice's identity:**
Bob receives `(A, Alice_Signature)`. He uses Alice's pre-loaded RSA Public Key to decrypt `Alice_Signature`, recovering the fingerprint inside. He independently computes SHA-256 of the `A` he received. He compares the two fingerprints. If they match, the signature is authentic — the `A` came from Alice, not an impersonator. If they don't match, Bob terminates the connection immediately.

**Step 5 — Bob responds:**
Bob computes `B = g^b mod p`, signs it with his own RSA Private Key, and sends `(B, Bob_Signature)` to Alice.

**Step 6 — Alice verifies Bob's identity:**
Alice performs the same signature verification process using Bob's pre-loaded RSA Public Key. If it passes, she trusts `B`.

---

### Phase 2: Shared Key Derivation (HKDF)

Alice raises Bob's public value to the power of her own private exponent:

```
SharedSecret = B^a mod p
```

Bob independently does the same with Alice's value:

```
SharedSecret = A^b mod p
```

Because `B = g^b mod p` and `A = g^a mod p`, both computations simplify to `g^(ab) mod p`. The result is mathematically identical on both machines. Neither party transmitted it. The eavesdropper who saw `A` and `B` in transit cannot compute it without solving the Discrete Logarithm Problem.

The raw `SharedSecret` integer is then passed through HKDF. HKDF mixes the integer with a context label through HMAC-SHA256 internally, producing a uniformly distributed 32-byte output. This is the `sharedKey` that will be used for everything that follows.

---

### Phase 3: Seed Encapsulation & Authentication

Alice is now ready to set up the stream cipher. To do that, she needs to agree on a random Seed with Bob.

**Step 1 — Generate Seed:**
Alice generates a 64-bit cryptographically random integer. For this walkthrough, that integer is `42`. She does *not* transmit it directly.

**Step 2 — Encrypt the Seed:**
Alice encodes `42` as a fixed 8-byte big-endian integer. She passes it into AES-256-GCM using the 32-byte `sharedKey` as the encryption key. AES-GCM also requires a random 12-byte nonce (an initialisation value that must be unique per encryption operation). The output is a single ciphertext blob that contains both the encrypted data and the 16-byte GCM authentication tag appended to it — totalling 24 bytes (8 bytes of encrypted seed + 16 bytes of GCM tag).

**Step 3 — Build the vault:**
Alice concatenates the raw bytes into a single binary structure called the vault:

```
vault = nonce + ciphertext       →  12 + 24 = 36 bytes
```

She then computes HMAC-SHA256 over the vault using `sharedKey`, producing a 32-byte authentication tag.

**Step 4 — Transmit:**
Alice prepends the HMAC tag to the vault and transmits the entire structure as one atomic payload:

```
payload = hmac + vault           →  32 + 36 = 68 bytes

┌──────────────────┬────────────┬──────────────────────────┐
│  HMAC (32 bytes) │ Nonce (12) │ AES-GCM Ciphertext (24)  │
└──────────────────┴────────────┴──────────────────────────┘
```

Every field has a fixed, known width. The receiver doesn't need delimiters, headers, or a parser — he just slices at the predetermined byte offsets.

---

### Phase 4: Receiver Synchronization

Bob receives the 68-byte payload from Alice.

**Step 1 — HMAC verification:**
Bob slices the payload at the fixed byte offsets. No parsing, no deserialization — just arithmetic:

```
received_hmac = payload[ 0 : 32]     ← first 32 bytes
vault         = payload[32 : 68]     ← remaining 36 bytes
```

Before touching any cryptographic operation on the vault, Bob must first prove it arrived intact. He computes his own HMAC-SHA256 tag over the vault using his identical `sharedKey`:

```
bobs_hmac = HMAC-SHA256(vault, sharedKey)        ← Bob's freshly computed tag
```

He now has two 32-byte tags side by side and compares them:

```
if received_hmac == bobs_hmac → payload is intact, proceed to decryption
if received_hmac != bobs_hmac → payload was tampered with, reject immediately
```

If the vault traveled untouched, both tags are the product of the same function, same input, and same key — so they are guaranteed to be identical. If Mallory flipped even a single bit anywhere in the 36-byte vault during transit, Bob fed slightly different bytes into HMAC-SHA256 than Alice originally did, and SHA-256's avalanche effect ensures his tag looks nothing like Alice's. The comparison fails, and Bob discards the entire message without attempting decryption.

This comparison is done using Python's `hmac.compare_digest()` constant-time equality function rather than a regular `==` operator. A regular check returns as soon as it finds the first differing byte, which leaks timing information — a sufficiently patient attacker could probe the system repeatedly and use the response times to deduce the correct tag one byte at a time. A constant-time comparison always takes exactly the same amount of time regardless of where or whether a difference exists, closing that side channel entirely.

**Step 2 — Decryption:**
The HMAC matched, so Bob knows the vault is authentic and unmodified. He slices the vault at the next fixed offset:

```
nonce         = vault[ 0 : 12]       ← 12 bytes
ciphertext    = vault[12 : 36]       ← 24 bytes (8 encrypted + 16 GCM tag)
```

He passes the nonce, ciphertext, and `sharedKey` into AES-256-GCM decryption. Out comes the fixed 8-byte big-endian integer, which decodes to `42`.

Both Alice and Bob now hold the same Seed: `42`. Their LCG engines can now be synchronised.

---

### Phase 5: Keystream Generation (LCG)

Alice and Bob each initialise an identical LCG with the Seed `42`.

The LCG constants are fixed and shared by both sides:

```
multiplier = 6364136223846793005
increment  = 1442695040888963407
modulus    = 2^64  (implemented via 64-bit integer overflow)
```

The state update formula:

```
state = (multiplier × state + increment) mod 2^64
```

After each state update, a single output byte is produced by discarding the weak low-order bits:

```
output_byte = (state >> 56) & 0xFF
```

Because both Alice and Bob start from state `42` and apply the exact same formula, they produce the exact same sequence of output bytes. The first call produces `104`, the second produces some other value, and so on — identically, on both machines, forever.

---

### Phase 6: Stream Payload Transmission (XOR)

The ASCII encoding of `"Hello"` is a sequence of five bytes: `[72, 101, 108, 108, 111]`.

**Encrypting 'H' (byte value 72):**

1. Alice calls her LCG once and gets the keystream byte: `104`.
2. She XORs the plaintext byte with the keystream byte: `72 ^ 104 = 32`.
3. She transmits the ciphertext byte `32` over the network.

To an eavesdropper, `32` is meaningless — it's just a number between 0 and 255 with no apparent relationship to any English letter.

**Decrypting 'H' on Bob's side:**

1. Bob calls his LCG once. Because he started from the same Seed and the same formula, he gets exactly `104`.
2. He XORs the ciphertext byte with his keystream byte: `32 ^ 104 = 72`.
3. He converts `72` to a character using its ASCII value and recovers `'H'`.

This process repeats for each of the remaining four bytes in `"Hello"`. Each call to the LCG advances the state by one step on both sides simultaneously, so they remain in lockstep throughout the entire message.

The full decryption of `"Hello"` proceeds byte by byte:

| Plaintext | Plaintext Byte | Keystream Byte | Ciphertext | Recovered |
|-----------|---------------|----------------|------------|-----------|
| H         | 72            | 104            | 32         | H         |
| e         | 101           | (next LCG)     | ...        | e         |
| l         | 108           | (next LCG)     | ...        | l         |
| l         | 108           | (next LCG)     | ...        | l         |
| o         | 111           | (next LCG)     | ...        | o         |

---

### Phase 7: Real-Time UI Synchronization (Queue-Based IPC)

Alice and Bob run in completely separate Python processes, simulating the isolation of two independent machines on a real network. They don't share memory. The main application process — the one managing the GUI — cannot directly reach into Alice or Bob's process and read their internal state.

The question then is: how does the frontend *display* the ciphertext Alice is generating and the plaintext Bob is recovering, in real time?

**The Shared Queue:**

Before the Alice and Bob processes are forked, the main orchestrator creates two `multiprocessing.Queue` objects — one for Alice's output and one for Bob's. These queues are passed into the child processes as arguments before the fork. Because the queues are created before the fork, both the parent process and the child processes hold a reference to the same underlying OS-level shared memory structure. Data pushed into the queue from one process becomes readable in another.

**Streaming Data Into the Queue:**

As Alice encrypts each byte of `"Hello"`, she does two things simultaneously: she sends the ciphertext byte through the network pipe to Bob *and* she pushes a copy of that ciphertext chunk into her `ui_queue`. Similarly, as Bob decrypts each byte, he pushes the recovered plaintext into his own `ui_queue`.

**The Frontend Harvesting Loop:**

Back in the main parent process, a component called the `ApiBridge` runs an asynchronous polling loop. It repeatedly calls `queue.get()` on both queues without blocking the main thread. When a new item appears in Alice's queue, the `ApiBridge` pulls it out and updates the GUI to show the latest ciphertext chunk. When a new item appears in Bob's queue, it similarly updates the decrypted plaintext display.

This architecture guarantees that the GUI is always showing real data produced by the actual cryptographic backend — not simulated or mocked output. Every character displayed on screen passed through the full pipeline: LCG keystream generation, XOR encryption, network transmission (via the pipe), XOR decryption, and queue delivery. The UI is a faithful real-time mirror of the cryptographic reality.
