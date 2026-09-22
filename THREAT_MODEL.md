# Threat model

VaultSeal encrypts vault items and wraps the vault key. It does not authenticate membership or derive keys from a password. `rotateVaultKey` reseals and rewraps when the app asks it to. The app still has to replace the stored blobs.

## Actors

| Actor | What the library guarantees |
|-------|--------------------------|
| Honest-but-curious server | Sees sealed items and wraps only. Those blobs are not sufficient to recover the vault key or the plaintext. |
| Member who holds a wrap | Can open items sealed under that vault key. |
| Revoked member | Can still open items sealed under a vault key that member already unwrapped. `rotateVaultKey` produces a new key, new item ciphertexts, and new wraps. The app must store those blobs and stop serving the previous generation. |
| Malicious storage | AEAD rejects a modified blob. It does not stop the storage from replacing a wrap with a new seal to the same public key. Scheme 1 is HPKE Base and scheme 2 is an unauthenticated hybrid KEM, so that replacement unwraps to a vault key the replacer chose. The app must bind each wrap to an authenticated membership record before trusting it. Neither scheme signs wraps. |
| Compromised device, memory dump, or password guessing | Out of scope. There is no password KDF. `destroy()` zeroes only the copy this library still holds, and the Dart VM may have copied it already. |
| LLM or agent | Out of scope. The API takes bytes from the application. It is not an interface for a model. |

## Algorithm limits

AES-256-GCM with a random 96-bit nonce is safe for far fewer than 2^32 seals under one vault key. Past that, the nonce-collision probability reaches about 2^-32. The library does not count seals. The app rotates the vault key first.

AES-GCM is not key-committing. This library accepts that while the honest client chooses the vault key.

## Harvest now, decrypt later

A scheme-1 wrap is X25519. A ciphertext recorded today can be unwrapped later by an attacker who can break that X25519 public key. Scheme 2 wraps the same vault key under X25519 and ML-KEM-768. The HKDF combiner takes both shared secrets and both ciphertexts, so the vault key stays confidential if either algorithm holds.

Items do not change. They remain AES-256-GCM under the vault key. Scheme 2 does not replace that item encryption. An attacker who never obtains the vault key still has to attack AES-256-GCM.

Scheme 2 does not authenticate the sender. The membership binding required for scheme 1 still applies.

Item associated data is not inside the ciphertext framing. Opening requires the same vault id, item id, and purpose. A server that changes those fields, and an app that feeds the changed fields into `openItem`, gets an authentication failure rather than the plaintext.

## Out of scope

Password hashing, HPKE authentication modes, wrap signatures, and any product rule about what a member may export. The share PIN is an application gate. This library never uses it as a key.
