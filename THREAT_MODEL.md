# Threat model

VaultSeal scheme 1 encrypts vault items and wraps the vault key. It does not authenticate membership, rotate keys, or derive keys from a password.

## Actors

| Actor | What scheme 1 guarantees |
|-------|--------------------------|
| Honest-but-curious server | Sees sealed items and wraps only. Those blobs are not sufficient to recover the vault key or the plaintext. |
| Member who holds a wrap | Can open items sealed under that vault key. |
| Revoked member | Can still open items sealed under the old vault key. The app has to re-seal under a new vault key. This library does not rotate. |
| Malicious storage | AEAD rejects a modified blob. It does not stop the storage from replacing a wrap with a new HPKE Base seal to the same public key. HPKE Base does not authenticate the sender, so that replacement unwraps to a vault key the replacer chose. The app must bind each wrap to an authenticated membership record before trusting it. Scheme 1 does not sign wraps. |
| Compromised device, memory dump, or password guessing | Out of scope. There is no password KDF. `destroy()` zeroes only the copy this library still holds, and the Dart VM may have copied it already. |
| LLM or agent | Out of scope. The API takes bytes from the application. It is not an interface for a model. |

## Algorithm limits

AES-256-GCM with a random 96-bit nonce is safe for far fewer than 2^32 seals under one vault key. Past that, the nonce-collision probability reaches about 2^-32. The library does not count seals. The app rotates the vault key first.

AES-GCM is not key-committing. Scheme 1 accepts that while the honest client chooses the vault key. A later scheme can switch algorithms if that assumption changes.

Item associated data is not inside the ciphertext framing. Opening requires the same vault id, item id, and purpose. A server that changes those fields, and an app that feeds the changed fields into `openItem`, gets an authentication failure rather than the plaintext.

## Out of scope

Password hashing, post-quantum hybrids, HPKE authentication modes, wrap signatures, vault-key rotation, and any product rule about what a member may export.
