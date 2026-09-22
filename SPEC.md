# VaultSeal

Item scheme version byte: `0x01`. X25519 wrap version byte: `0x01`. Hybrid wrap version byte: `0x02`.

A breaking change to a layout requires a new version byte. This library rejects any other version before it attempts to decrypt.

## Suite

| Use | Algorithm |
|-----|-----------|
| Item encryption | AES-256-GCM. The 32-byte vault key is the AES-256 key. There is no HKDF over the vault key. |
| Nonce | 12 bytes from a CSPRNG, chosen inside `sealItem`. Callers cannot supply it. |
| Tag | 16 bytes |
| Wrap | HPKE Base, one message (RFC 9180 §§4, 5.1, 7.1) |
| KEM | `0x0020` DHKEM(X25519, HKDF-SHA256) |
| KDF | `0x0001` HKDF-SHA256 |
| AEAD | `0x0002` AES-256-GCM |
| Mode | Base (`0x00`). PSK, Auth, and AuthPSK are not implemented. |
| Member keys | 32 raw bytes, RFC 7748. No PEM and no JSON. |

The HPKE sequence number for a wrap is 0. The AES-GCM nonce is `base_nonce` XOR that sequence and is not stored. DHKEM rejects an all-zero shared secret.

`lib/src/hpke.dart` is a transcription of those RFC sections for Base mode only. It is not part of the supported public API.

## Sealed item

Minimum length 29 bytes. Ciphertext may be empty. Maximum plaintext is 8388608 bytes, so the maximum framed length is `1 + 12 + 8388608 + 16`.

```text
0x01 || nonce(12) || ciphertext || tag(16)
```

The tag is the last 16 bytes. Bytes `[1, 13)` are the nonce.

Associated data is not stored in the blob. `openItem` must be given the same `SealContext` used to seal.

```text
ascii("vaultseal-item")
|| u16be(vaultIdUtf8.length) || vaultIdUtf8
|| u16be(itemIdUtf8.length) || itemIdUtf8
|| u8(purpose)
```

`purpose` in scheme 1 is `1` (`ItemPurpose.item`). `vaultId` and `itemId` are non-empty UTF-8, each at most 256 bytes. Multi-byte integers are big-endian.

## Wrapped vault key

Length is always 81 bytes.

```text
0x01 || enc(32) || ct(48)
```

`enc` is the HPKE encapsulated ephemeral X25519 public key. `ct` is the 32-byte vault key concatenated with the 16-byte tag.

HPKE `info` and HPKE `aad` are the same bytes:

```text
ascii("vaultseal-wrap")
|| u32be(keyGeneration)
|| u16be(vaultIdUtf8.length) || vaultIdUtf8
|| recipientPublicKey(32)
```

`keyGeneration` is a `uint32` greater than or equal to 1. A future rotation keeps scheme 1 and uses a new generation.

## Errors

`VaultSealFormatException` is thrown for a bad version, a bad length, an empty or oversized id, a plaintext longer than 8388608 bytes, `keyGeneration` outside `1 .. 2^32-1`, or a public or private key that is not 32 bytes. The check on plaintext length happens before encryption.

`VaultSealAuthenticationException` is the only failure used for a bad tag, a wrong vault key, a mismatched context, a wrong recipient, or a rejected X25519 public key. The message is always `authentication failed`. It does not name the cause and it does not include plaintext.

Using a key after `destroy()` throws `StateError`.

## Nonce budget

Random 96-bit nonces collide with probability about 2^-32 after 2^32 messages under one key. The library is stateless and does not count seals. The app must rotate the vault key before that budget. Revoking a member without rotating the vault key leaves that member able to open existing items.

## Secret handling

`VaultKey.fromBytes` and `MemberKeyPair.fromPrivateKeyBytes` copy the caller’s buffer. The stored X25519 private key is the clamped RFC 7748 scalar. `destroy()` overwrites this library’s `Uint8List` with zeros. The Dart VM may already have copied those bytes, so the wipe is best-effort.

`toString` on `VaultKey` and `MemberKeyPair` does not contain key material.

## Known limitations

AES-GCM is not key-committing. Scheme 1 accepts that because the honest client chooses the vault key.

HPKE Base does not authenticate the sender. Replacing a wrap with a new seal to the same public key produces a blob that unwraps. The app must bind each wrap to an authenticated membership record before trusting it. Scheme 1 does not sign wraps.

This library does not derive keys from passwords.

## Scheme 2 wrap

Items stay on scheme 1. Only the vault-key wrap changes.

| Use | Algorithm |
|-----|-----------|
| Item encryption | Unchanged AES-256-GCM under the vault key. |
| Classical half | X25519, RFC 7748. An all-zero shared secret is rejected. |
| Post-quantum half | ML-KEM-768, FIPS 203. |
| Combiner | HKDF-SHA256. `info` begins with `ascii("VaultSeal-Hybrid-Wrap-v2")`. |
| Vault-key AEAD | AES-256-GCM. The HKDF output is the 32-byte key. The 12-byte nonce is stored. |

`KeyAgreementScheme.hybridMlKem768` is this wrap. `KeyAgreementScheme.x25519` is scheme 1.

### Hybrid member key

Public key, 1216 bytes:

```text
x25519_public(32) || mlkem768_encapsulation_key(1184)
```

Private key, 2432 bytes:

```text
x25519_clamped_scalar(32) || mlkem768_decapsulation_key(2400)
```

The ML-KEM decapsulation key is the FIPS 203 encoding. The encapsulation key is the slice that encoding stores after the K-PKE secret.

### Hybrid wrapped vault key

Length is always 1181 bytes.

```text
0x02 || x25519_enc(32) || mlkem768_ciphertext(1088) || nonce(12) || vault_key(32) || tag(16)
```

`x25519_enc` is the ephemeral X25519 public key. `mlkem768_ciphertext` is the ML-KEM-768 ciphertext. `vault_key` is the AES-GCM ciphertext of the 32-byte vault key. `tag` is the last 16 bytes.

HKDF-SHA256 inputs:

```text
salt = empty (32 zero bytes inside Extract)
ikm  = x25519_shared_secret(32) || mlkem768_shared_secret(32)
info = ascii("VaultSeal-Hybrid-Wrap-v2")
    || x25519_enc(32)
    || mlkem768_ciphertext(1088)
    || recipient_hybrid_public_key(1216)
L    = 32
```

AES-GCM associated data is the scheme-1 wrap label with the hybrid public key in place of the X25519 public key:

```text
ascii("vaultseal-wrap")
|| u32be(keyGeneration)
|| u16be(vaultIdUtf8.length) || vaultIdUtf8
|| recipient_hybrid_public_key(1216)
```

A future rotation keeps version `0x02` and uses a new `keyGeneration`.

## Rotation

`rotateVaultKey` generates a new 32-byte vault key, opens each listed item with the current key, and seals it again under the new key with the same item associated data. It then wraps the new key to each X25519 recipient (scheme 1) and each hybrid recipient (scheme 2) under the caller-supplied `nextGeneration`.

The function does not delete the previous generation. The app stores the new blobs and stops serving the old ones. A member who already holds the old vault key can still open the old items.

## Ephemeral share

`sealSharePayload` encrypts bytes under a 32-byte DEK with AES-256-GCM. The associated data is:

```text
utf8(shareId) || 0x00 || utf8(senderId)
```

The result is three fields and has no version byte: nonce (12), ciphertext, tag (16). Those fields are the share v2 `iv`, `encrypted_data`, and `auth_tag`. The PIN is not an input. The app keeps the PIN gate and decides how the DEK is delivered.
