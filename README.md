# VaultSeal

VaultSeal seals vault items under a vault key and wraps that key to members.
The server stores ciphertext only.

This is the Dart package. The PyPI project named `vaultseal` is a different tool.

Scheme 1 wire format is stable in 0.1.0. The Dart API can still change before 1.0.0.

## Install

```yaml
dependencies:
  vaultseal: ^0.1.0
```

```dart
import 'package:vaultseal/vaultseal.dart';
```

## Example

`example/main.dart` seals one item and wraps the vault key to one member:

```dart
final key = await VaultKey.generate();
final member = await MemberKeyPair.generate();
final item = SealContext(vaultId: 'vault-1', itemId: 'item-1');
final sealed = await sealItem(
  plaintext: Uint8List.fromList(utf8.encode('hello vault')),
  vaultKey: key,
  context: item,
);
final opened = await openItem(sealed: sealed, vaultKey: key, context: item);
```

## What scheme 1 does

- Item encryption is AES-256-GCM. The 32-byte vault key is the AES key.
- Vault-key wrap is HPKE Base, single-shot: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM (RFC 9180).
- Associated data binds `vaultId`, `itemId`, and purpose for items, and `vaultId`, `keyGeneration`, and the recipient public key for wraps.

Byte layout, limits, and error behavior are in [SPEC.md](SPEC.md).

## Limits the app must honor

- Rotate a vault key before 2^32 seals. Nonces are random and this library does not count them.
- Plaintext longer than 8 MiB is rejected.
- HPKE Base does not authenticate the sender. Bind each wrap to an authenticated membership record before trusting it. See [THREAT_MODEL.md](THREAT_MODEL.md).
- `destroy()` zeroes the copy this library holds. That wipe is best-effort on the Dart VM.

Report vulnerabilities through [SECURITY.md](SECURITY.md). Do not open a public issue that contains key material.
