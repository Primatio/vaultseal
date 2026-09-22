## 0.3.0

- Add scheme 2 vault-key wrap: ML-KEM-768 plus X25519, combined with HKDF-SHA256 (`VaultSeal-Hybrid-Wrap-v2`). Item encryption stays AES-256-GCM.
- Add `rotateVaultKey` to reseal items under a new vault key and wrap that key to the remaining members.
- Add `sealSharePayload` for the ephemeral share DEK. The PIN remains an application gate.

## 0.1.0

- Initial release of scheme 1: AES-256-GCM item sealing and HPKE Base (X25519, HKDF-SHA256, AES-256-GCM) vault-key wrap.
- Wire format for scheme 1 is stable. The Dart API may change before 1.0.0.
