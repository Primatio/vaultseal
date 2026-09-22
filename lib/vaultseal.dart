/// Seal vault items under a vault key and wrap that key to members.
///
/// Scheme 1 wire format is stable: AES-256-GCM items and HPKE X25519 wraps.
/// Scheme 2 wraps the same vault key with ML-KEM-768 and X25519. Items stay
/// on scheme 1. The Dart API may change before 1.0.0.
library;

export 'src/aad.dart' show ItemPurpose, SealContext, WrapContext;
export 'src/hybrid_key.dart' show HybridMemberKeyPair, HybridMemberPublicKey;
export 'src/hybrid_wrap.dart'
    show HybridWrappedVaultKey, unwrapHybridVaultKey, wrapHybridVaultKey;
export 'src/item.dart' show SealedItem, openItem, sealItem;
export 'src/member_key.dart' show MemberKeyPair, MemberPublicKey;
export 'src/rotate.dart' show RotationItem, VaultRotation, rotateVaultKey;
export 'src/scheme.dart'
    show
        KeyAgreementScheme,
        VaultSealAuthenticationException,
        VaultSealFormatException,
        hybridPrivateKeyLength,
        hybridPublicKeyLength,
        hybridWrapScheme,
        hybridWrappedVaultKeyLength,
        maxPlaintextLength,
        schemeVersion,
        wrappedVaultKeyLength,
        x25519WrapScheme;
export 'src/share.dart'
    show
        SealedSharePayload,
        ShareContext,
        ShareDek,
        openSharePayload,
        sealSharePayload;
export 'src/vault_key.dart' show VaultKey;
export 'src/wrap.dart' show WrappedVaultKey, unwrapVaultKey, wrapVaultKey;
