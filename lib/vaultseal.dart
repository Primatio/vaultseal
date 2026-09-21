/// Seal vault items under a vault key and wrap that key to members.
///
/// Scheme 1 wire format is stable. The Dart API may change before 1.0.0.
library;

export 'src/aad.dart' show ItemPurpose, SealContext, WrapContext;
export 'src/item.dart' show SealedItem, openItem, sealItem;
export 'src/member_key.dart' show MemberKeyPair, MemberPublicKey;
export 'src/scheme.dart'
    show
        VaultSealAuthenticationException,
        VaultSealFormatException,
        maxPlaintextLength,
        schemeVersion,
        wrappedVaultKeyLength;
export 'src/vault_key.dart' show VaultKey;
export 'src/wrap.dart' show WrappedVaultKey, unwrapVaultKey, wrapVaultKey;
