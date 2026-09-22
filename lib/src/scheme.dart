/// Item scheme and X25519 wrap scheme. The version byte of a sealed item and
/// of a scheme-1 wrapped vault key.
const int schemeVersion = 1;

/// X25519 HPKE wrap. Same byte as [schemeVersion].
const int x25519WrapScheme = 1;

/// ML-KEM-768 + X25519 hybrid wrap. The version byte of a hybrid wrapped vault key.
const int hybridWrapScheme = 2;

/// How a vault key is wrapped to a member.
enum KeyAgreementScheme {
  /// HPKE Base with X25519. Wire version [x25519WrapScheme].
  x25519(x25519WrapScheme),

  /// ML-KEM-768 and X25519, combined with HKDF-SHA256. Wire version
  /// [hybridWrapScheme].
  hybridMlKem768(hybridWrapScheme);

  /// Creates a scheme whose wrap version byte is [wrapScheme].
  const KeyAgreementScheme(this.wrapScheme);

  /// Version byte written at the start of a wrapped vault key.
  final int wrapScheme;
}

/// Maximum item plaintext accepted by [sealItem], in bytes (8 MiB).
const int maxPlaintextLength = 8388608;

/// Byte length of every scheme-1 [WrappedVaultKey].
const int wrappedVaultKeyLength = 81;

/// Vault key length in bytes.
const int vaultKeyLength = 32;

/// AES-GCM nonce length in bytes.
const int nonceLength = 12;

/// AES-GCM tag length in bytes.
const int tagLength = 16;

/// X25519 public and private key length in bytes.
const int x25519KeyLength = 32;

/// ML-KEM-768 encapsulation key length in bytes (FIPS 203).
const int mlKem768PublicKeyLength = 1184;

/// ML-KEM-768 decapsulation key length in bytes (FIPS 203).
const int mlKem768PrivateKeyLength = 2400;

/// ML-KEM-768 ciphertext length in bytes (FIPS 203).
const int mlKem768CiphertextLength = 1088;

/// Hybrid member public key: X25519 public key followed by the ML-KEM-768
/// encapsulation key.
const int hybridPublicKeyLength = x25519KeyLength + mlKem768PublicKeyLength;

/// Hybrid member private key: clamped X25519 scalar followed by the ML-KEM-768
/// decapsulation key.
const int hybridPrivateKeyLength = x25519KeyLength + mlKem768PrivateKeyLength;

/// Byte length of every hybrid wrapped vault key.
///
/// `version || x25519 enc || ML-KEM ciphertext || nonce || vault key || tag`.
const int hybridWrappedVaultKeyLength = 1 +
    x25519KeyLength +
    mlKem768CiphertextLength +
    nonceLength +
    vaultKeyLength +
    tagLength;

/// Shortest scheme-1 sealed item: version, nonce, empty ciphertext, tag.
const int sealedItemMinLength = 1 + nonceLength + tagLength;

/// Longest scheme-1 sealed item this library will parse.
const int sealedItemMaxLength =
    1 + nonceLength + maxPlaintextLength + tagLength;

/// Maximum UTF-8 length of a vault id or item id.
const int maxIdentifierLength = 256;

/// A blob or argument does not match the vaultseal format.
final class VaultSealFormatException implements Exception {
  /// Creates a format error.
  ///
  /// [message] describes the rejected field. It does not include key material
  /// or plaintext.
  const VaultSealFormatException(this.message);

  /// What was rejected.
  final String message;

  @override
  String toString() => 'VaultSealFormatException: $message';
}

/// Authentication failed while opening an item or unwrapping a vault key.
///
/// The same exception is thrown for a bad tag, a wrong vault key, a mismatched
/// context, and a wrong recipient. The message does not say which, and it
/// does not include plaintext.
final class VaultSealAuthenticationException implements Exception {
  /// Creates an authentication failure.
  const VaultSealAuthenticationException();

  @override
  String toString() =>
      'VaultSealAuthenticationException: authentication failed';
}
