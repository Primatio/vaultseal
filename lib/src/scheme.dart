/// Scheme 1: AES-256-GCM items and HPKE Base X25519 wraps.
const int schemeVersion = 1;

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

/// Shortest scheme-1 sealed item: version, nonce, empty ciphertext, tag.
const int sealedItemMinLength = 1 + nonceLength + tagLength;

/// Longest scheme-1 sealed item this library will parse.
const int sealedItemMaxLength =
    1 + nonceLength + maxPlaintextLength + tagLength;

/// Maximum UTF-8 length of a vault id or item id.
const int maxIdentifierLength = 256;

/// A blob or argument does not match scheme 1.
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
