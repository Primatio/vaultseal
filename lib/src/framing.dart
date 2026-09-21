import 'dart:typed_data';

import 'scheme.dart';

/// Pieces of a scheme-1 sealed item, without the version byte.
final class ParsedSealedItem {
  /// Creates parsed fields.
  ParsedSealedItem({
    required this.nonce,
    required this.cipherText,
    required this.tag,
  });

  /// 12-byte AES-GCM nonce.
  final Uint8List nonce;

  /// Ciphertext, the same length as the plaintext. May be empty.
  final Uint8List cipherText;

  /// 16-byte AES-GCM tag.
  final Uint8List tag;
}

/// `0x01 || nonce(12) || ciphertext || tag(16)`.
Uint8List frameSealedItem({
  required Uint8List nonce,
  required Uint8List cipherText,
  required Uint8List tag,
}) {
  if (nonce.length != nonceLength || tag.length != tagLength) {
    throw const VaultSealFormatException('Sealed item frame is invalid.');
  }
  final out = Uint8List(1 + nonce.length + cipherText.length + tag.length);
  out[0] = schemeVersion;
  out.setAll(1, nonce);
  out.setAll(1 + nonce.length, cipherText);
  out.setAll(out.length - tag.length, tag);
  return out;
}

/// Splits a scheme-1 sealed item.
///
/// Rejects a bad version, a short blob, and a blob larger than
/// [sealedItemMaxLength].
ParsedSealedItem parseSealedItem(Uint8List bytes) {
  if (bytes.length < sealedItemMinLength ||
      bytes.length > sealedItemMaxLength) {
    throw const VaultSealFormatException('Sealed item has an invalid length.');
  }
  if (bytes[0] != schemeVersion) {
    throw const VaultSealFormatException('Sealed item version is not 1.');
  }
  final nonce = Uint8List.sublistView(bytes, 1, 1 + nonceLength);
  final tagStart = bytes.length - tagLength;
  final cipherText = Uint8List.sublistView(bytes, 1 + nonceLength, tagStart);
  final tag = Uint8List.sublistView(bytes, tagStart);
  return ParsedSealedItem(
    nonce: Uint8List.fromList(nonce),
    cipherText: Uint8List.fromList(cipherText),
    tag: Uint8List.fromList(tag),
  );
}

/// `0x01 || enc(32) || ciphertext(48)`.
Uint8List frameWrappedVaultKey({
  required Uint8List enc,
  required Uint8List ciphertext,
}) {
  if (enc.length != x25519KeyLength ||
      ciphertext.length != vaultKeyLength + tagLength) {
    throw StateError('Wrapped vault key frame is invalid.');
  }
  final out = Uint8List(wrappedVaultKeyLength);
  out[0] = schemeVersion;
  out.setAll(1, enc);
  out.setAll(1 + enc.length, ciphertext);
  return out;
}

/// Splits a scheme-1 wrapped vault key.
///
/// Any length other than [wrappedVaultKeyLength], and any version other than
/// 1, is a format error.
({Uint8List enc, Uint8List ciphertext}) parseWrappedVaultKey(Uint8List bytes) {
  if (bytes.length != wrappedVaultKeyLength) {
    throw const VaultSealFormatException(
      'Wrapped vault key must be 81 bytes.',
    );
  }
  if (bytes[0] != schemeVersion) {
    throw const VaultSealFormatException('Wrapped vault key version is not 1.');
  }
  return (
    enc: Uint8List.sublistView(bytes, 1, 1 + x25519KeyLength),
    ciphertext: Uint8List.sublistView(bytes, 1 + x25519KeyLength),
  );
}
