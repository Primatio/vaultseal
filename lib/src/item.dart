import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';

import 'aad.dart';
import 'framing.dart';
import 'scheme.dart';
import 'vault_key.dart';

/// A scheme-1 sealed vault item.
///
/// Layout: `0x01 || nonce(12) || ciphertext || tag(16)`.
final class SealedItem {
  SealedItem._(this._bytes);

  final Uint8List _bytes;

  /// Parses [bytes] as a scheme-1 sealed item.
  ///
  /// The bytes are copied. A bad version or length throws
  /// [VaultSealFormatException]. Authentication is checked by [openItem].
  factory SealedItem.parse(Uint8List bytes) {
    parseSealedItem(bytes);
    return SealedItem._(Uint8List.fromList(bytes));
  }

  /// A copy of the framed bytes.
  Uint8List toBytes() => Uint8List.fromList(_bytes);
}

/// Seals [plaintext] under [vaultKey] and [context].
///
/// The vault key is the AES-256-GCM key. A fresh 12-byte nonce is chosen for
/// every call. [plaintext] may be empty and may contain any bytes, including
/// sequences that are not UTF-8. Plaintexts longer than [maxPlaintextLength]
/// are rejected before encryption.
///
/// The app must rotate [vaultKey] before 2^32 seals. This function does not
/// count them.
Future<SealedItem> sealItem({
  required Uint8List plaintext,
  required VaultKey vaultKey,
  required SealContext context,
}) {
  return _seal(
    plaintext: plaintext,
    vaultKey: vaultKey,
    context: context,
    nonce: null,
    purposeByte: null,
  );
}

/// Same as [sealItem], with a caller-supplied nonce for known-answer tests.
///
/// Not part of the supported public API.
@visibleForTesting
Future<SealedItem> sealItemForTest({
  required Uint8List plaintext,
  required VaultKey vaultKey,
  required SealContext context,
  required Uint8List nonce,
  int? purposeByte,
}) {
  return _seal(
    plaintext: plaintext,
    vaultKey: vaultKey,
    context: context,
    nonce: nonce,
    purposeByte: purposeByte,
  );
}

/// Opens [sealed] with [vaultKey] and [context].
///
/// A wrong key, a wrong context, or a modified blob all throw
/// [VaultSealAuthenticationException]. The exception does not say which.
Future<Uint8List> openItem({
  required SealedItem sealed,
  required VaultKey vaultKey,
  required SealContext context,
}) {
  return _open(
    sealed: sealed,
    vaultKey: vaultKey,
    aad: context.toAad(),
  );
}

/// Same as [openItem], with an optional purpose byte override for tests.
///
/// Not part of the supported public API.
@visibleForTesting
Future<Uint8List> openItemForTest({
  required SealedItem sealed,
  required VaultKey vaultKey,
  required SealContext context,
  int? purposeByte,
}) {
  final aad = purposeByte == null
      ? context.toAad()
      : encodeItemAad(
          vaultId: context.vaultId,
          itemId: context.itemId,
          purposeByte: purposeByte,
        );
  return _open(sealed: sealed, vaultKey: vaultKey, aad: aad);
}

Future<SealedItem> _seal({
  required Uint8List plaintext,
  required VaultKey vaultKey,
  required SealContext context,
  required Uint8List? nonce,
  required int? purposeByte,
}) async {
  if (plaintext.length > maxPlaintextLength) {
    throw const VaultSealFormatException(
      'Plaintext exceeds 8388608 bytes.',
    );
  }
  final keyBytes = vaultKey.toBytes();
  final chosenNonce =
      nonce ?? Uint8List.fromList(AesGcm.with256bits().newNonce());
  if (chosenNonce.length != nonceLength) {
    throw const VaultSealFormatException('Nonce must be 12 bytes.');
  }
  final aad = purposeByte == null
      ? context.toAad()
      : encodeItemAad(
          vaultId: context.vaultId,
          itemId: context.itemId,
          purposeByte: purposeByte,
        );
  try {
    final box = await AesGcm.with256bits().encrypt(
      plaintext,
      secretKey: SecretKey(keyBytes),
      nonce: chosenNonce,
      aad: aad,
    );
    final framed = frameSealedItem(
      nonce: chosenNonce,
      cipherText: Uint8List.fromList(box.cipherText),
      tag: Uint8List.fromList(box.mac.bytes),
    );
    return SealedItem._(framed);
  } finally {
    keyBytes.fillRange(0, keyBytes.length, 0);
  }
}

Future<Uint8List> _open({
  required SealedItem sealed,
  required VaultKey vaultKey,
  required Uint8List aad,
}) async {
  final parsed = parseSealedItem(sealed.toBytes());
  final keyBytes = vaultKey.toBytes();
  final box = SecretBox(
    parsed.cipherText,
    nonce: parsed.nonce,
    mac: Mac(parsed.tag),
  );
  try {
    final clear = await AesGcm.with256bits().decrypt(
      box,
      secretKey: SecretKey(keyBytes),
      aad: aad,
    );
    return Uint8List.fromList(clear);
  } on SecretBoxAuthenticationError {
    throw const VaultSealAuthenticationException();
  } finally {
    keyBytes.fillRange(0, keyBytes.length, 0);
  }
}
