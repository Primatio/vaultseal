import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';

import 'scheme.dart';

/// Associated data for an ephemeral share payload.
///
/// The bytes are `utf8(shareId) || 0x00 || utf8(senderId)`. That is the share
/// v2 associated data. The PIN is not part of it and is not an argument of
/// [sealSharePayload]. The app keeps the PIN gate and the delivery of the DEK.
final class ShareContext {
  /// Creates a share context.
  ///
  /// [shareId] and [senderId] must be non-empty UTF-8, each at most 256 bytes.
  ShareContext({required String shareId, required String senderId})
      : shareId = _shareId(shareId, 'shareId'),
        senderId = _shareId(senderId, 'senderId');

  /// Stable id of the share.
  final String shareId;

  /// Id of the member who created the share.
  final String senderId;

  /// Canonical associated data for this context.
  Uint8List toAad() {
    final id = utf8.encode(shareId);
    final sender = utf8.encode(senderId);
    final out = Uint8List(id.length + 1 + sender.length);
    out.setAll(0, id);
    out[id.length] = 0;
    out.setAll(id.length + 1, sender);
    return out;
  }
}

/// A 32-byte data-encryption key for one ephemeral share.
///
/// This is not a vault key. Call [destroy] when the share no longer needs it.
/// Wiping is best-effort: the Dart VM may already have copied the bytes.
final class ShareDek {
  ShareDek._(this._bytes);

  final Uint8List _bytes;
  var _destroyed = false;

  /// Generates a share DEK from a CSPRNG.
  static Future<ShareDek> generate() async {
    final secret = await AesGcm.with256bits().newSecretKey();
    final bytes = await secret.extractBytes();
    return ShareDek._(Uint8List.fromList(bytes));
  }

  /// Copies [bytes] into a share DEK.
  ///
  /// [bytes] must be exactly 32 bytes. Later changes to the caller's list do
  /// not change the key.
  factory ShareDek.fromBytes(Uint8List bytes) {
    if (bytes.length != vaultKeyLength) {
      throw const VaultSealFormatException('Share DEK must be 32 bytes.');
    }
    return ShareDek._(Uint8List.fromList(bytes));
  }

  /// A copy of the raw key.
  ///
  /// Throws [StateError] if [destroy] has been called.
  Uint8List toBytes() {
    _check();
    return Uint8List.fromList(_bytes);
  }

  /// Overwrites the key bytes with zeros.
  void destroy() {
    _bytes.fillRange(0, _bytes.length, 0);
    _destroyed = true;
  }

  /// Whether [destroy] has been called.
  bool get isDestroyed => _destroyed;

  void _check() {
    if (_destroyed) {
      throw StateError('ShareDek has been destroyed.');
    }
  }

  /// Returns `ShareDek()`. The text does not contain key bytes.
  @override
  String toString() => 'ShareDek()';
}

/// AES-256-GCM share payload split into the three share-v2 fields.
///
/// [nonce] is the `iv`, [ciphertext] is `encrypted_data`, and [tag] is
/// `auth_tag`. There is no version byte. The app base64-encodes each field.
final class SealedSharePayload {
  /// Copies the three fields.
  SealedSharePayload({
    required Uint8List nonce,
    required Uint8List ciphertext,
    required Uint8List tag,
  })  : nonce = Uint8List.fromList(nonce),
        ciphertext = Uint8List.fromList(ciphertext),
        tag = Uint8List.fromList(tag) {
    if (this.nonce.length != nonceLength || this.tag.length != tagLength) {
      throw const VaultSealFormatException(
        'Share payload nonce must be 12 bytes and the tag 16 bytes.',
      );
    }
    if (this.ciphertext.length > maxPlaintextLength) {
      throw const VaultSealFormatException(
        'Share ciphertext exceeds 8388608 bytes.',
      );
    }
  }

  /// 12-byte AES-GCM nonce.
  final Uint8List nonce;

  /// Ciphertext, the same length as the plaintext. May be empty.
  final Uint8List ciphertext;

  /// 16-byte AES-GCM tag.
  final Uint8List tag;
}

/// Seals [plaintext] under [dek] and [context].
///
/// A fresh 12-byte nonce is chosen for every call. [plaintext] may be empty
/// and may contain any bytes. Plaintexts longer than [maxPlaintextLength] are
/// rejected before encryption. The PIN is not used.
Future<SealedSharePayload> sealSharePayload({
  required Uint8List plaintext,
  required ShareDek dek,
  required ShareContext context,
}) {
  return _sealShare(
    plaintext: plaintext,
    dek: dek,
    context: context,
    nonce: null,
  );
}

/// Same as [sealSharePayload], with a caller-supplied nonce for tests.
///
/// Not part of the supported public API.
@visibleForTesting
Future<SealedSharePayload> sealSharePayloadForTest({
  required Uint8List plaintext,
  required ShareDek dek,
  required ShareContext context,
  required Uint8List nonce,
}) {
  return _sealShare(
    plaintext: plaintext,
    dek: dek,
    context: context,
    nonce: nonce,
  );
}

/// Opens [payload] with [dek] and [context].
///
/// A wrong DEK, a wrong context, or a modified field all throw
/// [VaultSealAuthenticationException].
Future<Uint8List> openSharePayload({
  required SealedSharePayload payload,
  required ShareDek dek,
  required ShareContext context,
}) async {
  final keyBytes = dek.toBytes();
  final box = SecretBox(
    payload.ciphertext,
    nonce: payload.nonce,
    mac: Mac(payload.tag),
  );
  try {
    final clear = await AesGcm.with256bits().decrypt(
      box,
      secretKey: SecretKey(keyBytes),
      aad: context.toAad(),
    );
    return Uint8List.fromList(clear);
  } on SecretBoxAuthenticationError {
    throw const VaultSealAuthenticationException();
  } finally {
    keyBytes.fillRange(0, keyBytes.length, 0);
  }
}

Future<SealedSharePayload> _sealShare({
  required Uint8List plaintext,
  required ShareDek dek,
  required ShareContext context,
  required Uint8List? nonce,
}) async {
  if (plaintext.length > maxPlaintextLength) {
    throw const VaultSealFormatException(
      'Plaintext exceeds 8388608 bytes.',
    );
  }
  final chosenNonce =
      nonce ?? Uint8List.fromList(AesGcm.with256bits().newNonce());
  if (chosenNonce.length != nonceLength) {
    throw const VaultSealFormatException('Nonce must be 12 bytes.');
  }
  final keyBytes = dek.toBytes();
  try {
    final box = await AesGcm.with256bits().encrypt(
      plaintext,
      secretKey: SecretKey(keyBytes),
      nonce: chosenNonce,
      aad: context.toAad(),
    );
    return SealedSharePayload(
      nonce: chosenNonce,
      ciphertext: Uint8List.fromList(box.cipherText),
      tag: Uint8List.fromList(box.mac.bytes),
    );
  } finally {
    keyBytes.fillRange(0, keyBytes.length, 0);
  }
}

String _shareId(String value, String name) {
  final Uint8List bytes;
  try {
    bytes = Uint8List.fromList(utf8.encode(value));
  } on FormatException {
    throw VaultSealFormatException('$name must be valid UTF-8.');
  }
  if (bytes.isEmpty || bytes.length > maxIdentifierLength) {
    throw VaultSealFormatException(
      '$name must be 1 to $maxIdentifierLength UTF-8 bytes.',
    );
  }
  return value;
}
