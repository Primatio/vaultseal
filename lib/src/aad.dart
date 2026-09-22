import 'dart:convert';
import 'dart:typed_data';

import 'scheme.dart';

/// Why a sealed item exists.
///
/// Scheme 1 defines a single purpose.
enum ItemPurpose {
  /// A vault item body.
  item(1);

  /// Creates a purpose whose associated-data byte is [byte].
  const ItemPurpose(this.byte);

  /// Byte written at the end of the item associated data.
  final int byte;
}

/// Associated data for [sealItem] and [openItem].
///
/// The bytes are not stored inside the sealed item. Opening succeeds only when
/// the same vault id, item id, and purpose are supplied again.
final class SealContext {
  /// Creates a scheme-1 item context.
  ///
  /// [vaultId] and [itemId] must be non-empty UTF-8, each at most 256 bytes.
  SealContext({
    required String vaultId,
    required String itemId,
    this.purpose = ItemPurpose.item,
  })  : vaultId = _identifier(vaultId, 'vaultId'),
        itemId = _identifier(itemId, 'itemId');

  /// Vault that owns the item.
  final String vaultId;

  /// Stable id of the item inside the vault.
  final String itemId;

  /// What the ciphertext is for.
  final ItemPurpose purpose;

  /// Canonical associated data for this context.
  Uint8List toAad() => encodeItemAad(
        vaultId: vaultId,
        itemId: itemId,
        purposeByte: purpose.byte,
      );
}

/// Context bound into a vault-key wrap.
///
/// [keyGeneration] starts at 1. A later rotation keeps the wrap scheme and
/// uses a new generation. Scheme 2 uses this same context.
final class WrapContext {
  /// Creates a wrap context.
  ///
  /// [vaultId] must be non-empty UTF-8, at most 256 bytes.
  /// [keyGeneration] must be a uint32 greater than or equal to 1.
  WrapContext({required String vaultId, required int keyGeneration})
      : vaultId = _identifier(vaultId, 'vaultId'),
        keyGeneration = _generation(keyGeneration);

  /// Vault whose key is being wrapped.
  final String vaultId;

  /// Monotonic generation of the vault key. Scheme 1 requires a value of at
  /// least 1.
  final int keyGeneration;
}

/// Item associated data:
/// `ascii("vaultseal-item") || u16be(vaultId) || vaultId || u16be(itemId) || itemId || u8(purpose)`.
Uint8List encodeItemAad({
  required String vaultId,
  required String itemId,
  required int purposeByte,
}) {
  final vault = _utf8Id(vaultId, 'vaultId');
  final item = _utf8Id(itemId, 'itemId');
  if (purposeByte < 0 || purposeByte > 255) {
    throw const VaultSealFormatException('purpose must be a single byte.');
  }
  final out = BytesBuilder()
    ..add(utf8.encode('vaultseal-item'))
    ..addByte(vault.length >> 8)
    ..addByte(vault.length & 0xff)
    ..add(vault)
    ..addByte(item.length >> 8)
    ..addByte(item.length & 0xff)
    ..add(item)
    ..addByte(purposeByte);
  return out.toBytes();
}

/// HPKE `info` and `aad` for a wrap. Both inputs are this exact byte string.
///
/// `ascii("vaultseal-wrap") || u32be(keyGeneration) || u16be(vaultId) || vaultId || recipientPublicKey`.
Uint8List encodeWrapAad({
  required String vaultId,
  required int keyGeneration,
  required Uint8List recipientPublicKey,
}) {
  if (recipientPublicKey.length != x25519KeyLength) {
    throw const VaultSealFormatException(
      'Member public key must be 32 bytes.',
    );
  }
  return _encodeWrapLabel(
    vaultId: vaultId,
    keyGeneration: keyGeneration,
    recipientPublicKey: recipientPublicKey,
  );
}

/// Associated data for a scheme-2 hybrid wrap.
///
/// Same layout as [encodeWrapAad]. [recipientPublicKey] is the 1216-byte
/// hybrid public key.
Uint8List encodeHybridWrapAad({
  required String vaultId,
  required int keyGeneration,
  required Uint8List recipientPublicKey,
}) {
  if (recipientPublicKey.length != hybridPublicKeyLength) {
    throw const VaultSealFormatException(
      'Hybrid member public key must be 1216 bytes.',
    );
  }
  return _encodeWrapLabel(
    vaultId: vaultId,
    keyGeneration: keyGeneration,
    recipientPublicKey: recipientPublicKey,
  );
}

Uint8List _encodeWrapLabel({
  required String vaultId,
  required int keyGeneration,
  required Uint8List recipientPublicKey,
}) {
  final vault = _utf8Id(vaultId, 'vaultId');
  final generation = _generation(keyGeneration);
  final out = BytesBuilder()
    ..add(utf8.encode('vaultseal-wrap'))
    ..addByte((generation >> 24) & 0xff)
    ..addByte((generation >> 16) & 0xff)
    ..addByte((generation >> 8) & 0xff)
    ..addByte(generation & 0xff)
    ..addByte(vault.length >> 8)
    ..addByte(vault.length & 0xff)
    ..add(vault)
    ..add(recipientPublicKey);
  return out.toBytes();
}

String _identifier(String value, String name) {
  _utf8Id(value, name);
  return value;
}

Uint8List _utf8Id(String value, String name) {
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
  return bytes;
}

int _generation(int keyGeneration) {
  if (keyGeneration < 1 || keyGeneration > 0xffffffff) {
    throw const VaultSealFormatException(
      'keyGeneration must be a uint32 greater than or equal to 1.',
    );
  }
  return keyGeneration;
}
