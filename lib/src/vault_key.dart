import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'scheme.dart';

/// A 32-byte vault key used directly as an AES-256-GCM key.
///
/// The library does not derive this key from a password. Call [destroy] when
/// the key is no longer needed. Wiping is best-effort: the Dart VM may already
/// have copied the bytes.
final class VaultKey {
  VaultKey._(this._bytes);

  final Uint8List _bytes;
  var _destroyed = false;

  /// Generates a vault key from a CSPRNG.
  static Future<VaultKey> generate() async {
    final secret = await AesGcm.with256bits().newSecretKey();
    final bytes = await secret.extractBytes();
    return VaultKey._(Uint8List.fromList(bytes));
  }

  /// Copies [bytes] into a vault key.
  ///
  /// [bytes] must be exactly 32 bytes. Later changes to the caller's list do
  /// not change the key.
  factory VaultKey.fromBytes(Uint8List bytes) {
    if (bytes.length != vaultKeyLength) {
      throw const VaultSealFormatException('Vault key must be 32 bytes.');
    }
    return VaultKey._(Uint8List.fromList(bytes));
  }

  /// A copy of the raw key.
  ///
  /// Throws [StateError] if [destroy] has been called.
  Uint8List toBytes() {
    _check();
    return Uint8List.fromList(_bytes);
  }

  /// Overwrites the key bytes with zeros.
  ///
  /// This is best-effort. Copies the Dart VM already made are not cleared.
  void destroy() {
    _bytes.fillRange(0, _bytes.length, 0);
    _destroyed = true;
  }

  /// Whether [destroy] has been called.
  bool get isDestroyed => _destroyed;

  void _check() {
    if (_destroyed) {
      throw StateError('VaultKey has been destroyed.');
    }
  }

  /// Returns `VaultKey()`. The text does not contain key bytes.
  @override
  String toString() => 'VaultKey()';
}
