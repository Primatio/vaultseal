import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'scheme.dart';

/// An X25519 public key, stored as 32 raw bytes (RFC 7748).
final class MemberPublicKey {
  MemberPublicKey._(this._bytes);

  final Uint8List _bytes;

  /// Copies a 32-byte X25519 public key.
  ///
  /// Later changes to [bytes] do not change this key.
  factory MemberPublicKey.fromBytes(Uint8List bytes) {
    if (bytes.length != x25519KeyLength) {
      throw const VaultSealFormatException(
        'Member public key must be 32 bytes.',
      );
    }
    return MemberPublicKey._(Uint8List.fromList(bytes));
  }

  /// A copy of the raw public key.
  Uint8List toBytes() => Uint8List.fromList(_bytes);

  /// Returns `MemberPublicKey()`.
  @override
  String toString() => 'MemberPublicKey()';
}

/// An X25519 member key pair.
///
/// Private keys are 32 raw bytes. [fromPrivateKeyBytes] copies the input and
/// stores the clamped RFC 7748 scalar. [destroy] zeroes that copy. Wiping is
/// best-effort: the Dart VM may already have copied the bytes.
final class MemberKeyPair {
  MemberKeyPair._(this._private, this.publicKey);

  final Uint8List _private;
  var _destroyed = false;

  /// Public half of this pair.
  final MemberPublicKey publicKey;

  /// Generates a member key pair from a CSPRNG.
  static Future<MemberKeyPair> generate() async {
    final pair = await X25519().newKeyPair();
    final data = await pair.extract();
    return MemberKeyPair._(
      Uint8List.fromList(data.bytes),
      MemberPublicKey._(Uint8List.fromList(data.publicKey.bytes)),
    );
  }

  /// Restores a key pair from a 32-byte private key.
  ///
  /// The caller's list is copied and is not modified. The stored scalar is
  /// clamped as required by RFC 7748.
  static Future<MemberKeyPair> fromPrivateKeyBytes(Uint8List bytes) async {
    if (bytes.length != x25519KeyLength) {
      throw const VaultSealFormatException(
        'Member private key must be 32 bytes.',
      );
    }
    final pair = await X25519().newKeyPairFromSeed(bytes);
    final data = await pair.extract();
    return MemberKeyPair._(
      Uint8List.fromList(data.bytes),
      MemberPublicKey._(Uint8List.fromList(data.publicKey.bytes)),
    );
  }

  /// A copy of the clamped private key.
  ///
  /// Throws [StateError] if [destroy] has been called.
  Uint8List toPrivateKeyBytes() {
    _check();
    return Uint8List.fromList(_private);
  }

  /// Overwrites the private key with zeros.
  ///
  /// This is best-effort. The public key is left intact.
  void destroy() {
    _private.fillRange(0, _private.length, 0);
    _destroyed = true;
  }

  /// Whether [destroy] has been called.
  bool get isDestroyed => _destroyed;

  void _check() {
    if (_destroyed) {
      throw StateError('MemberKeyPair has been destroyed.');
    }
  }

  /// Returns `MemberKeyPair()`. The text does not contain key bytes.
  @override
  String toString() => 'MemberKeyPair()';
}
