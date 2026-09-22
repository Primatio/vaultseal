import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:pqcrypto/pqcrypto.dart';

import 'scheme.dart';

/// An ML-KEM-768 + X25519 public key.
///
/// Layout: X25519 public key (32) followed by the ML-KEM-768 encapsulation
/// key (1184).
final class HybridMemberPublicKey {
  HybridMemberPublicKey._(this._bytes);

  final Uint8List _bytes;

  /// Copies a 1216-byte hybrid public key.
  ///
  /// Later changes to [bytes] do not change this key.
  factory HybridMemberPublicKey.fromBytes(Uint8List bytes) {
    if (bytes.length != hybridPublicKeyLength) {
      throw const VaultSealFormatException(
        'Hybrid member public key must be 1216 bytes.',
      );
    }
    return HybridMemberPublicKey._(Uint8List.fromList(bytes));
  }

  /// A copy of the raw public key.
  Uint8List toBytes() => Uint8List.fromList(_bytes);

  /// A copy of the X25519 half of this public key.
  Uint8List get x25519PublicKey =>
      Uint8List.fromList(Uint8List.sublistView(_bytes, 0, x25519KeyLength));

  /// A copy of the ML-KEM-768 encapsulation key.
  Uint8List get mlKemPublicKey => Uint8List.fromList(
        Uint8List.sublistView(_bytes, x25519KeyLength),
      );

  /// Returns `HybridMemberPublicKey()`.
  @override
  String toString() => 'HybridMemberPublicKey()';
}

/// An ML-KEM-768 + X25519 member key pair.
///
/// [fromPrivateKeyBytes] copies the input. The stored X25519 scalar is clamped
/// as required by RFC 7748. [destroy] zeroes the private copy. Wiping is
/// best-effort: the Dart VM may already have copied the bytes.
final class HybridMemberKeyPair {
  HybridMemberKeyPair._(this._x25519, this._mlKem, this.publicKey);

  final Uint8List _x25519;
  final Uint8List _mlKem;
  var _destroyed = false;

  /// Public half of this pair.
  final HybridMemberPublicKey publicKey;

  /// Generates a hybrid member key pair from a CSPRNG.
  static Future<HybridMemberKeyPair> generate() async {
    final fresh = await X25519().newKeyPair();
    final seed = Uint8List.fromList((await fresh.extract()).bytes);
    // WebCrypto's extract() can return an unclamped seed. Re-import so the
    // stored scalar matches fromPrivateKeyBytes on every platform.
    final xPair = await X25519().newKeyPairFromSeed(seed);
    final xData = await xPair.extract();
    seed.fillRange(0, seed.length, 0);
    final (mlPublic, mlPrivate) = PqcKem.kyber768.generateKeyPair();
    return HybridMemberKeyPair._(
      Uint8List.fromList(xData.bytes),
      Uint8List.fromList(mlPrivate),
      HybridMemberPublicKey._(
        _join(xData.publicKey.bytes, mlPublic),
      ),
    );
  }

  /// Restores a key pair from a 2432-byte private key.
  ///
  /// The layout is the clamped X25519 scalar (32) followed by the ML-KEM-768
  /// decapsulation key (2400). The caller's list is copied and is not
  /// modified. An unclamped X25519 scalar is clamped before it is stored.
  static Future<HybridMemberKeyPair> fromPrivateKeyBytes(
    Uint8List bytes,
  ) async {
    if (bytes.length != hybridPrivateKeyLength) {
      throw const VaultSealFormatException(
        'Hybrid member private key must be 2432 bytes.',
      );
    }
    final xSeed = Uint8List.sublistView(bytes, 0, x25519KeyLength);
    final mlPrivate = Uint8List.fromList(
      Uint8List.sublistView(bytes, x25519KeyLength),
    );
    _rejectInvalidMlKemPrivateKey(mlPrivate);
    final xPair = await X25519().newKeyPairFromSeed(xSeed);
    final xData = await xPair.extract();
    final mlPublic = Uint8List.sublistView(
      mlPrivate,
      mlKem768PrivateKeyLength - mlKem768PublicKeyLength - 64,
      mlKem768PrivateKeyLength - 64,
    );
    return HybridMemberKeyPair._(
      Uint8List.fromList(xData.bytes),
      mlPrivate,
      HybridMemberPublicKey._(_join(xData.publicKey.bytes, mlPublic)),
    );
  }

  /// A copy of the private key: clamped X25519 scalar, then the ML-KEM-768
  /// decapsulation key.
  ///
  /// Throws [StateError] if [destroy] has been called.
  Uint8List toPrivateKeyBytes() {
    _check();
    return _join(_x25519, _mlKem);
  }

  /// Overwrites both private keys with zeros.
  ///
  /// This is best-effort. The public key is left intact.
  void destroy() {
    _x25519.fillRange(0, _x25519.length, 0);
    _mlKem.fillRange(0, _mlKem.length, 0);
    _destroyed = true;
  }

  /// Whether [destroy] has been called.
  bool get isDestroyed => _destroyed;

  /// X25519 scalar. Throws [StateError] after [destroy].
  Uint8List x25519PrivateKey() {
    _check();
    return Uint8List.fromList(_x25519);
  }

  /// ML-KEM-768 decapsulation key. Throws [StateError] after [destroy].
  Uint8List mlKemPrivateKey() {
    _check();
    return Uint8List.fromList(_mlKem);
  }

  void _check() {
    if (_destroyed) {
      throw StateError('HybridMemberKeyPair has been destroyed.');
    }
  }

  /// Returns `HybridMemberKeyPair()`. The text does not contain key bytes.
  @override
  String toString() => 'HybridMemberKeyPair()';
}

/// FIPS 203 stores the encapsulation key inside the decapsulation key, after
/// the K-PKE secret (`384 * k` bytes) and before `H(ek) || z`.
void _rejectInvalidMlKemPrivateKey(Uint8List privateKey) {
  try {
    final rejected = PqcKem.kyber768.decapsulate(
      privateKey,
      Uint8List(mlKem768CiphertextLength),
    );
    rejected.fillRange(0, rejected.length, 0);
  } on ArgumentError {
    throw const VaultSealFormatException(
      'Hybrid member private key is not a valid ML-KEM-768 key.',
    );
  }
}

Uint8List _join(List<int> first, List<int> second) {
  final out = Uint8List(first.length + second.length);
  out.setAll(0, first);
  out.setAll(first.length, second);
  return out;
}
