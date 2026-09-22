import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';
import 'package:pqcrypto/pqcrypto.dart';

import 'aad.dart';
import 'hybrid_key.dart';
import 'scheme.dart';
import 'vault_key.dart';

/// HKDF info label for the scheme-2 combiner.
const String hybridWrapLabel = 'VaultSeal-Hybrid-Wrap-v2';

/// A scheme-2 wrap of a vault key to one hybrid member.
///
/// Layout:
/// `0x02 || x25519 enc(32) || ML-KEM ciphertext(1088) || nonce(12) || vault key(32) || tag(16)`.
/// The length is always [hybridWrappedVaultKeyLength].
final class HybridWrappedVaultKey {
  HybridWrappedVaultKey._(this._bytes);

  final Uint8List _bytes;

  /// Parses [bytes] as a scheme-2 wrapped vault key.
  ///
  /// The bytes are copied. Any other length, and any version other than 2,
  /// throws [VaultSealFormatException].
  factory HybridWrappedVaultKey.parse(Uint8List bytes) {
    _parseHybridWrappedVaultKey(bytes);
    return HybridWrappedVaultKey._(Uint8List.fromList(bytes));
  }

  /// A copy of the framed bytes.
  Uint8List toBytes() => Uint8List.fromList(_bytes);
}

/// Wraps [vaultKey] to [recipient] with ML-KEM-768 and X25519.
///
/// The two shared secrets are combined with HKDF-SHA256 under
/// [hybridWrapLabel], bound to both ciphertexts and to the recipient public
/// key. AES-256-GCM then encrypts the vault key. The associated data is the
/// wrap label, [context], and the hybrid public key.
///
/// This wrap does not authenticate the sender. The app must bind the blob to
/// an authenticated membership record before trusting it.
Future<HybridWrappedVaultKey> wrapHybridVaultKey({
  required VaultKey vaultKey,
  required HybridMemberPublicKey recipient,
  required WrapContext context,
}) {
  return _wrapHybrid(
    vaultKey: vaultKey,
    recipient: recipient,
    context: context,
    ephemeralPrivateKey: null,
    mlKemCoins: null,
    nonce: null,
  );
}

/// Same as [wrapHybridVaultKey], with fixed ephemeral material for tests.
///
/// Not part of the supported public API.
@visibleForTesting
Future<HybridWrappedVaultKey> wrapHybridVaultKeyForTest({
  required VaultKey vaultKey,
  required HybridMemberPublicKey recipient,
  required WrapContext context,
  required Uint8List ephemeralPrivateKey,
  required Uint8List mlKemCoins,
  required Uint8List nonce,
}) {
  return _wrapHybrid(
    vaultKey: vaultKey,
    recipient: recipient,
    context: context,
    ephemeralPrivateKey: ephemeralPrivateKey,
    mlKemCoins: mlKemCoins,
    nonce: nonce,
  );
}

/// Unwraps [wrapped] with [recipient] and [context].
///
/// A wrong key, a wrong context, or a modified blob all throw
/// [VaultSealAuthenticationException].
Future<VaultKey> unwrapHybridVaultKey({
  required HybridWrappedVaultKey wrapped,
  required HybridMemberKeyPair recipient,
  required WrapContext context,
}) async {
  final parsed = _parseHybridWrappedVaultKey(wrapped.toBytes());
  final publicKey = recipient.publicKey.toBytes();
  final aad = encodeHybridWrapAad(
    vaultId: context.vaultId,
    keyGeneration: context.keyGeneration,
    recipientPublicKey: publicKey,
  );
  final xPrivate = recipient.x25519PrivateKey();
  final mlPrivate = recipient.mlKemPrivateKey();
  Uint8List? xSecret;
  Uint8List? mlSecret;
  Uint8List? aesKey;
  try {
    xSecret = await _x25519SharedSecret(
      privateKey: xPrivate,
      publicKey: Uint8List.sublistView(publicKey, 0, x25519KeyLength),
      remotePublicKey: parsed.x25519Enc,
    );
    mlSecret = _mlKemDecapsulate(mlPrivate, parsed.mlKemCiphertext);
    aesKey = await _hybridWrapKey(
      x25519SharedSecret: xSecret,
      mlKemSharedSecret: mlSecret,
      x25519Enc: parsed.x25519Enc,
      mlKemCiphertext: parsed.mlKemCiphertext,
      recipientPublicKey: publicKey,
    );
    final plaintext = await _openVaultKey(
      key: aesKey,
      nonce: parsed.nonce,
      ciphertext: parsed.ciphertext,
      tag: parsed.tag,
      aad: aad,
    );
    try {
      if (plaintext.length != vaultKeyLength) {
        throw const VaultSealAuthenticationException();
      }
      return VaultKey.fromBytes(plaintext);
    } finally {
      plaintext.fillRange(0, plaintext.length, 0);
    }
  } finally {
    xPrivate.fillRange(0, xPrivate.length, 0);
    mlPrivate.fillRange(0, mlPrivate.length, 0);
    _wipe(xSecret);
    _wipe(mlSecret);
    _wipe(aesKey);
  }
}

/// HKDF-SHA256 combiner. Not part of the supported public API.
@visibleForTesting
Future<Uint8List> hybridWrapKeyForTest({
  required Uint8List x25519SharedSecret,
  required Uint8List mlKemSharedSecret,
  required Uint8List x25519Enc,
  required Uint8List mlKemCiphertext,
  required Uint8List recipientPublicKey,
}) {
  return _hybridWrapKey(
    x25519SharedSecret: x25519SharedSecret,
    mlKemSharedSecret: mlKemSharedSecret,
    x25519Enc: x25519Enc,
    mlKemCiphertext: mlKemCiphertext,
    recipientPublicKey: recipientPublicKey,
  );
}

Future<HybridWrappedVaultKey> _wrapHybrid({
  required VaultKey vaultKey,
  required HybridMemberPublicKey recipient,
  required WrapContext context,
  required Uint8List? ephemeralPrivateKey,
  required Uint8List? mlKemCoins,
  required Uint8List? nonce,
}) async {
  final publicKey = recipient.toBytes();
  final aad = encodeHybridWrapAad(
    vaultId: context.vaultId,
    keyGeneration: context.keyGeneration,
    recipientPublicKey: publicKey,
  );
  final chosenNonce =
      nonce ?? Uint8List.fromList(AesGcm.with256bits().newNonce());
  if (chosenNonce.length != nonceLength) {
    throw const VaultSealFormatException('Nonce must be 12 bytes.');
  }
  if (mlKemCoins != null && mlKemCoins.length != 32) {
    throw const VaultSealFormatException('ML-KEM coins must be 32 bytes.');
  }
  final vaultKeyBytes = vaultKey.toBytes();
  Uint8List? xSecret;
  Uint8List? mlSecret;
  Uint8List? aesKey;
  try {
    final encapsulated = await _x25519Encapsulate(
      remotePublicKey: Uint8List.fromList(
        Uint8List.sublistView(publicKey, 0, x25519KeyLength),
      ),
      ephemeralPrivateKey: ephemeralPrivateKey,
    );
    xSecret = encapsulated.sharedSecret;
    final (mlCiphertext, mlShared) = _mlKemEncapsulate(
      Uint8List.fromList(Uint8List.sublistView(publicKey, x25519KeyLength)),
      mlKemCoins,
    );
    mlSecret = mlShared;
    aesKey = await _hybridWrapKey(
      x25519SharedSecret: xSecret,
      mlKemSharedSecret: mlSecret,
      x25519Enc: encapsulated.enc,
      mlKemCiphertext: mlCiphertext,
      recipientPublicKey: publicKey,
    );
    final box = await AesGcm.with256bits().encrypt(
      vaultKeyBytes,
      secretKey: SecretKey(aesKey),
      nonce: chosenNonce,
      aad: aad,
    );
    return HybridWrappedVaultKey._(
      _frame(
        x25519Enc: encapsulated.enc,
        mlKemCiphertext: mlCiphertext,
        nonce: chosenNonce,
        ciphertext: Uint8List.fromList(box.cipherText),
        tag: Uint8List.fromList(box.mac.bytes),
      ),
    );
  } finally {
    vaultKeyBytes.fillRange(0, vaultKeyBytes.length, 0);
    _wipe(xSecret);
    _wipe(mlSecret);
    _wipe(aesKey);
  }
}

Future<Uint8List> _hybridWrapKey({
  required Uint8List x25519SharedSecret,
  required Uint8List mlKemSharedSecret,
  required Uint8List x25519Enc,
  required Uint8List mlKemCiphertext,
  required Uint8List recipientPublicKey,
}) async {
  if (x25519SharedSecret.length != x25519KeyLength ||
      mlKemSharedSecret.length != 32 ||
      x25519Enc.length != x25519KeyLength ||
      mlKemCiphertext.length != mlKem768CiphertextLength ||
      recipientPublicKey.length != hybridPublicKeyLength) {
    throw const VaultSealFormatException(
        'Hybrid combiner input has a bad length.');
  }
  final ikm = Uint8List(x25519SharedSecret.length + mlKemSharedSecret.length);
  ikm.setAll(0, x25519SharedSecret);
  ikm.setAll(x25519SharedSecret.length, mlKemSharedSecret);
  final info = BytesBuilder()
    ..add(utf8.encode(hybridWrapLabel))
    ..add(x25519Enc)
    ..add(mlKemCiphertext)
    ..add(recipientPublicKey);
  try {
    final prk = await _hkdfExtract(Uint8List(0), ikm);
    try {
      return await _hkdfExpand(prk, info.toBytes(), vaultKeyLength);
    } finally {
      prk.fillRange(0, prk.length, 0);
    }
  } finally {
    ikm.fillRange(0, ikm.length, 0);
  }
}

Future<({Uint8List enc, Uint8List sharedSecret})> _x25519Encapsulate({
  required Uint8List remotePublicKey,
  required Uint8List? ephemeralPrivateKey,
}) async {
  final Uint8List privateBytes;
  final Uint8List publicBytes;
  if (ephemeralPrivateKey == null) {
    final pair = await X25519().newKeyPair();
    final data = await pair.extract();
    privateBytes = Uint8List.fromList(data.bytes);
    publicBytes = Uint8List.fromList(data.publicKey.bytes);
  } else {
    if (ephemeralPrivateKey.length != x25519KeyLength) {
      throw const VaultSealFormatException(
        'X25519 ephemeral private key must be 32 bytes.',
      );
    }
    final pair = await X25519().newKeyPairFromSeed(ephemeralPrivateKey);
    final data = await pair.extract();
    privateBytes = Uint8List.fromList(data.bytes);
    publicBytes = Uint8List.fromList(data.publicKey.bytes);
  }
  try {
    final shared = await _x25519SharedSecret(
      privateKey: privateBytes,
      publicKey: publicBytes,
      remotePublicKey: remotePublicKey,
    );
    return (enc: publicBytes, sharedSecret: shared);
  } finally {
    privateBytes.fillRange(0, privateBytes.length, 0);
  }
}

Future<Uint8List> _x25519SharedSecret({
  required Uint8List privateKey,
  required Uint8List publicKey,
  required Uint8List remotePublicKey,
}) async {
  try {
    final shared = await X25519().sharedSecretKey(
      keyPair: SimpleKeyPairData(
        privateKey,
        publicKey: SimplePublicKey(publicKey, type: KeyPairType.x25519),
        type: KeyPairType.x25519,
      ),
      remotePublicKey: SimplePublicKey(
        remotePublicKey,
        type: KeyPairType.x25519,
      ),
    );
    final bytes = Uint8List.fromList(await shared.extractBytes());
    if (_allZero(bytes)) {
      bytes.fillRange(0, bytes.length, 0);
      throw const VaultSealAuthenticationException();
    }
    return bytes;
  } on ArgumentError {
    throw const VaultSealAuthenticationException();
  } on StateError {
    throw const VaultSealAuthenticationException();
  } on UnsupportedError {
    throw const VaultSealAuthenticationException();
  }
}

(Uint8List, Uint8List) _mlKemEncapsulate(
    Uint8List publicKey, Uint8List? coins) {
  try {
    final (ciphertext, shared) = PqcKem.kyber768.encapsulate(publicKey, coins);
    return (Uint8List.fromList(ciphertext), Uint8List.fromList(shared));
  } on ArgumentError {
    throw const VaultSealAuthenticationException();
  }
}

Uint8List _mlKemDecapsulate(Uint8List privateKey, Uint8List ciphertext) {
  try {
    return Uint8List.fromList(
      PqcKem.kyber768.decapsulate(privateKey, ciphertext),
    );
  } on ArgumentError {
    throw const VaultSealAuthenticationException();
  }
}

Future<Uint8List> _openVaultKey({
  required Uint8List key,
  required Uint8List nonce,
  required Uint8List ciphertext,
  required Uint8List tag,
  required Uint8List aad,
}) async {
  final box = SecretBox(ciphertext, nonce: nonce, mac: Mac(tag));
  try {
    final clear = await AesGcm.with256bits().decrypt(
      box,
      secretKey: SecretKey(key),
      aad: aad,
    );
    return Uint8List.fromList(clear);
  } on SecretBoxAuthenticationError {
    throw const VaultSealAuthenticationException();
  }
}

Uint8List _frame({
  required Uint8List x25519Enc,
  required Uint8List mlKemCiphertext,
  required Uint8List nonce,
  required Uint8List ciphertext,
  required Uint8List tag,
}) {
  if (x25519Enc.length != x25519KeyLength ||
      mlKemCiphertext.length != mlKem768CiphertextLength ||
      nonce.length != nonceLength ||
      ciphertext.length != vaultKeyLength ||
      tag.length != tagLength) {
    throw StateError('Hybrid wrapped vault key frame is invalid.');
  }
  final out = Uint8List(hybridWrappedVaultKeyLength);
  var offset = 0;
  out[offset++] = hybridWrapScheme;
  out.setAll(offset, x25519Enc);
  offset += x25519Enc.length;
  out.setAll(offset, mlKemCiphertext);
  offset += mlKemCiphertext.length;
  out.setAll(offset, nonce);
  offset += nonce.length;
  out.setAll(offset, ciphertext);
  offset += ciphertext.length;
  out.setAll(offset, tag);
  return out;
}

({
  Uint8List x25519Enc,
  Uint8List mlKemCiphertext,
  Uint8List nonce,
  Uint8List ciphertext,
  Uint8List tag,
}) _parseHybridWrappedVaultKey(Uint8List bytes) {
  if (bytes.length != hybridWrappedVaultKeyLength) {
    throw const VaultSealFormatException(
      'Hybrid wrapped vault key must be 1181 bytes.',
    );
  }
  if (bytes[0] != hybridWrapScheme) {
    throw const VaultSealFormatException(
      'Hybrid wrapped vault key version is not 2.',
    );
  }
  var offset = 1;
  final x25519Enc = Uint8List.fromList(
    Uint8List.sublistView(bytes, offset, offset + x25519KeyLength),
  );
  offset += x25519KeyLength;
  final mlKemCiphertext = Uint8List.fromList(
    Uint8List.sublistView(bytes, offset, offset + mlKem768CiphertextLength),
  );
  offset += mlKem768CiphertextLength;
  final nonce = Uint8List.fromList(
    Uint8List.sublistView(bytes, offset, offset + nonceLength),
  );
  offset += nonceLength;
  final ciphertext = Uint8List.fromList(
    Uint8List.sublistView(bytes, offset, offset + vaultKeyLength),
  );
  offset += vaultKeyLength;
  final tag = Uint8List.fromList(Uint8List.sublistView(bytes, offset));
  return (
    x25519Enc: x25519Enc,
    mlKemCiphertext: mlKemCiphertext,
    nonce: nonce,
    ciphertext: ciphertext,
    tag: tag,
  );
}

/// HKDF-Extract (RFC 5869). An empty salt is HashLen zero bytes.
Future<Uint8List> _hkdfExtract(Uint8List salt, Uint8List ikm) async {
  final effectiveSalt = salt.isEmpty ? Uint8List(32) : salt;
  final mac = await Hmac.sha256().calculateMac(
    ikm,
    secretKey: SecretKey(effectiveSalt),
  );
  return Uint8List.fromList(mac.bytes);
}

/// HKDF-Expand (RFC 5869).
Future<Uint8List> _hkdfExpand(Uint8List prk, Uint8List info, int length) async {
  const hashLength = 32;
  final blocks = (length + hashLength - 1) ~/ hashLength;
  final hmac = Hmac.sha256();
  final out = BytesBuilder();
  var previous = Uint8List(0);
  for (var i = 1; i <= blocks; i++) {
    final input = Uint8List(previous.length + info.length + 1);
    input.setAll(0, previous);
    input.setAll(previous.length, info);
    input[previous.length + info.length] = i;
    final mac = await hmac.calculateMac(input, secretKey: SecretKey(prk));
    previous = Uint8List.fromList(mac.bytes);
    out.add(previous);
  }
  final bytes = out.toBytes();
  return Uint8List.fromList(bytes.sublist(0, length));
}

void _wipe(Uint8List? bytes) {
  if (bytes == null) return;
  bytes.fillRange(0, bytes.length, 0);
}

bool _allZero(Uint8List bytes) {
  for (final byte in bytes) {
    if (byte != 0) return false;
  }
  return true;
}
