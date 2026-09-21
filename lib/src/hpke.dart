import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';

import 'scheme.dart';

/// HPKE Base single-shot result: `enc || ciphertext`.
final class HpkeSealed {
  /// Creates a sealed HPKE message.
  HpkeSealed({required this.enc, required this.ciphertext});

  /// Encapsulated ephemeral public key (32 bytes for X25519).
  final Uint8List enc;

  /// AEAD ciphertext including the tag. The nonce is not included.
  final Uint8List ciphertext;
}

/// One HPKE encryption under a base-mode context.
///
/// Sequence numbers start at 0. Scheme-1 wraps call [seal] once.
final class HpkeContext {
  HpkeContext({
    required this.enc,
    required this.sharedSecret,
    required this.key,
    required this.baseNonce,
    required this.exporterSecret,
    required AesGcm aead,
  }) : _aead = aead;

  /// Encapsulated key from [Encap].
  final Uint8List enc;

  /// KEM shared secret (`Nsecret` bytes).
  final Uint8List sharedSecret;

  /// AEAD key.
  final Uint8List key;

  /// Base nonce. The message nonce is `baseNonce` XOR the sequence number.
  final Uint8List baseNonce;

  /// Exporter secret. Scheme 1 does not export from it.
  final Uint8List exporterSecret;

  final AesGcm _aead;
  var _seq = 0;

  /// Encrypts [plaintext] and increments the sequence number.
  Future<Uint8List> seal(Uint8List plaintext, Uint8List aad) {
    return _crypt(plaintext, aad, encrypting: true);
  }

  /// Decrypts [ciphertext] and increments the sequence number.
  Future<Uint8List> open(Uint8List ciphertext, Uint8List aad) {
    return _crypt(ciphertext, aad, encrypting: false);
  }

  Future<Uint8List> _crypt(
    Uint8List input,
    Uint8List aad, {
    required bool encrypting,
  }) async {
    final nonce = _nonceFor(_seq);
    _seq += 1;
    if (encrypting) {
      final box = await _aead.encrypt(
        input,
        secretKey: SecretKey(key),
        nonce: nonce,
        aad: aad,
      );
      final out = Uint8List(box.cipherText.length + box.mac.bytes.length);
      out.setAll(0, box.cipherText);
      out.setAll(box.cipherText.length, box.mac.bytes);
      return out;
    }
    if (input.length < tagLength) {
      throw const VaultSealAuthenticationException();
    }
    final split = input.length - tagLength;
    final box = SecretBox(
      Uint8List.sublistView(input, 0, split),
      nonce: nonce,
      mac: Mac(Uint8List.sublistView(input, split)),
    );
    try {
      final clear = await _aead.decrypt(
        box,
        secretKey: SecretKey(key),
        aad: aad,
      );
      return Uint8List.fromList(clear);
    } on SecretBoxAuthenticationError {
      throw const VaultSealAuthenticationException();
    }
  }

  Uint8List _nonceFor(int seq) {
    final out = Uint8List.fromList(baseNonce);
    var value = seq;
    for (var i = out.length - 1; i >= 0 && value > 0; i--) {
      out[i] ^= value & 0xff;
      value >>= 8;
    }
    if (value != 0) {
      throw const VaultSealAuthenticationException();
    }
    return out;
  }
}

final _hpkeVersion = utf8.encode('HPKE-v1');

/// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and one AES-GCM AEAD.
enum HpkeAead {
  /// AES-128-GCM, AEAD id `0x0001`. Used for RFC 9180 Appendix A.1.
  aes128Gcm(1, 16),

  /// AES-256-GCM, AEAD id `0x0002`. Scheme 1 wraps use this.
  aes256Gcm(2, 32);

  const HpkeAead(this.id, this.nk);

  /// RFC 9180 AEAD identifier.
  final int id;

  /// AEAD key length in bytes.
  final int nk;

  AesGcm get _cipher => id == 1 ? AesGcm.with128bits() : AesGcm.with256bits();
}

/// KEM id for DHKEM(X25519, HKDF-SHA256).
const int hpkeKemX25519 = 0x0020;

/// KDF id for HKDF-SHA256.
const int hpkeKdfSha256 = 0x0001;

/// Sender setup for HPKE Base mode (RFC 9180 sections 4, 5.1, and 7.1).
@visibleForTesting
Future<HpkeContext> hpkeSetupBaseSender({
  required Uint8List recipientPublicKey,
  required Uint8List info,
  Uint8List? ephemeralPrivateKey,
  HpkeAead aead = HpkeAead.aes256Gcm,
}) async {
  final encapsulated = await _encap(
    recipientPublicKey: recipientPublicKey,
    ephemeralPrivateKey: ephemeralPrivateKey,
  );
  return _keySchedule(
    sharedSecret: encapsulated.sharedSecret,
    enc: encapsulated.enc,
    info: info,
    aead: aead,
  );
}

/// Recipient setup for HPKE Base mode.
@visibleForTesting
Future<HpkeContext> hpkeSetupBaseRecipient({
  required Uint8List enc,
  required Uint8List recipientPrivateKey,
  required Uint8List info,
  HpkeAead aead = HpkeAead.aes256Gcm,
}) async {
  final sharedSecret = await _decap(
    enc: enc,
    recipientPrivateKey: recipientPrivateKey,
  );
  return _keySchedule(
    sharedSecret: sharedSecret,
    enc: enc,
    info: info,
    aead: aead,
  );
}

/// Single-shot Base [Seal]: returns `enc` and `ciphertext || tag`.
Future<HpkeSealed> hpkeSealBase({
  required Uint8List recipientPublicKey,
  required Uint8List info,
  required Uint8List aad,
  required Uint8List plaintext,
  Uint8List? ephemeralPrivateKey,
  HpkeAead aead = HpkeAead.aes256Gcm,
}) async {
  final context = await hpkeSetupBaseSender(
    recipientPublicKey: recipientPublicKey,
    info: info,
    ephemeralPrivateKey: ephemeralPrivateKey,
    aead: aead,
  );
  final ciphertext = await context.seal(plaintext, aad);
  return HpkeSealed(enc: context.enc, ciphertext: ciphertext);
}

/// Single-shot Base [Open].
Future<Uint8List> hpkeOpenBase({
  required Uint8List enc,
  required Uint8List ciphertext,
  required Uint8List recipientPrivateKey,
  required Uint8List info,
  required Uint8List aad,
  HpkeAead aead = HpkeAead.aes256Gcm,
}) async {
  final context = await hpkeSetupBaseRecipient(
    enc: enc,
    recipientPrivateKey: recipientPrivateKey,
    info: info,
    aead: aead,
  );
  return context.open(ciphertext, aad);
}

Future<({Uint8List sharedSecret, Uint8List enc})> _encap({
  required Uint8List recipientPublicKey,
  Uint8List? ephemeralPrivateKey,
}) async {
  final pair = await _keyPair(ephemeralPrivateKey);
  final data = await pair.extract();
  final enc = Uint8List.fromList(data.publicKey.bytes);
  final dh = await _dh(pair, recipientPublicKey);
  final sharedSecret =
      await _extractAndExpand(dh, _kemContext(enc, recipientPublicKey));
  dh.fillRange(0, dh.length, 0);
  return (sharedSecret: sharedSecret, enc: enc);
}

Future<Uint8List> _decap({
  required Uint8List enc,
  required Uint8List recipientPrivateKey,
}) async {
  if (enc.length != x25519KeyLength ||
      recipientPrivateKey.length != x25519KeyLength) {
    throw const VaultSealAuthenticationException();
  }
  final pair = await _keyPair(recipientPrivateKey);
  final data = await pair.extract();
  final pkR = Uint8List.fromList(data.publicKey.bytes);
  final dh = await _dh(pair, enc);
  final sharedSecret = await _extractAndExpand(dh, _kemContext(enc, pkR));
  dh.fillRange(0, dh.length, 0);
  return sharedSecret;
}

Future<SimpleKeyPair> _keyPair(Uint8List? privateKey) {
  final x25519 = X25519();
  if (privateKey == null) {
    return x25519.newKeyPair();
  }
  if (privateKey.length != x25519KeyLength) {
    throw const VaultSealFormatException(
      'X25519 private key must be 32 bytes.',
    );
  }
  return x25519.newKeyPairFromSeed(privateKey);
}

Future<Uint8List> _dh(KeyPair pair, List<int> remotePublic) async {
  if (remotePublic.length != x25519KeyLength) {
    throw const VaultSealAuthenticationException();
  }
  try {
    final secret = await X25519().sharedSecretKey(
      keyPair: pair,
      remotePublicKey: SimplePublicKey(
        remotePublic,
        type: KeyPairType.x25519,
      ),
    );
    final bytes = Uint8List.fromList(await secret.extractBytes());
    if (_allZero(bytes)) {
      throw const VaultSealAuthenticationException();
    }
    return bytes;
  } on ArgumentError {
    throw const VaultSealAuthenticationException();
  } on StateError {
    // WebCrypto rejects a low-order X25519 public key with OperationError.
    throw const VaultSealAuthenticationException();
  } on UnsupportedError {
    throw const VaultSealAuthenticationException();
  }
}

Uint8List _kemContext(Uint8List enc, Uint8List pkR) {
  return Uint8List(enc.length + pkR.length)
    ..setAll(0, enc)
    ..setAll(enc.length, pkR);
}

Future<Uint8List> _extractAndExpand(Uint8List dh, Uint8List kemContext) async {
  final suiteId = _kemSuiteId(hpkeKemX25519);
  final prk = await _labeledExtract(
    suiteId: suiteId,
    salt: Uint8List(0),
    label: 'eae_prk',
    ikm: dh,
  );
  final shared = await _labeledExpand(
    suiteId: suiteId,
    prk: prk,
    label: 'shared_secret',
    info: kemContext,
    length: 32,
  );
  prk.fillRange(0, prk.length, 0);
  return shared;
}

Future<HpkeContext> _keySchedule({
  required Uint8List sharedSecret,
  required Uint8List enc,
  required Uint8List info,
  required HpkeAead aead,
}) async {
  final suiteId = _hpkeSuiteId(aead.id);
  final empty = Uint8List(0);
  final pskIdHash = await _labeledExtract(
    suiteId: suiteId,
    salt: empty,
    label: 'psk_id_hash',
    ikm: empty,
  );
  final infoHash = await _labeledExtract(
    suiteId: suiteId,
    salt: empty,
    label: 'info_hash',
    ikm: info,
  );
  final schedule = BytesBuilder()
    ..addByte(0)
    ..add(pskIdHash)
    ..add(infoHash);
  final scheduleContext = schedule.toBytes();
  final secret = await _labeledExtract(
    suiteId: suiteId,
    salt: sharedSecret,
    label: 'secret',
    ikm: empty,
  );
  final key = await _labeledExpand(
    suiteId: suiteId,
    prk: secret,
    label: 'key',
    info: scheduleContext,
    length: aead.nk,
  );
  final baseNonce = await _labeledExpand(
    suiteId: suiteId,
    prk: secret,
    label: 'base_nonce',
    info: scheduleContext,
    length: 12,
  );
  final exporterSecret = await _labeledExpand(
    suiteId: suiteId,
    prk: secret,
    label: 'exp',
    info: scheduleContext,
    length: 32,
  );
  secret.fillRange(0, secret.length, 0);
  return HpkeContext(
    enc: enc,
    sharedSecret: sharedSecret,
    key: key,
    baseNonce: baseNonce,
    exporterSecret: exporterSecret,
    aead: aead._cipher,
  );
}

Uint8List _kemSuiteId(int kemId) {
  return Uint8List.fromList([
    0x4b, 0x45, 0x4d, // "KEM"
    (kemId >> 8) & 0xff,
    kemId & 0xff,
  ]);
}

Uint8List _hpkeSuiteId(int aeadId) {
  return Uint8List.fromList([
    0x48, 0x50, 0x4b, 0x45, // "HPKE"
    (hpkeKemX25519 >> 8) & 0xff,
    hpkeKemX25519 & 0xff,
    (hpkeKdfSha256 >> 8) & 0xff,
    hpkeKdfSha256 & 0xff,
    (aeadId >> 8) & 0xff,
    aeadId & 0xff,
  ]);
}

Future<Uint8List> _labeledExtract({
  required Uint8List suiteId,
  required Uint8List salt,
  required String label,
  required Uint8List ikm,
}) {
  final labeledIkm = BytesBuilder()
    ..add(_hpkeVersion)
    ..add(suiteId)
    ..add(utf8.encode(label))
    ..add(ikm);
  return _hkdfExtract(salt, labeledIkm.toBytes());
}

Future<Uint8List> _labeledExpand({
  required Uint8List suiteId,
  required Uint8List prk,
  required String label,
  required Uint8List info,
  required int length,
}) {
  final labeledInfo = BytesBuilder()
    ..addByte((length >> 8) & 0xff)
    ..addByte(length & 0xff)
    ..add(_hpkeVersion)
    ..add(suiteId)
    ..add(utf8.encode(label))
    ..add(info);
  return _hkdfExpand(prk, labeledInfo.toBytes(), length);
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
  if (blocks > 255) {
    throw StateError('HKDF-Expand length is too large.');
  }
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

bool _allZero(Uint8List bytes) {
  for (final byte in bytes) {
    if (byte != 0) return false;
  }
  return true;
}
