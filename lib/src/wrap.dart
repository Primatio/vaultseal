import 'dart:typed_data';

import 'package:meta/meta.dart';

import 'aad.dart';
import 'framing.dart';
import 'hpke.dart';
import 'member_key.dart';
import 'scheme.dart';
import 'vault_key.dart';

/// A scheme-1 wrap of a vault key to one member.
///
/// Layout: `0x01 || enc(32) || ciphertext(48)`. The length is always
/// [wrappedVaultKeyLength].
final class WrappedVaultKey {
  WrappedVaultKey._(this._bytes);

  final Uint8List _bytes;

  /// Parses [bytes] as a scheme-1 wrapped vault key.
  ///
  /// The bytes are copied. Any length other than 81, and any version other
  /// than 1, throws [VaultSealFormatException].
  factory WrappedVaultKey.parse(Uint8List bytes) {
    parseWrappedVaultKey(bytes);
    return WrappedVaultKey._(Uint8List.fromList(bytes));
  }

  /// A copy of the framed bytes.
  Uint8List toBytes() => Uint8List.fromList(_bytes);
}

/// Wraps [vaultKey] to [recipient] with HPKE Base single-shot.
///
/// The HPKE `info` and `aad` are the same bytes: the wrap label, [context],
/// and the recipient public key. HPKE Base does not authenticate the sender.
/// The app must bind the resulting blob to an authenticated membership record
/// before trusting it.
Future<WrappedVaultKey> wrapVaultKey({
  required VaultKey vaultKey,
  required MemberPublicKey recipient,
  required WrapContext context,
}) {
  return _wrap(
    vaultKey: vaultKey,
    recipient: recipient,
    context: context,
    ephemeralPrivateKey: null,
  );
}

/// Same as [wrapVaultKey], with a fixed ephemeral private key for tests.
///
/// Not part of the supported public API.
@visibleForTesting
Future<WrappedVaultKey> wrapVaultKeyForTest({
  required VaultKey vaultKey,
  required MemberPublicKey recipient,
  required WrapContext context,
  required Uint8List ephemeralPrivateKey,
}) {
  return _wrap(
    vaultKey: vaultKey,
    recipient: recipient,
    context: context,
    ephemeralPrivateKey: ephemeralPrivateKey,
  );
}

/// Unwraps [wrapped] with [recipient] and [context].
///
/// A wrong key, a wrong context, or a modified blob all throw
/// [VaultSealAuthenticationException].
Future<VaultKey> unwrapVaultKey({
  required WrappedVaultKey wrapped,
  required MemberKeyPair recipient,
  required WrapContext context,
}) async {
  final parsed = parseWrappedVaultKey(wrapped.toBytes());
  final aad = encodeWrapAad(
    vaultId: context.vaultId,
    keyGeneration: context.keyGeneration,
    recipientPublicKey: recipient.publicKey.toBytes(),
  );
  final privateKey = recipient.toPrivateKeyBytes();
  try {
    final plaintext = await hpkeOpenBase(
      enc: Uint8List.fromList(parsed.enc),
      ciphertext: Uint8List.fromList(parsed.ciphertext),
      recipientPrivateKey: privateKey,
      info: aad,
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
    privateKey.fillRange(0, privateKey.length, 0);
  }
}

Future<WrappedVaultKey> _wrap({
  required VaultKey vaultKey,
  required MemberPublicKey recipient,
  required WrapContext context,
  required Uint8List? ephemeralPrivateKey,
}) async {
  final publicKey = recipient.toBytes();
  final aad = encodeWrapAad(
    vaultId: context.vaultId,
    keyGeneration: context.keyGeneration,
    recipientPublicKey: publicKey,
  );
  final vaultKeyBytes = vaultKey.toBytes();
  try {
    final sealed = await hpkeSealBase(
      recipientPublicKey: publicKey,
      info: aad,
      aad: aad,
      plaintext: vaultKeyBytes,
      ephemeralPrivateKey: ephemeralPrivateKey,
    );
    return WrappedVaultKey._(
      frameWrappedVaultKey(enc: sealed.enc, ciphertext: sealed.ciphertext),
    );
  } finally {
    vaultKeyBytes.fillRange(0, vaultKeyBytes.length, 0);
  }
}
