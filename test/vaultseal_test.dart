import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';
import 'package:vaultseal/src/hpke.dart';
import 'package:vaultseal/src/item.dart';
import 'package:vaultseal/src/wrap.dart';
import 'package:vaultseal/vaultseal.dart';

import 'hex.dart';
import 'known_vectors.dart';

void main() {
  group('known answers', () {
    test('NIST CAVP AES-256-GCM empty message', () async {
      final box = await AesGcm.with256bits().encrypt(
        Uint8List(0),
        secretKey: SecretKey(decodeHex(nistKey)),
        nonce: decodeHex(nistNonce),
      );
      expect(box.cipherText, isEmpty);
      expect(encodeHex(box.mac.bytes), nistTag);
    });

    test('pyhpke suite seals a vault key', () async {
      final info = decodeHex(pyhpkeInfo);
      final sealed = await hpkeSealBase(
        recipientPublicKey: decodeHex(pyhpkeRecipientPublic),
        info: info,
        aad: info,
        plaintext: decodeHex(pyhpkeVaultKey),
        ephemeralPrivateKey: decodeHex(pyhpkeEphemeralPrivate),
      );
      expect(encodeHex(sealed.enc), pyhpkeEnc);
      expect(encodeHex(sealed.ciphertext), pyhpkeCiphertext);

      final opened = await hpkeOpenBase(
        enc: sealed.enc,
        ciphertext: sealed.ciphertext,
        recipientPrivateKey: decodeHex(pyhpkeRecipientPrivate),
        info: info,
        aad: info,
      );
      expect(encodeHex(opened), pyhpkeVaultKey);
    });

    test('wrapVaultKeyForTest matches the pyhpke blob', () async {
      final recipient =
          MemberPublicKey.fromBytes(decodeHex(pyhpkeRecipientPublic));
      final wrapped = await wrapVaultKeyForTest(
        vaultKey: VaultKey.fromBytes(decodeHex(pyhpkeVaultKey)),
        recipient: recipient,
        context: WrapContext(vaultId: 'vault-1', keyGeneration: 1),
        ephemeralPrivateKey: decodeHex(pyhpkeEphemeralPrivate),
      );
      expect(encodeHex(wrapped.toBytes()), pyhpkeWrapped);
      expect(wrapped.toBytes(), hasLength(wrappedVaultKeyLength));

      final member = await MemberKeyPair.fromPrivateKeyBytes(
        decodeHex(pyhpkeRecipientPrivate),
      );
      final unwrapped = await unwrapVaultKey(
        wrapped: wrapped,
        recipient: member,
        context: WrapContext(vaultId: 'vault-1', keyGeneration: 1),
      );
      expect(encodeHex(unwrapped.toBytes()), pyhpkeVaultKey);
    });

    test('sealItemForTest matches the Python AES-GCM frame', () async {
      final context = SealContext(vaultId: 'vault-1', itemId: 'item-1');
      expect(encodeHex(context.toAad()), itemAad);
      final sealed = await sealItemForTest(
        plaintext: decodeHex(itemPlaintext),
        vaultKey: VaultKey.fromBytes(decodeHex(itemVaultKey)),
        context: context,
        nonce: decodeHex(itemNonce),
      );
      expect(encodeHex(sealed.toBytes()), itemSealed);
      final opened = await openItem(
        sealed: sealed,
        vaultKey: VaultKey.fromBytes(decodeHex(itemVaultKey)),
        context: context,
      );
      expect(encodeHex(opened), itemPlaintext);
    });
  });

  group('round trip', () {
    test('seals empty and non-UTF-8 plaintext', () async {
      final key = await VaultKey.generate();
      final context = SealContext(vaultId: 'v', itemId: 'i');
      for (final plaintext in [
        Uint8List(0),
        Uint8List.fromList([0xff, 0xfe, 0x00, 0x80]),
      ]) {
        final sealed = await sealItem(
          plaintext: plaintext,
          vaultKey: key,
          context: context,
        );
        final opened = await openItem(
          sealed: sealed,
          vaultKey: key,
          context: context,
        );
        expect(opened, plaintext);
      }
    });

    test('two seals of the same plaintext differ', () async {
      final key = await VaultKey.generate();
      final context = SealContext(vaultId: 'v', itemId: 'i');
      final plaintext = Uint8List.fromList([1, 2, 3]);
      final first = await sealItem(
        plaintext: plaintext,
        vaultKey: key,
        context: context,
      );
      final second = await sealItem(
        plaintext: plaintext,
        vaultKey: key,
        context: context,
      );
      expect(first.toBytes(), isNot(second.toBytes()));
    });

    test('wraps one vault key to two recipients', () async {
      final vaultKey = await VaultKey.generate();
      final alice = await MemberKeyPair.generate();
      final bob = await MemberKeyPair.generate();
      final context = WrapContext(vaultId: 'vault', keyGeneration: 1);
      final toAlice = await wrapVaultKey(
        vaultKey: vaultKey,
        recipient: alice.publicKey,
        context: context,
      );
      final toBob = await wrapVaultKey(
        vaultKey: vaultKey,
        recipient: bob.publicKey,
        context: context,
      );
      expect(toAlice.toBytes(), isNot(toBob.toBytes()));
      final openedAlice = await unwrapVaultKey(
        wrapped: toAlice,
        recipient: alice,
        context: context,
      );
      final openedBob = await unwrapVaultKey(
        wrapped: toBob,
        recipient: bob,
        context: context,
      );
      expect(openedAlice.toBytes(), vaultKey.toBytes());
      expect(openedBob.toBytes(), vaultKey.toBytes());
      expect(
        () =>
            unwrapVaultKey(wrapped: toAlice, recipient: bob, context: context),
        throwsA(isA<VaultSealAuthenticationException>()),
      );
    });

    test('100 random plaintexts round-trip', () async {
      final random = Random(1);
      final key = await VaultKey.generate();
      final context = SealContext(vaultId: 'vault-é', itemId: 'item');
      for (var i = 0; i < 100; i++) {
        final length = random.nextInt(128);
        final plaintext = Uint8List.fromList(
          List<int>.generate(length, (_) => random.nextInt(256)),
        );
        final sealed = await sealItem(
          plaintext: plaintext,
          vaultKey: key,
          context: context,
        );
        final opened = await openItem(
          sealed: sealed,
          vaultKey: key,
          context: context,
        );
        expect(opened, plaintext);
      }
    });
  });

  group('rejection', () {
    test('swapped item context fails authentication', () async {
      final key = await VaultKey.generate();
      final sealed = await sealItem(
        plaintext: Uint8List.fromList([7, 8, 9]),
        vaultKey: key,
        context: SealContext(vaultId: 'vault-a', itemId: 'item-a'),
      );
      Future<void> expectAuth(SealContext context) {
        return expectLater(
          openItem(sealed: sealed, vaultKey: key, context: context),
          throwsA(isA<VaultSealAuthenticationException>()),
        );
      }

      await expectAuth(SealContext(vaultId: 'vault-b', itemId: 'item-a'));
      await expectAuth(SealContext(vaultId: 'vault-a', itemId: 'item-b'));
      await expectLater(
        openItemForTest(
          sealed: sealed,
          vaultKey: key,
          context: SealContext(vaultId: 'vault-a', itemId: 'item-a'),
          purposeByte: 2,
        ),
        throwsA(isA<VaultSealAuthenticationException>()),
      );
      final otherKey = await VaultKey.generate();
      await expectLater(
        openItem(
          sealed: sealed,
          vaultKey: otherKey,
          context: SealContext(vaultId: 'vault-a', itemId: 'item-a'),
        ),
        throwsA(isA<VaultSealAuthenticationException>()),
      );
    });

    test('swapped wrap context fails authentication', () async {
      final vaultKey = await VaultKey.generate();
      final member = await MemberKeyPair.generate();
      final wrapped = await wrapVaultKey(
        vaultKey: vaultKey,
        recipient: member.publicKey,
        context: WrapContext(vaultId: 'vault-a', keyGeneration: 1),
      );
      await expectLater(
        unwrapVaultKey(
          wrapped: wrapped,
          recipient: member,
          context: WrapContext(vaultId: 'vault-b', keyGeneration: 1),
        ),
        throwsA(isA<VaultSealAuthenticationException>()),
      );
      await expectLater(
        unwrapVaultKey(
          wrapped: wrapped,
          recipient: member,
          context: WrapContext(vaultId: 'vault-a', keyGeneration: 2),
        ),
        throwsA(isA<VaultSealAuthenticationException>()),
      );
    });

    test('bit flips and bad versions are rejected', () async {
      final key = VaultKey.fromBytes(decodeHex(itemVaultKey));
      final context = SealContext(vaultId: 'vault-1', itemId: 'item-1');
      final sealed = await sealItemForTest(
        plaintext: decodeHex(itemPlaintext),
        vaultKey: key,
        context: context,
        nonce: decodeHex(itemNonce),
      );
      final bytes = sealed.toBytes();
      for (final index in [1, 13, bytes.length - 1]) {
        final flipped = Uint8List.fromList(bytes)..[index] ^= 0x01;
        final parsed = SealedItem.parse(flipped);
        await expectLater(
          openItem(sealed: parsed, vaultKey: key, context: context),
          throwsA(isA<VaultSealAuthenticationException>()),
        );
      }
      expect(
        () => SealedItem.parse(Uint8List.fromList(bytes)..[0] = 0),
        throwsA(isA<VaultSealFormatException>()),
      );
      expect(
        () => SealedItem.parse(Uint8List.fromList(bytes)..[0] = 2),
        throwsA(isA<VaultSealFormatException>()),
      );
      expect(
        () => SealedItem.parse(Uint8List(28)),
        throwsA(isA<VaultSealFormatException>()),
      );

      final wrapped = await wrapVaultKeyForTest(
        vaultKey: VaultKey.fromBytes(decodeHex(pyhpkeVaultKey)),
        recipient: MemberPublicKey.fromBytes(decodeHex(pyhpkeRecipientPublic)),
        context: WrapContext(vaultId: 'vault-1', keyGeneration: 1),
        ephemeralPrivateKey: decodeHex(pyhpkeEphemeralPrivate),
      );
      final member = await MemberKeyPair.fromPrivateKeyBytes(
        decodeHex(pyhpkeRecipientPrivate),
      );
      final wrapContext = WrapContext(vaultId: 'vault-1', keyGeneration: 1);
      final wrapBytes = wrapped.toBytes();
      for (final index in [1, 33, wrapBytes.length - 1]) {
        final flipped = Uint8List.fromList(wrapBytes)..[index] ^= 0x01;
        final parsed = WrappedVaultKey.parse(flipped);
        await expectLater(
          unwrapVaultKey(
              wrapped: parsed, recipient: member, context: wrapContext),
          throwsA(isA<VaultSealAuthenticationException>()),
        );
      }
      expect(
        () => WrappedVaultKey.parse(Uint8List(81)),
        throwsA(isA<VaultSealFormatException>()),
      );
      expect(
        () => WrappedVaultKey.parse(Uint8List.fromList(wrapBytes)..[0] = 2),
        throwsA(isA<VaultSealFormatException>()),
      );
      expect(
        () => WrappedVaultKey.parse(Uint8List(80)),
        throwsA(isA<VaultSealFormatException>()),
      );
      expect(
        () => WrappedVaultKey.parse(Uint8List(82)),
        throwsA(isA<VaultSealFormatException>()),
      );
    });

    test('rejects oversized plaintext, bad ids, and short keys', () async {
      final key = await VaultKey.generate();
      expect(
        () => sealItem(
          plaintext: Uint8List(maxPlaintextLength + 1),
          vaultKey: key,
          context: SealContext(vaultId: 'v', itemId: 'i'),
        ),
        throwsA(isA<VaultSealFormatException>()),
      );
      expect(
        () => SealContext(vaultId: '', itemId: 'i'),
        throwsA(isA<VaultSealFormatException>()),
      );
      expect(
        () => SealContext(vaultId: 'v' * 257, itemId: 'i'),
        throwsA(isA<VaultSealFormatException>()),
      );
      expect(
        () => WrapContext(vaultId: 'v', keyGeneration: 0),
        throwsA(isA<VaultSealFormatException>()),
      );
      expect(
        () => MemberPublicKey.fromBytes(Uint8List(31)),
        throwsA(isA<VaultSealFormatException>()),
      );
      expect(
        () => VaultKey.fromBytes(Uint8List(31)),
        throwsA(isA<VaultSealFormatException>()),
      );
      expect(
        () => wrapVaultKey(
          vaultKey: key,
          recipient: MemberPublicKey.fromBytes(Uint8List(32)),
          context: WrapContext(vaultId: 'v', keyGeneration: 1),
        ),
        throwsA(isA<VaultSealAuthenticationException>()),
      );
    });
  });

  group('secret handling', () {
    test('fromBytes copies and toString hides key material', () async {
      final raw = Uint8List(32)..[0] = 0xff;
      final key = VaultKey.fromBytes(raw);
      raw[0] = 0x01;
      expect(key.toBytes()[0], 0xff);
      expect(key.toString(), 'VaultKey()');
      expect(key.toString().toLowerCase().contains(encodeHex(key.toBytes())),
          isFalse);

      final private = Uint8List(32)..[0] = 0x07;
      final member = await MemberKeyPair.fromPrivateKeyBytes(private);
      expect(private[0], 0x07);
      expect(member.toString(), 'MemberKeyPair()');
      final stored = member.toPrivateKeyBytes();
      expect(
          member.toString().toLowerCase().contains(encodeHex(stored)), isFalse);
      expect(stored[0] & 0x07, 0);
    });

    test('destroy wipes the local copy', () async {
      final key = await VaultKey.generate();
      key.destroy();
      expect(key.toString(), 'VaultKey()');
      expect(key.toBytes, throwsStateError);
      final member = await MemberKeyPair.generate();
      member.destroy();
      expect(member.toString(), 'MemberKeyPair()');
      expect(member.toPrivateKeyBytes, throwsStateError);
    });

    test('authentication errors use one message', () {
      expect(
        VaultSealAuthenticationException().toString(),
        'VaultSealAuthenticationException: authentication failed',
      );
    });
  });
}
