import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:vaultseal/src/share.dart';
import 'package:vaultseal/vaultseal.dart';

void main() {
  group('rotateVaultKey', () {
    test('reseals items and wraps the new key to each recipient', () async {
      final current = await VaultKey.generate();
      final alice = await MemberKeyPair.generate();
      final bob = await MemberKeyPair.generate();
      final context = SealContext(vaultId: 'vault-1', itemId: 'item-1');
      final sealed = await sealItem(
        plaintext: Uint8List.fromList(utf8.encode('secret')),
        vaultKey: current,
        context: context,
      );

      final rotation = await rotateVaultKey(
        current: current,
        vaultId: 'vault-1',
        nextGeneration: 2,
        items: [RotationItem(sealed: sealed, context: context)],
        recipients: [alice.publicKey, bob.publicKey],
      );

      expect(rotation.keyGeneration, 2);
      expect(rotation.wraps, hasLength(2));
      final opened = await openItem(
        sealed: rotation.items.single.sealed,
        vaultKey: rotation.vaultKey,
        context: context,
      );
      expect(utf8.decode(opened), 'secret');
      await expectLater(
        openItem(
            sealed: rotation.items.single.sealed,
            vaultKey: current,
            context: context),
        throwsA(isA<VaultSealAuthenticationException>()),
      );

      final wrapContext = WrapContext(vaultId: 'vault-1', keyGeneration: 2);
      for (final member in [alice, bob]) {
        final unwrapped = await unwrapVaultKey(
          wrapped: member == alice ? rotation.wraps[0] : rotation.wraps[1],
          recipient: member,
          context: wrapContext,
        );
        expect(unwrapped.toBytes(), rotation.vaultKey.toBytes());
        unwrapped.destroy();
      }

      current.destroy();
      rotation.vaultKey.destroy();
      alice.destroy();
      bob.destroy();
    });

    test('a failed open destroys the new key and keeps the old one', () async {
      final current = await VaultKey.generate();
      final other = await VaultKey.generate();
      final member = await MemberKeyPair.generate();
      final context = SealContext(vaultId: 'vault-1', itemId: 'item-1');
      final sealed = await sealItem(
        plaintext: Uint8List.fromList([1, 2, 3]),
        vaultKey: other,
        context: context,
      );

      await expectLater(
        rotateVaultKey(
          current: current,
          vaultId: 'vault-1',
          nextGeneration: 2,
          items: [RotationItem(sealed: sealed, context: context)],
          recipients: [member.publicKey],
        ),
        throwsA(isA<VaultSealAuthenticationException>()),
      );
      expect(current.isDestroyed, isFalse);
      current.destroy();
      other.destroy();
      member.destroy();
    });

    test('rejects an empty recipient list and a mismatched vault id', () async {
      final current = await VaultKey.generate();
      await expectLater(
        rotateVaultKey(
          current: current,
          vaultId: 'vault-1',
          nextGeneration: 2,
          items: const [],
        ),
        throwsA(isA<VaultSealFormatException>()),
      );
      final context = SealContext(vaultId: 'other', itemId: 'item-1');
      final sealed = await sealItem(
        plaintext: Uint8List(0),
        vaultKey: current,
        context: context,
      );
      final member = await MemberKeyPair.generate();
      await expectLater(
        rotateVaultKey(
          current: current,
          vaultId: 'vault-1',
          nextGeneration: 2,
          items: [RotationItem(sealed: sealed, context: context)],
          recipients: [member.publicKey],
        ),
        throwsA(isA<VaultSealFormatException>()),
      );
      current.destroy();
      member.destroy();
    });
  });

  group('share payload', () {
    test('uses the share v2 associated data and round-trips', () async {
      final context = ShareContext(shareId: 'share-1', senderId: 'sender-1');
      expect(
        context.toAad(),
        Uint8List.fromList(
            [...utf8.encode('share-1'), 0, ...utf8.encode('sender-1')]),
      );
      final dek = ShareDek.fromBytes(Uint8List(32)..[0] = 7);
      final sealed = await sealSharePayloadForTest(
        plaintext: Uint8List.fromList(utf8.encode('hello')),
        dek: dek,
        context: context,
        nonce: Uint8List.fromList(List<int>.generate(12, (i) => i + 1)),
      );
      expect(sealed.nonce, hasLength(12));
      expect(sealed.tag, hasLength(16));
      final opened = await openSharePayload(
        payload: sealed,
        dek: dek,
        context: context,
      );
      expect(utf8.decode(opened), 'hello');
      expect(dek.toString(), 'ShareDek()');

      final flipped = SealedSharePayload(
        nonce: sealed.nonce,
        ciphertext: Uint8List.fromList(sealed.ciphertext)..[0] ^= 0x01,
        tag: sealed.tag,
      );
      await expectLater(
        openSharePayload(payload: flipped, dek: dek, context: context),
        throwsA(isA<VaultSealAuthenticationException>()),
      );
      await expectLater(
        openSharePayload(
          payload: sealed,
          dek: dek,
          context: ShareContext(shareId: 'share-1', senderId: 'other'),
        ),
        throwsA(isA<VaultSealAuthenticationException>()),
      );
      dek.destroy();
      expect(dek.isDestroyed, isTrue);
    });

    test('rejects an empty id and an oversized plaintext', () async {
      expect(
        () => ShareContext(shareId: '', senderId: 'sender'),
        throwsA(isA<VaultSealFormatException>()),
      );
      final dek = await ShareDek.generate();
      await expectLater(
        sealSharePayload(
          plaintext: Uint8List(maxPlaintextLength + 1),
          dek: dek,
          context: ShareContext(shareId: 's', senderId: 'a'),
        ),
        throwsA(isA<VaultSealFormatException>()),
      );
      dek.destroy();
    });
  });
}
