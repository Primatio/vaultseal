import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart';
import 'package:test/test.dart';
import 'package:vaultseal/src/hybrid_wrap.dart';
import 'package:vaultseal/vaultseal.dart';

import 'hex.dart';

void main() {
  group('hybrid wrap', () {
    test('combiner matches the locked HKDF vector', () async {
      final key = await hybridWrapKeyForTest(
        x25519SharedSecret: Uint8List(32)..fillRange(0, 32, 0x11),
        mlKemSharedSecret: Uint8List(32)..fillRange(0, 32, 0x22),
        x25519Enc: Uint8List(32)..fillRange(0, 32, 0x33),
        mlKemCiphertext: Uint8List(1088)..fillRange(0, 4, 0x44),
        recipientPublicKey: Uint8List(hybridPublicKeyLength)
          ..fillRange(0, 4, 0x55),
      );
      expect(encodeHex(key), hybridCombinerVector);
    });

    test('fixed coins produce the locked scheme-2 blob', () async {
      final member = await HybridMemberKeyPair.fromPrivateKeyBytes(
        await _hybridPrivate(x25519: 0x22, mlKemSeed: 0x11),
      );
      final wrapped = await wrapHybridVaultKeyForTest(
        vaultKey: VaultKey.fromBytes(Uint8List(32)..fillRange(0, 32, 0x55)),
        recipient: member.publicKey,
        context: WrapContext(vaultId: 'vault-1', keyGeneration: 1),
        ephemeralPrivateKey: Uint8List(32)..fillRange(0, 32, 0x33),
        mlKemCoins: Uint8List(32)..fillRange(0, 32, 0x44),
        nonce: Uint8List.fromList(List<int>.generate(12, (i) => i + 1)),
      );
      expect(wrapped.toBytes(), hasLength(hybridWrappedVaultKeyLength));
      expect(wrapped.toBytes()[0], hybridWrapScheme);
      expect(encodeHex(wrapped.toBytes()), hybridWrappedVector);

      final opened = await unwrapHybridVaultKey(
        wrapped: wrapped,
        recipient: member,
        context: WrapContext(vaultId: 'vault-1', keyGeneration: 1),
      );
      expect(opened.toBytes(), everyElement(0x55));
      opened.destroy();
      member.destroy();
    });

    test('round-trips, rejects a mismatch, and hides key bytes', () async {
      final member = await HybridMemberKeyPair.generate();
      final other = await HybridMemberKeyPair.generate();
      final key = await VaultKey.generate();
      final context = WrapContext(vaultId: 'vault-1', keyGeneration: 4);
      final wrapped = await wrapHybridVaultKey(
        vaultKey: key,
        recipient: member.publicKey,
        context: context,
      );
      final opened = await unwrapHybridVaultKey(
        wrapped: wrapped,
        recipient: member,
        context: context,
      );
      expect(opened.toBytes(), key.toBytes());

      final flipped = Uint8List.fromList(wrapped.toBytes())..last ^= 0x01;
      await expectLater(
        unwrapHybridVaultKey(
          wrapped: HybridWrappedVaultKey.parse(flipped),
          recipient: member,
          context: context,
        ),
        throwsA(isA<VaultSealAuthenticationException>()),
      );
      await expectLater(
        unwrapHybridVaultKey(
          wrapped: wrapped,
          recipient: other,
          context: context,
        ),
        throwsA(isA<VaultSealAuthenticationException>()),
      );
      await expectLater(
        unwrapHybridVaultKey(
          wrapped: wrapped,
          recipient: member,
          context: WrapContext(vaultId: 'vault-1', keyGeneration: 5),
        ),
        throwsA(isA<VaultSealAuthenticationException>()),
      );

      expect(member.toString(), 'HybridMemberKeyPair()');
      expect(member.publicKey.toString(), 'HybridMemberPublicKey()');
      final restored = await HybridMemberKeyPair.fromPrivateKeyBytes(
        member.toPrivateKeyBytes(),
      );
      expect(restored.publicKey.toBytes(), member.publicKey.toBytes());
      expect(restored.toPrivateKeyBytes(), member.toPrivateKeyBytes());
      member.destroy();
      expect(() => member.toPrivateKeyBytes(), throwsA(isA<StateError>()));

      opened.destroy();
      key.destroy();
      other.destroy();
      restored.destroy();
    });

    test('scheme-1 and scheme-2 frames do not parse as each other', () {
      expect(
        () => HybridWrappedVaultKey.parse(Uint8List(wrappedVaultKeyLength)),
        throwsA(isA<VaultSealFormatException>()),
      );
      expect(
        () => WrappedVaultKey.parse(
          Uint8List(hybridWrappedVaultKeyLength)..[0] = hybridWrapScheme,
        ),
        throwsA(isA<VaultSealFormatException>()),
      );
      expect(KeyAgreementScheme.hybridMlKem768.wrapScheme, hybridWrapScheme);
      expect(KeyAgreementScheme.x25519.wrapScheme, x25519WrapScheme);
    });

    test('rotateVaultKey can wrap the new key to a hybrid member', () async {
      final current = await VaultKey.generate();
      final hybrid = await HybridMemberKeyPair.generate();
      final context = SealContext(vaultId: 'vault-1', itemId: 'item-1');
      final sealed = await sealItem(
        plaintext: Uint8List.fromList([9]),
        vaultKey: current,
        context: context,
      );
      final rotation = await rotateVaultKey(
        current: current,
        vaultId: 'vault-1',
        nextGeneration: 3,
        items: [RotationItem(sealed: sealed, context: context)],
        hybridRecipients: [hybrid.publicKey],
      );
      final unwrapped = await unwrapHybridVaultKey(
        wrapped: rotation.hybridWraps.single,
        recipient: hybrid,
        context: WrapContext(vaultId: 'vault-1', keyGeneration: 3),
      );
      expect(unwrapped.toBytes(), rotation.vaultKey.toBytes());
      final opened = await openItem(
        sealed: rotation.items.single.sealed,
        vaultKey: unwrapped,
        context: context,
      );
      expect(opened, [9]);
      current.destroy();
      rotation.vaultKey.destroy();
      unwrapped.destroy();
      hybrid.destroy();
    });
  });
}

Future<Uint8List> _hybridPrivate({
  required int x25519,
  required int mlKemSeed,
}) async {
  final (_, mlPrivate) = PqcKem.kyber768.generateKeyPair(
    Uint8List(64)..fillRange(0, 64, mlKemSeed),
  );
  final out = Uint8List(hybridPrivateKeyLength);
  out.fillRange(0, 32, x25519);
  out.setAll(32, mlPrivate);
  return out;
}

/// HKDF-SHA256(`0x11`*32 || `0x22`*32) with the scheme-2 label and the fixed
/// transcript used above. Locked so a combiner change fails closed.
const String hybridCombinerVector =
    '90b5d82111ba82f320e17d63be9fb9b16bb31d68199798a24aa03cfc08659899';

/// Scheme-2 wrap of vault key `0x55`*32 to the fixed hybrid recipient.
const String hybridWrappedVector =
    '027b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b14'
    'b2a915564acf467211b5e521ed547fab76cc6e1da8eaacf763d0e39ec0fb9f08b9'
    'f14b939ebae184ed866337b52412d8ecf81accbda20bfc19a77325b8c84a37bb01'
    '0b413040976bf57d1e73a8c3a219d9f48466be33285116fec68f404d3b68d94f5f'
    '105f8184f6436f380e2849bfed760a322c679f4c2f7b501e93f940a25fa99d7564'
    '2283fb1373dfdece2ce0c15f466b6be1c5329e99b5e2328dafb06eeecbe936cbab'
    '8f8c0c7d62c9bb22f44c48504f3c9c6f1c33dbdd3860e13a88f526e0ac9e36a701'
    'bd2a47e13f0b22373de572fb012a2ba558bb8be3b0c9d4b4cd2dbc05f5e52ba52d'
    '717b0476f3512773a3a348c5dd3c3feac0b9c7e3cf2dc45b7b43a1d21fbf564a83'
    'c5e21a4899dc7fea9758b99d65ef49e6bb87669abeced86f01e4235f28304ee625'
    'ad865d6c56efbc6510b29271a868ba6ed96be6d90b35510b1a8bea9e2d89e035c8'
    '2efcd3685770f7c2e275eb89fda5dae4aab3f86252be0784c82fcb9b8c17a33c2f'
    '0fcb12fc0aa8b896ebb8ff83d8367a3e02a60543e75f4c04643543968879e47af9'
    'e6ae75efe5b6c5cfa9ee1ad1339d0c4c58266bf03b8450cec4b4f9ae6c26045543'
    '2f7717ad439f469ad4d0ed2ff43fab54103be297d485e72cccc4bb2a980ebd3e54'
    '1d0a9e9ff3fadb55809eb8df67b490200326e7e5ab7eeb58e562782aa7fe67c6df'
    '3546cfc4fb8afb816b390a3811a21ee71273f5bd4d64ad579d9628296466e09edc'
    'fd75482703e5c069c2b73e91572733a65af86445a06d8e4227a2151acb8893e0c3'
    'c2d8f744cdca6d7631b2a00897a9716423d1f4376c6fd169af6113926a6cea10ea'
    '4ba3b1ed4ef1237260ba5f749a7183fd30190a4b09942167d00533e3c8ac89ef39'
    '5e78d9625c9c616e712f41f27cdb95568eb2dc3d06c7bfe4aa6ee3056cd0d9e8b0'
    '834e1fe90a14670a7c314474401b8d462851a184dead5fb62b15d15f973e0edc71'
    '749b3c5f5356910446c97e0f8658201415c052fc937fb78efba524106627b343d5'
    'eec13286bbd9bff6537b1029b73ee0a25997eaf4661e9b8e7ba758f176b27cc671'
    '22d611ec16b6459c252a8fe410cc638a75d8309cd7585ec207fedefddd2fc9b0cb'
    '8b8a4cb5abd0b785ba46b2be396c40767c58dc02fe96e80694b5f4be380a93fce4'
    '20cffa58d8069fb005941cda15f3f584fd1f4941dce959ea36094acc619d0774b9'
    'ac97f94ae3f2b39bd0f90d036666cfdf9b1c5f586ca855cc1f4b416006171e8b14'
    '66b540aaead544beb03c4b9efb86beb32c53b1104b8b47e26a55cf1b8841fa52d4'
    '38a83b2d412911861f51d2422280a9898fa8a9e478a3bb2077c3bf0c9fa8a3859c'
    '44c8a2519651df2644b1c8fcce8b45b2a1526b578f38f67a037e5c5216e76aaa43'
    '5951b6c138ba339a4ce32d3b0fe807c722aabc260403af4edb78ca9be9911afffd'
    'ffd90624c4f0b98587de8e99b917363217a2891db0155e6dd7ca2b1abce7e53dd8'
    'b2adb52711546fa6d3e247caed0312f5067b1424fa0157d90edc36d7150aab5901'
    '02030405060708090a0b0c50625414cc7aeb9f0a48b37cde0305555273da6da14f'
    'cef797d1a11f3a7fa6516f103ae25f75517a82a5c0b57a59bb58';
