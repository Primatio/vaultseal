import 'item.dart';
import 'aad.dart';
import 'hybrid_key.dart';
import 'hybrid_wrap.dart';
import 'member_key.dart';
import 'scheme.dart';
import 'vault_key.dart';
import 'wrap.dart';

/// One sealed item to open under the current vault key and seal again.
final class RotationItem {
  /// Creates an item for [rotateVaultKey].
  RotationItem({required this.sealed, required this.context});

  /// Item sealed under the current vault key.
  final SealedItem sealed;

  /// Associated data to keep. The vault id must match the rotation.
  final SealContext context;
}

/// A vault key rotation: a new key, the resealed items, and the new wraps.
///
/// The caller owns [vaultKey] and must call [VaultKey.destroy] when the new
/// blobs have been stored. This object does not delete the previous generation
/// from storage.
final class VaultRotation {
  /// Creates a completed rotation.
  VaultRotation({
    required this.vaultKey,
    required this.keyGeneration,
    required this.items,
    required this.wraps,
    required this.hybridWraps,
  });

  /// New vault key. Items in [items] open with this key.
  final VaultKey vaultKey;

  /// Generation bound into [wraps] and [hybridWraps].
  final int keyGeneration;

  /// Items resealed under [vaultKey], in the same order as the input.
  final List<RotationItem> items;

  /// Scheme-1 wraps of [vaultKey], in the same order as the X25519 recipients.
  final List<WrappedVaultKey> wraps;

  /// Scheme-2 wraps of [vaultKey], in the same order as the hybrid recipients.
  final List<HybridWrappedVaultKey> hybridWraps;
}

/// Opens every item under [current], seals it under a new vault key, and wraps
/// that key to [recipients] and [hybridRecipients].
///
/// [nextGeneration] is the generation written into the new wraps. The app
/// chooses it and must keep it greater than the generation it is replacing.
/// Item associated data is preserved, including purpose.
///
/// At least one recipient is required. An item whose vault id differs from
/// [vaultId] is a format error. If any item fails to open, the new key is
/// destroyed and [VaultSealAuthenticationException] is thrown. [current] is
/// left intact.
///
/// The app must store the new blobs and stop serving the previous generation.
/// A member who already unwrapped the old key can still open the old items.
Future<VaultRotation> rotateVaultKey({
  required VaultKey current,
  required String vaultId,
  required int nextGeneration,
  required List<RotationItem> items,
  List<MemberPublicKey> recipients = const [],
  List<HybridMemberPublicKey> hybridRecipients = const [],
}) async {
  if (recipients.isEmpty && hybridRecipients.isEmpty) {
    throw const VaultSealFormatException(
      'A rotation needs at least one recipient.',
    );
  }
  final context = WrapContext(vaultId: vaultId, keyGeneration: nextGeneration);
  for (final item in items) {
    if (item.context.vaultId != context.vaultId) {
      throw const VaultSealFormatException(
        'Item vaultId does not match the rotation vault.',
      );
    }
  }

  final fresh = await VaultKey.generate();
  try {
    final resealed = <RotationItem>[];
    for (final item in items) {
      final plaintext = await openItem(
        sealed: item.sealed,
        vaultKey: current,
        context: item.context,
      );
      try {
        final sealed = await sealItem(
          plaintext: plaintext,
          vaultKey: fresh,
          context: item.context,
        );
        resealed.add(RotationItem(sealed: sealed, context: item.context));
      } finally {
        plaintext.fillRange(0, plaintext.length, 0);
      }
    }

    final wraps = <WrappedVaultKey>[];
    for (final recipient in recipients) {
      wraps.add(
        await wrapVaultKey(
          vaultKey: fresh,
          recipient: recipient,
          context: context,
        ),
      );
    }
    final hybridWraps = <HybridWrappedVaultKey>[];
    for (final recipient in hybridRecipients) {
      hybridWraps.add(
        await wrapHybridVaultKey(
          vaultKey: fresh,
          recipient: recipient,
          context: context,
        ),
      );
    }
    return VaultRotation(
      vaultKey: fresh,
      keyGeneration: context.keyGeneration,
      items: resealed,
      wraps: wraps,
      hybridWraps: hybridWraps,
    );
  } catch (error) {
    fresh.destroy();
    rethrow;
  }
}
