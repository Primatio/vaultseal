import 'dart:convert';
import 'dart:typed_data';

import 'package:vaultseal/vaultseal.dart';

Future<void> main() async {
  final key = await VaultKey.generate();
  final member = await MemberKeyPair.generate();
  final item = SealContext(vaultId: 'v', itemId: 'i');
  final w = WrapContext(vaultId: 'v', keyGeneration: 1);
  final pub = member.publicKey;
  final body = Uint8List.fromList(utf8.encode('hi'));
  final sealed = await sealItem(plaintext: body, vaultKey: key, context: item);
  final opened = await openItem(sealed: sealed, vaultKey: key, context: item);
  final box = await wrapVaultKey(vaultKey: key, recipient: pub, context: w);
  final raw = await unwrapVaultKey(wrapped: box, recipient: member, context: w);
  if (utf8.decode(opened) != 'hi') throw StateError('open failed');
  key.destroy();
  member.destroy();
  raw.destroy();
}
