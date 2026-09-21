@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';

import 'known_vectors.dart';

void main() {
  test('vectors/hpke_x25519_aes256gcm.json matches the Dart literals', () {
    final json = jsonDecode(
            File('vectors/hpke_x25519_aes256gcm.json').readAsStringSync())
        as Map<String, Object?>;
    expect(json['wrapped_vault_key'], pyhpkeWrapped);
    expect(json['ciphertext'], pyhpkeCiphertext);
    expect(json['enc'], pyhpkeEnc);
    expect(json['info'], pyhpkeInfo);
    expect(json['recipient_public_key'], pyhpkeRecipientPublic);
  });

  test('vectors/item_scheme_v1.json matches the Dart literals', () {
    final json =
        jsonDecode(File('vectors/item_scheme_v1.json').readAsStringSync())
            as Map<String, Object?>;
    expect(json['sealed_item'], itemSealed);
    expect(json['aad'], itemAad);
    final nist =
        json['nist_cavp_gcmEncryptExtIV256_count0'] as Map<String, Object?>;
    expect(nist['ciphertext_and_tag'], nistTag);
  });

  test('vectors/rfc9180_a1_base.json matches the Dart literals', () {
    final json =
        jsonDecode(File('vectors/rfc9180_a1_base.json').readAsStringSync())
            as Map<String, Object?>;
    expect(json['shared_secret'], rfcSharedSecret);
    final encryptions = json['encryptions'] as List<Object?>;
    final first = encryptions.first as Map<String, Object?>;
    expect(first['ct'], rfcCt0);
  });
}
