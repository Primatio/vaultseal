import 'package:test/test.dart';
import 'package:vaultseal/src/hpke.dart';

import 'hex.dart';

void main() {
  const info = '4f6465206f6e2061204772656369616e2055726e';
  const skEm =
      '52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736';
  const pkRm =
      '3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d';
  const skRm =
      '4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8';
  const enc =
      '37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431';
  const sharedSecret =
      'fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc';
  const key = '4531685d41d65f03dc48f6b8302c05b0';
  const baseNonce = '56d890e5accaaf011cff4b7d';
  const exporterSecret =
      '45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8';
  const pt = '4265617574792069732074727574682c20747275746820626561757479';
  const aad0 = '436f756e742d30';
  const ct0 =
      'f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a';
  const aad1 = '436f756e742d31';
  const ct1 =
      'af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84';

  test('RFC 9180 A.1.1 Base setup matches', () async {
    final sender = await hpkeSetupBaseSender(
      recipientPublicKey: decodeHex(pkRm),
      info: decodeHex(info),
      ephemeralPrivateKey: decodeHex(skEm),
      aead: HpkeAead.aes128Gcm,
    );
    expect(encodeHex(sender.enc), enc);
    expect(encodeHex(sender.sharedSecret), sharedSecret);
    expect(encodeHex(sender.key), key);
    expect(encodeHex(sender.baseNonce), baseNonce);
    expect(encodeHex(sender.exporterSecret), exporterSecret);

    final sealed0 = await sender.seal(decodeHex(pt), decodeHex(aad0));
    expect(encodeHex(sealed0), ct0);
    final sealed1 = await sender.seal(decodeHex(pt), decodeHex(aad1));
    expect(encodeHex(sealed1), ct1);
  });

  test('RFC 9180 A.1.1 recipient opens sequence 0', () async {
    final recipient = await hpkeSetupBaseRecipient(
      enc: decodeHex(enc),
      recipientPrivateKey: decodeHex(skRm),
      info: decodeHex(info),
      aead: HpkeAead.aes128Gcm,
    );
    expect(encodeHex(recipient.sharedSecret), sharedSecret);
    expect(encodeHex(recipient.key), key);
    final opened = await recipient.open(decodeHex(ct0), decodeHex(aad0));
    expect(encodeHex(opened), pt);
  });
}
