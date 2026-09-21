#!/usr/bin/env python3
"""Write independent known-answer vectors for scheme 1.

HPKE vectors come from pyhpke. Item vectors come from the Python
cryptography AES-GCM implementation. Neither path imports the Dart code.
"""

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pyhpke import AEADId, CipherSuite, KDFId, KEMId
from pyhpke.kem_key import KEMKeyPair

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "vectors"


def hexlify(data: bytes) -> str:
    return data.hex()


def suite_for(aead: AEADId) -> CipherSuite:
    return CipherSuite.new(
        KEMId.DHKEM_X25519_HKDF_SHA256,
        KDFId.HKDF_SHA256,
        aead,
    )


def public_bytes(private: bytes) -> bytes:
    key = X25519PrivateKey.from_private_bytes(private)
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def key_pair(suite: CipherSuite, private: bytes) -> KEMKeyPair:
    secret = suite.kem.deserialize_private_key(private)
    public = suite.kem.deserialize_public_key(public_bytes(private))
    return KEMKeyPair(secret, public)


def item_aad(vault_id: str, item_id: str, purpose: int = 1) -> bytes:
    vault = vault_id.encode()
    item = item_id.encode()
    return (
        b"vaultseal-item"
        + len(vault).to_bytes(2, "big")
        + vault
        + len(item).to_bytes(2, "big")
        + item
        + bytes([purpose])
    )


def wrap_aad(vault_id: str, key_generation: int, recipient_public: bytes) -> bytes:
    vault = vault_id.encode()
    return (
        b"vaultseal-wrap"
        + key_generation.to_bytes(4, "big")
        + len(vault).to_bytes(2, "big")
        + vault
        + recipient_public
    )


def verify_rfc_a1() -> None:
    suite = suite_for(AEADId.AES128_GCM)
    sk_e = bytes.fromhex(
        "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736"
    )
    sk_r = bytes.fromhex(
        "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8"
    )
    info = bytes.fromhex("4f6465206f6e2061204772656369616e2055726e")
    pt = bytes.fromhex("4265617574792069732074727574682c20747275746820626561757479")
    aad = bytes.fromhex("436f756e742d30")
    expected_ct = bytes.fromhex(
        "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a9"
        "6d8770ac83d07bea87e13c512a"
    )
    sender_keys = key_pair(suite, sk_e)
    recipient = key_pair(suite, sk_r).public_key
    enc, context = suite.create_sender_context(recipient, info, eks=sender_keys)
    ct = context.seal(pt, aad)
    if enc.hex() != "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431":
        raise SystemExit(f"unexpected enc {enc.hex()}")
    if ct != expected_ct:
        raise SystemExit("pyhpke diverges from RFC 9180 A.1.1")


def write_hpke_aes256() -> None:
    suite = suite_for(AEADId.AES256_GCM)
    sk_e = bytes.fromhex("11" * 32)
    sk_r = bytes.fromhex("22" * 32)
    vault_key = bytes.fromhex("33" * 32)
    sender_keys = key_pair(suite, sk_e)
    recipient_keys = key_pair(suite, sk_r)
    recipient_public = recipient_keys.public_key.to_public_bytes()
    info = wrap_aad("vault-1", 1, recipient_public)
    enc, context = suite.create_sender_context(
        recipient_keys.public_key,
        info,
        eks=sender_keys,
    )
    ciphertext = context.seal(vault_key, info)
    recipient = suite.create_recipient_context(enc, recipient_keys.private_key, info)
    opened = recipient.open(ciphertext, info)
    if opened != vault_key:
        raise SystemExit("pyhpke open did not return the vault key")
    blob = bytes([0x01]) + enc + ciphertext
    if len(blob) != 81:
        raise SystemExit(f"wrap length {len(blob)}")
    payload = {
        "description": "pyhpke DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, Base single-shot",
        "kem_id": 32,
        "kdf_id": 1,
        "aead_id": 2,
        "ephemeral_private_key": hexlify(sk_e),
        "recipient_private_key": hexlify(sk_r),
        "recipient_public_key": hexlify(recipient_public),
        "vault_key": hexlify(vault_key),
        "vault_id": "vault-1",
        "key_generation": 1,
        "info": hexlify(info),
        "enc": hexlify(enc),
        "ciphertext": hexlify(ciphertext),
        "wrapped_vault_key": hexlify(blob),
    }
    (VECTORS / "hpke_x25519_aes256gcm.json").write_text(
        json.dumps(payload, indent=2) + "\n"
    )


def write_item() -> None:
    key = bytes.fromhex("44" * 32)
    nonce = bytes.fromhex("0102030405060708090a0b0c")
    plaintext = bytes.fromhex("00112233fffe")
    aad = item_aad("vault-1", "item-1", 1)
    sealed_body = AESGCM(key).encrypt(nonce, plaintext, aad)
    framed = bytes([0x01]) + nonce + sealed_body
    nist_key = bytes.fromhex(
        "b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4"
    )
    nist_nonce = bytes.fromhex("516c33929df5a3284ff463d7")
    nist_body = AESGCM(nist_key).encrypt(nist_nonce, b"", b"")
    if nist_body.hex() != "bdc1ac884d332457a1d2664f168c76f0":
        raise SystemExit(f"NIST vector mismatch {nist_body.hex()}")
    payload = {
        "description": "scheme 1 item, AES-256-GCM via Python cryptography",
        "vault_key": hexlify(key),
        "nonce": hexlify(nonce),
        "plaintext": hexlify(plaintext),
        "vault_id": "vault-1",
        "item_id": "item-1",
        "purpose": 1,
        "aad": hexlify(aad),
        "sealed_item": hexlify(framed),
        "nist_cavp_gcmEncryptExtIV256_count0": {
            "key": hexlify(nist_key),
            "nonce": hexlify(nist_nonce),
            "plaintext": "",
            "aad": "",
            "ciphertext_and_tag": nist_body.hex(),
        },
    }
    (VECTORS / "item_scheme_v1.json").write_text(json.dumps(payload, indent=2) + "\n")


def write_rfc() -> None:
    payload = {
        "description": "RFC 9180 Appendix A.1.1 Base, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM",
        "info": "4f6465206f6e2061204772656369616e2055726e",
        "skEm": "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
        "pkRm": "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
        "skRm": "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
        "enc": "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
        "shared_secret": "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
        "key": "4531685d41d65f03dc48f6b8302c05b0",
        "base_nonce": "56d890e5accaaf011cff4b7d",
        "exporter_secret": "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8",
        "encryptions": [
            {
                "seq": 0,
                "pt": "4265617574792069732074727574682c20747275746820626561757479",
                "aad": "436f756e742d30",
                "ct": "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
            }
        ],
    }
    (VECTORS / "rfc9180_a1_base.json").write_text(json.dumps(payload, indent=2) + "\n")


def main() -> None:
    VECTORS.mkdir(exist_ok=True)
    verify_rfc_a1()
    write_rfc()
    write_hpke_aes256()
    write_item()
    print("wrote vectors")


if __name__ == "__main__":
    main()
