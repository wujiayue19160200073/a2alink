"""密码学模块测试。

重点不是"加密能解回来"（那种测试几乎总能过），而是：
  1. 是否符合 RFC —— 用官方测试向量，防止"自签自验的假正确"
  2. 篡改是否被检出 —— 每一个字节都要验
  3. 失败是否"安全地失败" —— 异常不能变成跳过校验
"""

import base64
import os
import shutil
import tempfile
import unittest

from a2alink.crypto import (CryptoError, DecryptionError, Ed25519KeyPair,
                            KeyStore, SignatureError, X25519KeyPair, aead_open,
                            aead_seal, b64d, b64e, decrypt_from, encrypt_for,
                            fingerprint_of, hkdf_sha256, x25519)


class TestRFCVectors(unittest.TestCase):
    """官方测试向量。这些不过，后面所有测试都毫无意义。"""

    # RFC 8032 §7.1
    ED25519 = [
        ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
        ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
        ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
         "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    ]

    def test_ed25519_vectors(self):
        for sk, pk, msg, sig in self.ED25519:
            with self.subTest(pk=pk[:16]):
                kp = Ed25519KeyPair(bytes.fromhex(sk))
                self.assertEqual(kp.public_bytes.hex(), pk)
                self.assertEqual(kp.sign(bytes.fromhex(msg)).hex(), sig)
                self.assertTrue(Ed25519KeyPair.verify(
                    bytes.fromhex(pk), bytes.fromhex(msg), bytes.fromhex(sig)))

    def test_x25519_vectors(self):
        """RFC 7748 §5.2。"""
        cases = [
            ("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
             "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
             "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
            ("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
             "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
             "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
        ]
        for k, u, exp in cases:
            self.assertEqual(x25519(bytes.fromhex(k), bytes.fromhex(u)).hex(), exp)

    def test_x25519_dh_rfc7748_61(self):
        a = X25519KeyPair(bytes.fromhex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
        b = X25519KeyPair(bytes.fromhex(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
        self.assertEqual(a.public_bytes.hex(),
                         "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        self.assertEqual(a.agree(b.public_bytes), b.agree(a.public_bytes))
        self.assertEqual(a.agree(b.public_bytes).hex(),
                         "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

    def test_hkdf_rfc5869_case1(self):
        okm = hkdf_sha256(b"\x0b" * 22,
                          bytes.fromhex("000102030405060708090a0b0c"),
                          bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42)
        self.assertEqual(
            okm.hex(),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56"
            "ecc4c5bf34007208d5b887185865")


class TestSignature(unittest.TestCase):
    def test_tamper_message(self):
        kp = Ed25519KeyPair.generate()
        sig = kp.sign(b"original")
        self.assertTrue(Ed25519KeyPair.verify(kp.public_bytes, b"original", sig))
        self.assertFalse(Ed25519KeyPair.verify(kp.public_bytes, b"originaL", sig))

    def test_tamper_signature_bit(self):
        kp = Ed25519KeyPair.generate()
        sig = bytearray(kp.sign(b"msg"))
        for i in (0, 31, 32, 63):
            bad = bytearray(sig)
            bad[i] ^= 0x01
            self.assertFalse(Ed25519KeyPair.verify(kp.public_bytes, b"msg", bytes(bad)))

    def test_wrong_key_fails(self):
        a = Ed25519KeyPair.generate()
        b = Ed25519KeyPair.generate()
        sig = a.sign(b"msg")
        self.assertFalse(Ed25519KeyPair.verify(b.public_bytes, b"msg", sig))

    def test_malformed_inputs_return_false_not_raise(self):
        """畸形输入必须返回 False，不能抛异常。

        因为调用方一般是 `if not verify(...): reject`。
        如果这里抛异常，而上层没有 try，消息可能就"意外地"被放行了。
        """
        kp = Ed25519KeyPair.generate()
        sig = kp.sign(b"m")
        self.assertFalse(Ed25519KeyPair.verify(kp.public_bytes, b"m", b""))
        self.assertFalse(Ed25519KeyPair.verify(kp.public_bytes, b"m", b"x" * 64))
        self.assertFalse(Ed25519KeyPair.verify(b"\x00" * 32, b"m", sig))
        self.assertFalse(Ed25519KeyPair.verify(b"", b"m", sig))

    def test_sig_of_zero_scalar_rejected(self):
        """S 分量全零是经典的伪造点，必须拒。"""
        kp = Ed25519KeyPair.generate()
        sig = sig0 = kp.sign(b"m")[:32] + b"\x00" * 32
        self.assertFalse(Ed25519KeyPair.verify(kp.public_bytes, b"m", sig0))


class TestAEAD(unittest.TestCase):
    def test_roundtrip(self):
        key = os.urandom(32)
        for text in (b"", b"a", "中文内容".encode(), os.urandom(5000)):
            sealed = aead_seal(key, text, b"aad")
            self.assertEqual(aead_open(key, sealed, b"aad"), text)

    def test_aad_must_match(self):
        key = os.urandom(32)
        sealed = aead_seal(key, b"x", b"header-A")
        with self.assertRaises(DecryptionError):
            aead_open(key, sealed, b"header-B")

    def test_every_field_tamper(self):
        key = os.urandom(32)
        sealed = aead_seal(key, b"secret", b"")
        for field in ("n", "ct", "tag"):
            raw = bytearray(b64d(sealed[field]))
            raw[0] ^= 0x01
            bad = dict(sealed)
            bad[field] = b64e(bytes(raw))
            with self.assertRaises(DecryptionError, msg=field):
                aead_open(key, bad, b"")

    def test_wrong_key(self):
        sealed = aead_seal(os.urandom(32), b"x")
        with self.assertRaises(DecryptionError):
            aead_open(os.urandom(32), sealed)


class TestEnvelopeCrypto(unittest.TestCase):
    def test_encrypt_for_nondeterministic(self):
        r = X25519KeyPair.generate()
        a = encrypt_for(r.public_bytes, b"same text", b"aad")
        b = encrypt_for(r.public_bytes, b"same text", b"aad")
        self.assertNotEqual(a["ct"], b["ct"])
        self.assertNotEqual(a["epk"], b["epk"])   # 临时密钥每次不同 → 前向保密

    def test_header_binding(self):
        """aad 不同就不能解——这一条挡住"改 from/to 后转发给第三方"。"""
        r = X25519KeyPair.generate()
        blob = encrypt_for(r.public_bytes, b"x", b"from=alice,to=bob")
        with self.assertRaises(DecryptionError):
            decrypt_from(r, r.public_bytes, blob, b"from=alice,to=carol")

    def test_unknown_alg_rejected(self):
        r = X25519KeyPair.generate()
        blob = encrypt_for(r.public_bytes, b"x")
        blob["alg"] = "rot13"
        with self.assertRaises(DecryptionError):
            decrypt_from(r, r.public_bytes, blob)


class TestKeyStore(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_generate_and_reload(self):
        ks = KeyStore(os.path.join(self.root, "k")).load_or_create()
        fp = ks.signing.fingerprint
        ks2 = KeyStore(os.path.join(self.root, "k")).load_or_create()
        self.assertEqual(ks2.signing.fingerprint, fp)

    def test_private_key_permissions(self):
        ks = KeyStore(os.path.join(self.root, "k")).load_or_create()
        if os.name == "nt":
            self.skipTest("Windows 上 chmod 语义不同，无法断言 0600")
        mode = os.stat(os.path.join(ks.root, "signing.key")).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_regenerate_refuses_to_overwrite(self):
        """覆盖已有密钥 = 悄悄把身份弄丢。必须显式 rotate。"""
        ks = KeyStore(os.path.join(self.root, "k")).load_or_create()
        with self.assertRaises(CryptoError):
            ks.generate()

    def test_rotate_keeps_archived_copy(self):
        ks = KeyStore(os.path.join(self.root, "k")).load_or_create()
        old = ks.signing.fingerprint
        out = ks.rotate()
        self.assertNotEqual(ks.signing.fingerprint, old)
        self.assertEqual(out["old_fingerprint"], old)
        archived = [f for f in os.listdir(ks.root) if f.endswith(".old")]
        self.assertTrue(archived, "旧私钥应被归档而不是删除")

    def test_corrupt_key_file_raises(self):
        ks = KeyStore(os.path.join(self.root, "k")).load_or_create()
        with open(os.path.join(ks.root, "signing.key"), "wb") as f:
            f.write(b"short")
        with self.assertRaises(CryptoError):
            KeyStore(os.path.join(self.root, "k")).load_or_create()

    def test_write_key_is_binary_on_windows(self):
        """回归测试：Windows 的 os.open 默认文本模式会把 0x0A 写成 0x0D 0x0A。

        32 字节随机密钥含 0x0A 的概率约 12%，这个 bug 会让"偶尔有人的
        密钥文件读不出来"，而且只在 Windows 上出现。
        """
        ks = KeyStore(os.path.join(self.root, "k")).load_or_create()
        payload = b"\n" * 16 + b"\r" * 16
        target = os.path.join(ks.root, "probe.key")
        KeyStore._write_key(target, payload)
        with open(target, "rb") as f:
            self.assertEqual(f.read(), payload)

    def test_many_generated_keys_always_32_bytes(self):
        """连续生成若干把钥匙，全部都必须是 32 字节可回读的。"""
        for i in range(30):
            root = os.path.join(self.root, f"k{i}")
            ks = KeyStore(root).load_or_create()
            again = KeyStore(root).load_or_create()
            self.assertEqual(again.signing.private_bytes, ks.signing.private_bytes)
            self.assertEqual(len(again.kex.private_bytes), 32)

    def test_public_bundle_has_no_private(self):
        ks = KeyStore(os.path.join(self.root, "k")).load_or_create()
        blob = ks.public_bundle()
        raw = str(blob)
        self.assertNotIn(ks.signing.private_bytes.hex()[:16], raw)
        self.assertNotIn(ks.kex.private_bytes.hex()[:16], raw)


class TestFingerprint(unittest.TestCase):
    def test_format_is_human_readable(self):
        fp = fingerprint_of(b"\x01" * 32)
        self.assertEqual(len(fp.split("-")), 8)
        self.assertEqual(len(fp.replace("-", "")), 32)

    def test_stable_and_distinct(self):
        self.assertEqual(fingerprint_of(b"a" * 32), fingerprint_of(b"a" * 32))
        self.assertNotEqual(fingerprint_of(b"a" * 32), fingerprint_of(b"b" * 32))


if __name__ == "__main__":
    unittest.main()
