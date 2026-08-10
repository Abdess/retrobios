#!/usr/bin/env python3
"""The hand-written crypto that backs 3DS file validation.

crypto_verify.py and sect233r1.py reimplement RSA PKCS#1 v1.5, AES-128-CBC
and ECDSA over GF(2^233) in pure Python, and validation.py reaches them by a
dynamic import. Nothing exercised them, and a signature check that accepts
everything looks exactly like one that works.

Where possible the expected values come from outside the modules: the curve
parameters are the published SEC 2 ones, so "G is on the curve" and
"n*G is the point at infinity" test the field arithmetic against real
constants rather than against itself. The AES vector is from NIST SP 800-38A.
"""

from __future__ import annotations

import hashlib
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import crypto_verify  # noqa: E402
import sect233r1 as ec  # noqa: E402


class FieldArithmetic(unittest.TestCase):
    """GF(2^233) with the reduction polynomial t^233 + t^74 + 1."""

    VALUES = (1, 2, 3, 0x1234567, ec._Gx, ec._Gy, (1 << 232) | 1)

    def test_reduction_keeps_the_degree_below_the_field_size(self):
        for value in (1 << 300, (1 << 466) - 1, ec._F, ec._F << 5):
            self.assertLessEqual(ec._gf_reduce(value).bit_length(), ec._M)

    def test_addition_is_xor_and_is_its_own_inverse(self):
        for a in self.VALUES:
            for b in self.VALUES:
                self.assertEqual(ec._gf_add(a, b), a ^ b)
                self.assertEqual(ec._gf_add(ec._gf_add(a, b), b), a)

    def test_multiplication_commutes_and_has_one_as_identity(self):
        for a in self.VALUES:
            self.assertEqual(ec._gf_mul(a, 1), ec._gf_reduce(a))
            for b in self.VALUES:
                self.assertEqual(ec._gf_mul(a, b), ec._gf_mul(b, a))

    def test_multiplication_is_associative(self):
        a, b, c = ec._Gx, ec._Gy, 0x1234567
        self.assertEqual(
            ec._gf_mul(ec._gf_mul(a, b), c), ec._gf_mul(a, ec._gf_mul(b, c))
        )

    def test_squaring_agrees_with_multiplying_by_self(self):
        for a in self.VALUES:
            self.assertEqual(ec._gf_sqr(a), ec._gf_mul(a, a))

    def test_inverse_multiplied_back_gives_one(self):
        for a in self.VALUES:
            self.assertEqual(ec._gf_mul(a, ec._gf_inv(a)), 1)

    def test_zero_has_no_inverse(self):
        with self.assertRaises(ZeroDivisionError):
            ec._gf_inv(0)


class CurveParameters(unittest.TestCase):
    """Checks against the published SEC 2 v2 values, not against the module."""

    def _on_curve(self, point) -> bool:
        x, y = point
        left = ec._gf_add(ec._gf_sqr(y), ec._gf_mul(x, y))
        right = ec._gf_add(
            ec._gf_add(ec._gf_mul(ec._gf_sqr(x), x), ec._gf_sqr(x)), ec._B
        )
        return left == right

    def test_the_generator_satisfies_the_curve_equation(self):
        self.assertTrue(self._on_curve((ec._Gx, ec._Gy)))

    def test_multiplying_the_generator_by_the_group_order_gives_infinity(self):
        """The definitive check on the point arithmetic."""
        self.assertIsNone(ec._ec_mul(ec._N, (ec._Gx, ec._Gy)))

    def test_scalar_multiplication_agrees_with_repeated_addition(self):
        g = (ec._Gx, ec._Gy)
        accumulated = None
        for k in range(1, 9):
            accumulated = ec._ec_add(accumulated, g)
            self.assertEqual(ec._ec_mul(k, g), accumulated, f"k={k}")

    def test_doubling_agrees_with_adding_a_point_to_itself(self):
        g = (ec._Gx, ec._Gy)
        self.assertEqual(ec._ec_double(g), ec._ec_add(g, g))

    def test_infinity_is_the_additive_identity(self):
        g = (ec._Gx, ec._Gy)
        self.assertEqual(ec._ec_add(g, None), g)
        self.assertEqual(ec._ec_add(None, g), g)
        self.assertIsNone(ec._ec_add(None, None))
        self.assertIsNone(ec._ec_mul(0, g))

    def test_modular_inverse_round_trips(self):
        for a in (1, 2, 3, 12345, ec._N - 1):
            self.assertEqual((a * ec._modinv(a, ec._N)) % ec._N, 1)


def _sign(message: bytes, private: int, nonce: int) -> bytes:
    """ECDSA-SHA256 signing, so verification has something real to check."""
    g = (ec._Gx, ec._Gy)
    point = ec._ec_mul(nonce, g)
    r = point[0] % ec._N
    digest = int.from_bytes(hashlib.sha256(message).digest(), "big")
    if 256 > ec._N_BITLEN:
        digest >>= 256 - ec._N_BITLEN
    s = (ec._modinv(nonce, ec._N) * (digest + r * private)) % ec._N
    return r.to_bytes(30, "big") + s.to_bytes(30, "big")


class EcdsaVerification(unittest.TestCase):
    PRIVATE = 0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01234567
    NONCE = 0x00FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA
    MESSAGE = b"otp certificate body"

    @classmethod
    def setUpClass(cls):
        point = ec._ec_mul(cls.PRIVATE, (ec._Gx, ec._Gy))
        cls.public = point[0].to_bytes(30, "big") + point[1].to_bytes(30, "big")
        cls.signature = _sign(cls.MESSAGE, cls.PRIVATE, cls.NONCE)

    def test_a_valid_signature_verifies(self):
        self.assertTrue(
            ec.ecdsa_verify_sha256(self.MESSAGE, self.signature, self.public)
        )

    def test_a_changed_message_is_rejected(self):
        self.assertFalse(
            ec.ecdsa_verify_sha256(b"otp certificate bodY", self.signature, self.public)
        )

    def test_a_flipped_signature_bit_is_rejected(self):
        tampered = bytearray(self.signature)
        tampered[45] ^= 0x01
        self.assertFalse(
            ec.ecdsa_verify_sha256(self.MESSAGE, bytes(tampered), self.public)
        )

    def test_another_public_key_is_rejected(self):
        other = ec._ec_mul(self.PRIVATE + 1, (ec._Gx, ec._Gy))
        encoded = other[0].to_bytes(30, "big") + other[1].to_bytes(30, "big")
        self.assertFalse(
            ec.ecdsa_verify_sha256(self.MESSAGE, self.signature, encoded)
        )

    def test_wrong_length_inputs_are_rejected(self):
        self.assertFalse(ec.ecdsa_verify_sha256(self.MESSAGE, b"\x00" * 59, self.public))
        self.assertFalse(
            ec.ecdsa_verify_sha256(self.MESSAGE, self.signature, b"\x00" * 61)
        )

    def test_out_of_range_scalars_are_rejected(self):
        for bad in (b"\x00" * 30, ec._N.to_bytes(30, "big")):
            self.assertFalse(
                ec.ecdsa_verify_sha256(self.MESSAGE, bad + self.signature[30:], self.public)
            )
            self.assertFalse(
                ec.ecdsa_verify_sha256(self.MESSAGE, self.signature[:30] + bad, self.public)
            )


# A 512-bit RSA key built from two fixed primes. Small enough to keep the test
# instant, and the padding logic under test does not depend on modulus size.
_P = 0xE2E9E9B5C1E1C4A1D0A1F7B3C5D7E9F1A3B5C7D9E1F3A5B7C9D1E3F5A7B9C223
_Q = 0xC5D7E9F1A3B5C7D9E1F3A5B7C9D1E3F5A7B9C1D3E5F7A9B1C3D5E7F9A1B3C5DD


class RsaPkcs1V15(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.n = _P * _Q
        cls.e = 65537
        cls.d = pow(cls.e, -1, (_P - 1) * (_Q - 1))
        cls.mod_len = (cls.n.bit_length() + 7) // 8
        cls.modulus = cls.n.to_bytes(cls.mod_len, "big")
        cls.exponent = cls.e.to_bytes(3, "big")

    def _sign(self, message: bytes) -> bytes:
        prefix = bytes.fromhex("3031300d060960864801650304020105000420")
        digest_info = prefix + hashlib.sha256(message).digest()
        ps_len = self.mod_len - len(digest_info) - 3
        em = b"\x00\x01" + b"\xff" * ps_len + b"\x00" + digest_info
        return pow(int.from_bytes(em, "big"), self.d, self.n).to_bytes(
            self.mod_len, "big"
        )

    def test_a_valid_signature_verifies(self):
        message = b"SecureInfo_A body"
        self.assertTrue(
            crypto_verify._rsa_verify_pkcs1v15_sha256(
                message, self._sign(message), self.modulus, self.exponent
            )
        )

    def test_a_changed_message_is_rejected(self):
        signature = self._sign(b"SecureInfo_A body")
        self.assertFalse(
            crypto_verify._rsa_verify_pkcs1v15_sha256(
                b"SecureInfo_B body", signature, self.modulus, self.exponent
            )
        )

    def test_a_flipped_signature_bit_is_rejected(self):
        tampered = bytearray(self._sign(b"body"))
        tampered[-1] ^= 0x01
        self.assertFalse(
            crypto_verify._rsa_verify_pkcs1v15_sha256(
                b"body", bytes(tampered), self.modulus, self.exponent
            )
        )

    def test_a_signature_at_or_above_the_modulus_is_rejected(self):
        self.assertFalse(
            crypto_verify._rsa_verify_pkcs1v15_sha256(
                b"body", self.modulus, self.modulus, self.exponent
            )
        )

    def test_an_all_zero_signature_is_rejected(self):
        self.assertFalse(
            crypto_verify._rsa_verify_pkcs1v15_sha256(
                b"body", b"\x00" * self.mod_len, self.modulus, self.exponent
            )
        )

    def test_padding_shorter_than_eight_bytes_is_rejected(self):
        """A modulus too small to hold the required padding cannot verify."""
        tiny = (1 << 335).to_bytes(42, "big")
        self.assertFalse(
            crypto_verify._rsa_verify_pkcs1v15_sha256(
                b"body", b"\x01" * 42, tiny, self.exponent
            )
        )


@unittest.skipUnless(
    _HAS_AES := (
        shutil.which("openssl") is not None
        or __import__("importlib").util.find_spec("cryptography") is not None
    ),
    "needs openssl or the cryptography package",
)
class AesCbc(unittest.TestCase):
    """NIST SP 800-38A F.2.2 AES-128-CBC vector."""

    KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    CIPHERTEXT = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")
    PLAINTEXT = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")

    def test_the_published_vector_decrypts(self):
        self.assertEqual(
            crypto_verify._aes_128_cbc_decrypt(self.CIPHERTEXT, self.KEY, self.IV),
            self.PLAINTEXT,
        )

    def test_a_different_key_does_not_give_the_plaintext(self):
        other = bytes(self.KEY[:-1]) + bytes([self.KEY[-1] ^ 0x01])
        self.assertNotEqual(
            crypto_verify._aes_128_cbc_decrypt(self.CIPHERTEXT, other, self.IV),
            self.PLAINTEXT,
        )


class KeysFile(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_sections_comments_and_hex_values_are_parsed(self):
        path = self.tmp / "aes_keys.txt"
        path.write_text(
            "# a comment\n"
            "\n"
            ":AES\n"
            "slot0x2CKeyN=00112233445566778899aabbccddeeff\n"
            "  slot0x3DKeyX = ffeeddccbbaa99887766554433221100  \n"
            ":RSA\n"
            "mod=0102\n"
            "not a pair\n"
            "odd_length=abc\n"
        )
        parsed = crypto_verify.parse_keys_file(path)
        self.assertEqual(
            parsed["AES"]["slot0x2CKeyN"],
            bytes.fromhex("00112233445566778899aabbccddeeff"),
        )
        self.assertEqual(parsed["AES"]["slot0x3DKeyX"][:2], b"\xff\xee")
        self.assertEqual(parsed["RSA"]["mod"], b"\x01\x02")
        self.assertNotIn("odd_length", parsed["RSA"])
        self.assertNotIn("not a pair", parsed["RSA"])

    def test_an_empty_file_yields_no_sections(self):
        path = self.tmp / "aes_keys.txt"
        path.write_text("")
        self.assertEqual(crypto_verify.parse_keys_file(path), {})

    def test_the_keys_file_is_found_under_nintendo_3ds(self):
        target = self.tmp / "Nintendo" / "3DS"
        target.mkdir(parents=True)
        (target / "aes_keys.txt").write_text(":AES\n")
        self.assertEqual(
            crypto_verify.find_keys_file(self.tmp), target / "aes_keys.txt"
        )

    def test_the_alternate_name_is_found(self):
        target = self.tmp / "Nintendo" / "3DS"
        target.mkdir(parents=True)
        (target / "keys.txt").write_text(":AES\n")
        self.assertEqual(crypto_verify.find_keys_file(self.tmp), target / "keys.txt")

    def test_absence_reports_none(self):
        self.assertIsNone(crypto_verify.find_keys_file(self.tmp))


if __name__ == "__main__":
    unittest.main()
