#!/usr/bin/env python3
"""The four 3DS console-unique file verifiers.

verify.py reaches these through a dynamic import in validation.py, and a
signature check that accepts everything is indistinguishable from one that
works. Real console dumps are personal data and cannot be committed, but the
verifiers only ever check structure and signatures, so the artefacts are built
here from the layouts the code parses: the fixture signs with a key it owns
and hands the matching public key in through the keys file, exactly the way a
console's would arrive.

Layouts, from Azahar src/core/hw/unique_data.cpp and src/core/file_sys/otp.cpp:
  SecureInfo_A          0x100 RSA sig + 0x11 body (region, unknown, serial)
  LocalFriendCodeSeed_B 0x100 RSA sig + 0x10 body (unknown, friend code seed)
  movable.sed           "SEED" + 4 + the 0x110 LFCS blob + 8 keyY
  otp.bin               0xE0 body + SHA-256 of that body
"""

from __future__ import annotations

import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import crypto_verify  # noqa: E402
import sect233r1 as ec  # noqa: E402

# A 2048-bit RSA key, the size the 3DS signatures use, from two fixed primes
# so the fixture is reproducible and costs nothing to build.
_P = int(
    "0xC0FFEE" + "0" * 250 + "1234567890ABCF3F".rjust(0, "0"), 16
) if False else 0xC0FFEE0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001234567890ABCF3F
_Q = 0xDEADBEEF0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000FEDCBA9876543B5B
_N = _P * _Q
_E = 65537
_D = pow(_E, -1, (_P - 1) * (_Q - 1))
_MOD = _N.to_bytes(256, "big")
_EXP = _E.to_bytes(3, "big")

_ECC_PRIVATE = 0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01234567
_ECC_NONCE = 0x00FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA


def _rsa_sign(message: bytes) -> bytes:
    """PKCS#1 v1.5 SHA-256 signature, the encoding the verifier expects."""
    prefix = bytes.fromhex("3031300d060960864801650304020105000420")
    digest_info = prefix + hashlib.sha256(message).digest()
    padding = b"\xff" * (256 - len(digest_info) - 3)
    em = b"\x00\x01" + padding + b"\x00" + digest_info
    return pow(int.from_bytes(em, "big"), _D, _N).to_bytes(256, "big")


def _ecdsa_sign(message: bytes) -> bytes:
    g = (ec._Gx, ec._Gy)
    r = ec._ec_mul(_ECC_NONCE, g)[0] % ec._N
    digest = int.from_bytes(hashlib.sha256(message).digest(), "big")
    if 256 > ec._N_BITLEN:
        digest >>= 256 - ec._N_BITLEN
    s = (ec._modinv(_ECC_NONCE, ec._N) * (digest + r * _ECC_PRIVATE)) % ec._N
    return r.to_bytes(30, "big") + s.to_bytes(30, "big")


def _keys(**overrides) -> dict:
    keys = {
        "RSA": {
            "secureInfoMod": _MOD,
            "secureInfoExp": _EXP,
            "lfcsMod": _MOD,
            "lfcsExp": _EXP,
        },
        "AES": {},
        "ECC": {},
    }
    for section, values in overrides.items():
        keys.setdefault(section, {}).update(values)
    return keys


def _secure_info_body(region: int = 1, serial: bytes = b"CW1234567890123") -> bytes:
    return bytes([region]) + b"\x00" + serial[:15].ljust(15, b"\x00")


def _lfcs_body(seed: int = 0x0123456789ABCDEF) -> bytes:
    return b"\x00" * 8 + struct.pack("<Q", seed)


class _Fixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, name: str, data: bytes) -> Path:
        path = self.tmp / name
        path.write_bytes(data)
        return path


class SecureInfoA(_Fixture):
    def _file(self, body: bytes | None = None, sign: bytes | None = None) -> Path:
        body = _secure_info_body() if body is None else body
        return self._write("SecureInfo_A", _rsa_sign(sign or body) + body)

    def test_a_correctly_signed_file_verifies(self):
        ok, reason = crypto_verify.verify_secure_info_a(self._file(), _keys())
        self.assertTrue(ok, reason)
        self.assertEqual(reason, "signature valid")

    def test_wrong_size_is_refused_before_anything_else(self):
        path = self._write("SecureInfo_A", b"\x00" * 100)
        ok, reason = crypto_verify.verify_secure_info_a(path, _keys())
        self.assertFalse(ok)
        self.assertIn("size mismatch", reason)

    def test_an_all_zero_serial_is_refused(self):
        body = bytes([1]) + b"\x00" + b"\x00" * 15
        ok, reason = crypto_verify.verify_secure_info_a(self._file(body), _keys())
        self.assertFalse(ok)
        self.assertIn("serial_number is all zeros", reason)

    def test_missing_keys_are_reported_rather_than_guessed(self):
        keys = _keys()
        keys["RSA"].pop("secureInfoMod")
        ok, reason = crypto_verify.verify_secure_info_a(self._file(), keys)
        self.assertFalse(ok)
        self.assertIn("missing RSA keys", reason)

    def test_a_tampered_serial_fails(self):
        body = _secure_info_body()
        tampered = body[:2] + b"X" + body[3:]
        path = self._write("SecureInfo_A", _rsa_sign(body) + tampered)
        ok, reason = crypto_verify.verify_secure_info_a(path, _keys())
        self.assertFalse(ok)
        self.assertEqual(reason, "signature invalid")

    def test_a_changed_region_is_named_as_such(self):
        """The distinctive check: a signature valid for another region byte."""
        signed = _secure_info_body(region=2)
        shipped = _secure_info_body(region=5)
        path = self._write("SecureInfo_A", _rsa_sign(signed) + shipped)
        ok, reason = crypto_verify.verify_secure_info_a(path, _keys())
        self.assertFalse(ok)
        self.assertIn("region changed from 2 to 5", reason)


class LocalFriendCodeSeedB(_Fixture):
    def _file(self, body: bytes | None = None, sign: bytes | None = None) -> Path:
        body = _lfcs_body() if body is None else body
        return self._write("LocalFriendCodeSeed_B", _rsa_sign(sign or body) + body)

    def test_a_correctly_signed_file_verifies(self):
        ok, reason = crypto_verify.verify_local_friend_code_seed_b(self._file(), _keys())
        self.assertTrue(ok, reason)

    def test_wrong_size_is_refused(self):
        path = self._write("LocalFriendCodeSeed_B", b"\x00" * 0x111)
        ok, reason = crypto_verify.verify_local_friend_code_seed_b(path, _keys())
        self.assertFalse(ok)
        self.assertIn("size mismatch", reason)

    def test_a_zero_friend_code_seed_is_refused(self):
        ok, reason = crypto_verify.verify_local_friend_code_seed_b(
            self._file(_lfcs_body(seed=0)), _keys()
        )
        self.assertFalse(ok)
        self.assertIn("friend_code_seed is zero", reason)

    def test_a_tampered_seed_fails(self):
        body = _lfcs_body()
        path = self._write(
            "LocalFriendCodeSeed_B", _rsa_sign(body) + _lfcs_body(seed=0xDEAD)
        )
        ok, reason = crypto_verify.verify_local_friend_code_seed_b(path, _keys())
        self.assertFalse(ok)
        self.assertEqual(reason, "signature invalid")

    def test_missing_keys_are_reported(self):
        keys = _keys()
        keys["RSA"].pop("lfcsExp")
        ok, reason = crypto_verify.verify_local_friend_code_seed_b(self._file(), keys)
        self.assertFalse(ok)
        self.assertIn("missing RSA keys", reason)


class MovableSed(_Fixture):
    def _file(self, magic: bytes = b"SEED", size: int = 0x120, seed: int | None = None) -> Path:
        body = _lfcs_body() if seed is None else _lfcs_body(seed)
        blob = _rsa_sign(_lfcs_body()) + body
        data = bytearray(size)
        data[0:4] = magic
        data[0x08:0x118] = blob
        return self._write("movable.sed", bytes(data))

    def test_the_short_variant_verifies(self):
        ok, reason = crypto_verify.verify_movable_sed(self._file(), _keys())
        self.assertTrue(ok, reason)
        self.assertIn("magic valid", reason)

    def test_the_long_variant_verifies(self):
        ok, reason = crypto_verify.verify_movable_sed(self._file(size=0x140), _keys())
        self.assertTrue(ok, reason)

    def test_a_wrong_magic_is_refused(self):
        ok, reason = crypto_verify.verify_movable_sed(self._file(magic=b"SEXD"), _keys())
        self.assertFalse(ok)
        self.assertIn("invalid magic", reason)

    def test_an_unexpected_size_is_refused(self):
        path = self._write("movable.sed", b"\x00" * 0x130)
        ok, reason = crypto_verify.verify_movable_sed(path, _keys())
        self.assertFalse(ok)
        self.assertIn("size mismatch", reason)

    def test_a_tampered_embedded_seed_fails_while_the_magic_still_passes(self):
        ok, reason = crypto_verify.verify_movable_sed(self._file(seed=0xBADF00D), _keys())
        self.assertFalse(ok)
        self.assertEqual(reason, "magic valid, LFCS signature invalid")


def _otp_plaintext(
    device_id: int = 0x0A0B0C0D,
    system_type: int = 0,
    otp_version: int = 5,
    expiry: int = 0x50000000,
    sign: bool = True,
) -> bytes:
    """A decrypted OTP whose CTCert signature the fixture's root key made."""
    body = bytearray(0xE0)
    struct.pack_into("<I", body, 0x00, 0xDEADB00F)
    struct.pack_into("<I", body, 0x04, device_id)
    body[0x18] = otp_version
    body[0x19] = system_type
    if otp_version < 5:
        struct.pack_into(">I", body, 0x20, expiry)
    else:
        struct.pack_into("<I", body, 0x20, expiry)
    body[0x24:0x44] = _ECC_PRIVATE.to_bytes(0x20, "big")

    # Rebuild the certificate exactly as the verifier does, then sign it.
    point = ec._ec_mul(_ECC_PRIVATE % ec._N, (ec._Gx, ec._Gy))
    pub_xy = point[0].to_bytes(30, "big") + point[1].to_bytes(30, "big")
    issuer = bytearray(0x40)
    issuer_str = (
        b"Nintendo CA - G3_NintendoCTR2prod"
        if system_type == 0
        else b"Nintendo CA - G3_NintendoCTR2dev"
    )
    issuer[: len(issuer_str)] = issuer_str
    name = bytearray(0x40)
    name_str = f"CT{device_id:08X}-{system_type:02X}".encode()
    name[: len(name_str)] = name_str
    cert = bytes(issuer) + struct.pack(">I", 2) + bytes(name)
    cert += struct.pack(">I", expiry) + pub_xy
    cert = cert.ljust(((len(cert) + 0x3F) // 0x40) * 0x40, b"\x00")

    body[0x44:0x80] = _ecdsa_sign(cert) if sign else bytes(0x3C)
    return bytes(body) + hashlib.sha256(bytes(body)).digest()


def _root_public() -> bytes:
    point = ec._ec_mul(_ECC_PRIVATE, (ec._Gx, ec._Gy))
    return point[0].to_bytes(30, "big") + point[1].to_bytes(30, "big")


class Otp(_Fixture):
    def test_a_decrypted_otp_passes_every_stage(self):
        path = self._write("otp.bin", _otp_plaintext())
        ok, reason = crypto_verify.verify_otp(
            path, _keys(ECC={"rootPublicXY": _root_public()})
        )
        self.assertTrue(ok, reason)
        self.assertIn("ECC cert valid", reason)

    def test_without_a_root_key_the_ecc_stage_is_skipped_not_faked(self):
        path = self._write("otp.bin", _otp_plaintext())
        ok, reason = crypto_verify.verify_otp(path, _keys())
        self.assertTrue(ok)
        self.assertIn("ECC skipped", reason)

    def test_wrong_size_is_refused(self):
        path = self._write("otp.bin", b"\x00" * 0xFF)
        ok, reason = crypto_verify.verify_otp(path, _keys())
        self.assertFalse(ok)
        self.assertIn("size mismatch", reason)

    def test_a_corrupted_body_fails_the_stored_hash(self):
        data = bytearray(_otp_plaintext())
        data[0x30] ^= 0xFF
        path = self._write("otp.bin", bytes(data))
        ok, reason = crypto_verify.verify_otp(path, _keys())
        self.assertFalse(ok)
        self.assertIn("SHA-256 hash mismatch", reason)

    def test_an_unsigned_certificate_is_refused(self):
        path = self._write("otp.bin", _otp_plaintext(sign=False))
        ok, reason = crypto_verify.verify_otp(
            path, _keys(ECC={"rootPublicXY": _root_public()})
        )
        self.assertFalse(ok)
        self.assertIn("ECC cert signature invalid", reason)

    def test_a_certificate_signed_for_another_console_is_refused(self):
        """device_id feeds the signed name, so it cannot be swapped."""
        data = bytearray(_otp_plaintext(device_id=0x0A0B0C0D))
        struct.pack_into("<I", data, 0x04, 0x0A0B0C0E)
        body = bytes(data[:0xE0])
        path = self._write("otp.bin", body + hashlib.sha256(body).digest())
        ok, reason = crypto_verify.verify_otp(
            path, _keys(ECC={"rootPublicXY": _root_public()})
        )
        self.assertFalse(ok)
        self.assertIn("ECC cert signature invalid", reason)

    def test_the_pre_v5_expiry_endianness_is_honoured(self):
        path = self._write("otp.bin", _otp_plaintext(otp_version=4))
        ok, reason = crypto_verify.verify_otp(
            path, _keys(ECC={"rootPublicXY": _root_public()})
        )
        self.assertTrue(ok, reason)

    def test_a_dev_unit_uses_the_dev_issuer(self):
        path = self._write("otp.bin", _otp_plaintext(system_type=1))
        ok, reason = crypto_verify.verify_otp(
            path, _keys(ECC={"rootPublicXY": _root_public()})
        )
        self.assertTrue(ok, reason)

    def test_an_encrypted_otp_without_keys_says_so(self):
        path = self._write("otp.bin", b"\x11" * 0x100)
        ok, reason = crypto_verify.verify_otp(path, _keys())
        self.assertFalse(ok)
        self.assertIn("missing AES keys", reason)


class Dispatch(_Fixture):
    """check_crypto_validation is the entry point verify.py actually calls."""

    def test_an_unknown_filename_is_not_this_module_business(self):
        self.assertIsNone(
            crypto_verify.check_crypto_validation("x", "scph5501.bin", str(self.tmp))
        )

    def test_a_known_filename_without_a_keys_file_does_not_crash(self):
        path = self._write("movable.sed", b"\x00" * 0x120)
        result = crypto_verify.check_crypto_validation(
            str(path), "movable.sed", str(self.tmp)
        )
        self.assertIsInstance(result, (str, type(None)))

    def test_every_verifier_is_reachable_by_its_filename(self):
        self.assertEqual(
            sorted(crypto_verify._CRYPTO_VERIFIERS),
            ["LocalFriendCodeSeed_B", "SecureInfo_A", "movable.sed", "otp.bin"],
        )


if __name__ == "__main__":
    unittest.main()
