"""otp.bin decrypts with the standard library alone.

The build promises stdlib + pyyaml. AES needed cryptography, pycryptodome
or an openssl binary, and verify.py raised RuntimeError on otp.bin for a
contributor with none of them.
"""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import crypto_verify  # noqa: E402

STDLIB_OR_LOCAL = {"__future__", "hashlib", "struct", "collections", "pathlib", "sect233r1"}


class StdlibAes(unittest.TestCase):
    def test_fips_197_vector(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        cipher = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        plain = crypto_verify._decrypt_block(cipher, crypto_verify._expand_key(key))
        self.assertEqual(plain.hex(), "00112233445566778899aabbccddeeff")

    def test_cbc_chains_blocks(self):
        # NIST SP 800-38A F.2.2, CBC-AES128 decrypt, first two blocks.
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        cipher = bytes.fromhex(
            "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
        )
        self.assertEqual(
            crypto_verify._aes_128_cbc_decrypt(cipher, key, iv).hex(),
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
        )

    def test_no_third_party_import(self):
        tree = ast.parse((REPO_ROOT / "scripts" / "crypto_verify.py").read_text())
        modules = {
            (node.module if isinstance(node, ast.ImportFrom) else alias.name).split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertLessEqual(modules, STDLIB_OR_LOCAL)


if __name__ == "__main__":
    unittest.main()
