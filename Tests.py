import unittest
import os
from binascii import unhexlify

from main import (
    encrypt_cfb, decrypt_cfb,
    mix_columns, key_expansion, mix_single_column,
    shift_rows, sub_bytes, Sbox, aes_128_encrypt_block, add_round_key
)
class Invalid_Input_TestCase(unittest.TestCase):
    def test_invalid_key_length(self):
        # Key must be 16 bytes
        key = os.urandom(15)  # Invalid length
        iv = os.urandom(16)
        plaintext = b"test"
        with self.assertRaises(AssertionError):
            encrypt_cfb(plaintext, key, iv)

    def test_invalid_iv_length(self):
        # IV must be 16 bytes
        key = os.urandom(16)
        iv = os.urandom(15)  # Invalid length
        plaintext = b"test"
        with self.assertRaises(AssertionError):
            encrypt_cfb(plaintext, key, iv)


# -------------------------------
# Test AES-CFB Mode Functionality
# -------------------------------
class AES128_with_CFBmode_TestCase(unittest.TestCase):

    def test_partial_block(self):
        # Partial block encryption and decryption (not 16 bytes)
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = b"HELLO!!"  # 7 bytes
        ciphertext = encrypt_cfb(plaintext, key, iv)
        decrypted = decrypt_cfb(ciphertext, key, iv)
        self.assertEqual(decrypted, plaintext)

    def test_long_plaintext(self):
        # Very long plaintext (10,000 bytes)
        key = os.urandom(16)
        iv = os.urandom(16)
        plaintext = os.urandom(10000)
        ciphertext = encrypt_cfb(plaintext, key, iv)
        decrypted = decrypt_cfb(ciphertext, key, iv)
        self.assertEqual(decrypted, plaintext)

    def test_all_zero_input(self):
        # Input filled with zero bytes
        key = b'\x00' * 16
        iv = b'\x00' * 16
        plaintext = b'\x00' * 16
        ciphertext = encrypt_cfb(plaintext, key, iv)
        decrypted = decrypt_cfb(ciphertext, key, iv)
        self.assertEqual(decrypted, plaintext)

    def test_empty_plaintext(self):
        # No input should produce no output
        key = os.urandom(16)
        iv = os.urandom(16)
        plaintext = b""
        ciphertext = encrypt_cfb(plaintext, key, iv)
        self.assertEqual(ciphertext, b"")
        decrypted = decrypt_cfb(ciphertext, key, iv)
        self.assertEqual(decrypted, plaintext)


    def test_randomized_round_trip(self):
        # Random inputs should round-trip successfully
        for _ in range(10):
            key = os.urandom(16)
            iv = os.urandom(16)
            plaintext = os.urandom(100)
            ciphertext = encrypt_cfb(plaintext, key, iv)
            decrypted = decrypt_cfb(ciphertext, key, iv)
            self.assertEqual(decrypted, plaintext)

    def test_same_plaintext_different_iv(self):
        # Same input, different IV → different output
        key = os.urandom(16)
        iv1 = os.urandom(16)
        iv2 = os.urandom(16)
        plaintext = b"Important message."
        ct1 = encrypt_cfb(plaintext, key, iv1)
        ct2 = encrypt_cfb(plaintext, key, iv2)
        self.assertNotEqual(ct1, ct2)

    def test_different_keys_same_iv(self):
        # Different keys → different ciphertext
        key1 = os.urandom(16)
        key2 = os.urandom(16)
        iv = os.urandom(16)
        plaintext = b"Important message."
        ct1 = encrypt_cfb(plaintext, key1, iv)
        ct2 = encrypt_cfb(plaintext, key2, iv)
        self.assertNotEqual(ct1, ct2)

    def test_reused_iv_same_ciphertext(self):
        # Encrypt same input twice → same result
        key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
        iv = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        plaintext = b"same input for both cases"
        ct1 = encrypt_cfb(plaintext, key, iv)
        ct2 = encrypt_cfb(plaintext, key, iv)
        self.assertEqual(ct1, ct2)

    def test_utf8_unicode_plaintext(self):
        # Encrypt and decrypt UTF-8 encoded Unicode
        key = bytes.fromhex('603deb1015ca71be2b73aef0857d7781')
        iv = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        plaintext = "שלום".encode('utf-8')
        ciphertext = encrypt_cfb(plaintext, key, iv)
        decrypted = decrypt_cfb(ciphertext, key, iv)
        self.assertEqual(decrypted, plaintext)

    def test_ciphertext_differs_on_similar_prefixes(self):
        # Similar messages should produce different ciphertexts
        key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
        iv = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        ct1 = encrypt_cfb(b"Hello world!", key, iv)
        ct2 = encrypt_cfb(b"Hello there!", key, iv)
        self.assertNotEqual(ct1, ct2)

    def test_non_block_aligned_lengths(self):
        # Random lengths not multiples of 16
        for length in [17, 31, 48]:
            key = os.urandom(16)
            iv = os.urandom(16)
            plaintext = os.urandom(length)
            ciphertext = encrypt_cfb(plaintext, key, iv)
            decrypted = decrypt_cfb(ciphertext, key, iv)
            self.assertEqual(decrypted, plaintext)

    def setUp(self):
        self.test_vectors = [
            {
                "key": "2b7e151628aed2a6abf7158809cf4f3c",
                "iv": "000102030405060708090a0b0c0d0e0f",
                "plaintext": "6bc1bee22e409f96e93d7e117393172a",
                "expected_ciphertext": "3b3fd92eb72dad20333449f8e83cfb4a",
                "description": "NIST AES-128-CFB single block"
            },
            {
                "key": "2b7e151628aed2a6abf7158809cf4f3c",
                "iv": "000102030405060708090a0b0c0d0e0f",
                "plaintext": (
                    "6bc1bee22e409f96e93d7e117393172a"
                    "ae2d8a571e03ac9c9eb76fac45af8e51"
                    "30c81c46a35ce411e5fbc1191a0a52ef"
                    "f69f2445df4f9b17ad2b417be66c3710"
                ),
                "expected_ciphertext": (
                    "3b3fd92eb72dad20333449f8e83cfb4a"
                    "c8a64537a0b3a93fcde3cdad9f1ce58b"
                    "26751f67a3cbb140b1808cf187a4f4df"
                    "c04b05357c5d1c0eeac4c66f9ff7f2e6"
                ),
                "description": "NIST AES-128-CFB multi-block"
            }
        ]

    def test_encrypt_and_decrypt_vectors(self):
        for idx, vector in enumerate(self.test_vectors, 1):
            with self.subTest(vector=vector["description"]):
                key = hex2bytes(vector["key"])
                iv = hex2bytes(vector["iv"])
                plaintext = hex2bytes(vector["plaintext"])
                expected_ciphertext = hex2bytes(vector["expected_ciphertext"])

                ciphertext = encrypt_cfb(plaintext, key, iv)
                decrypted = decrypt_cfb(ciphertext, key, iv)

                self.assertEqual(ciphertext, expected_ciphertext,
                                 f"\n❌ Encryption failed:\nExpected: {expected_ciphertext.hex()}\nGot     : {ciphertext.hex()}")

                self.assertEqual(decrypted, plaintext,
                                 f"\n❌ Decryption failed:\nExpected: {plaintext.hex()}\nGot     : {decrypted.hex()}")


# ---NIST Vector Parsing & Test---

VECTORS_DIR = "nist_vectors_cfb"

def parse_rsp_file(filepath):
    with open(filepath, 'r') as f:
        lines = f.readlines()

    mode = None
    tests = {"ENCRYPT": [], "DECRYPT": []}
    current = {}

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[ENCRYPT]"):
            mode = "ENCRYPT"
            continue
        if line.startswith("[DECRYPT]"):
            mode = "DECRYPT"
            continue
        if line.startswith("COUNT"):
            if current:
                tests[mode].append(current)
            current = {"COUNT": int(line.split('=')[1])}
        elif "=" in line:
            key, value = line.split("=")
            current[key.strip()] = value.strip()
    if current:
        tests[mode].append(current)
    return tests

def run_test_case_vector(test, mode):
    key = unhexlify(test["KEY"])
    iv = unhexlify(test["IV"])
    plaintext = unhexlify(test["PLAINTEXT"])
    ciphertext = unhexlify(test["CIPHERTEXT"])

    if mode == "ENCRYPT":
        result = encrypt_cfb(plaintext, key, iv)
        expected = ciphertext
    else:
        result = decrypt_cfb(ciphertext, key, iv)
        expected = plaintext

    return result, expected

class NISTVectors_TestCase(unittest.TestCase):
    def test_all_vectors(self):
        total_tests = 0
        for filename in os.listdir(VECTORS_DIR):
            if not filename.endswith(".rsp"):
                continue
            filepath = os.path.join(VECTORS_DIR, filename)
            vectors = parse_rsp_file(filepath)

            for mode in ["ENCRYPT", "DECRYPT"]:
                for test in vectors[mode]:
                    total_tests += 1
                    with self.subTest(file=filename, mode=mode, count=test["COUNT"]):
                        result, expected = run_test_case_vector(test, mode)
                        self.assertEqual(result, expected)
        print(f"\n✅ Total NIST vector tests run: {total_tests}")


# --------------------------
# AES + Internal AES Function Tests
# --------------------------

class AESTestCase(unittest.TestCase):

    def test_encrypt_block(self):
        # Example from FIPS-197 Appendix B (official AES spec)
        plaintext = hex2bytes("00112233445566778899aabbccddeeff")
        key = hex2bytes("000102030405060708090a0b0c0d0e0f")
        expected_ciphertext = hex2bytes("69c4e0d86a7b0430d8cdb78070b4c55a")

        round_keys = key_expansion(key)
        ciphertext = aes_128_encrypt_block(plaintext, round_keys)

        self.assertEqual(ciphertext, expected_ciphertext)

    def transpose_key_schedule(self, words):
        return [[words[col][row] for col in range(4)] for row in range(4)]

    def test_sub_bytes(self):
        input_state = [
            [0x19, 0xa0, 0x9a, 0xe9],
            [0x3d, 0xf4, 0xc6, 0xf8],
            [0xe3, 0xe2, 0x8d, 0x48],
            [0xbe, 0x2b, 0x2a, 0x08],
        ]
        expected = [[Sbox[b] for b in row] for row in input_state]
        result = sub_bytes([row[:] for row in input_state])
        self.assertEqual(result, expected)

    def test_shift_rows(self):
        input_state = [
            [0xd4, 0xe0, 0xb8, 0x1e],
            [0xbf, 0xb4, 0x41, 0x27],
            [0x5d, 0x52, 0x11, 0x98],
            [0x30, 0xae, 0xf1, 0xe5],
        ]
        expected = [
            [0xd4, 0xe0, 0xb8, 0x1e],
            [0xb4, 0x41, 0x27, 0xbf],
            [0x11, 0x98, 0x5d, 0x52],
            [0xe5, 0x30, 0xae, 0xf1],
        ]
        result = shift_rows([row[:] for row in input_state])
        self.assertEqual(result, expected)

    def test_mix_single_column(self):
        col = [0xdb, 0x13, 0x53, 0x45]
        expected = [0x8e, 0x4d, 0xa1, 0xbc]
        result = mix_single_column(col[:])
        self.assertEqual(result, expected)

    def test_mix_columns(self):
        input_state = [
            [0xdb, 0xf2, 0x01, 0xc6],
            [0x13, 0x0a, 0x01, 0xc6],
            [0x53, 0x22, 0x01, 0xc6],
            [0x45, 0x5c, 0x01, 0xc6],
        ]
        expected = [
            [0x8e, 0x9f, 0x01, 0xc6],
            [0x4d, 0xdc, 0x01, 0xc6],
            [0xa1, 0x58, 0x01, 0xc6],
            [0xbc, 0x9d, 0x01, 0xc6],
        ]
        result = mix_columns([row[:] for row in input_state])
        self.assertEqual(result, expected)

    def test_key_expansion_last_round_key(self):
        key = unhexlify("2b7e151628aed2a6abf7158809cf4f3c")
        expanded = key_expansion(key)
        expected_last = [
            [0xd0, 0xc9, 0xe1, 0xb6],
            [0x14, 0xee, 0x3f, 0x63],
            [0xf9, 0x25, 0x0c, 0x0c],
            [0xa8, 0x89, 0xc8, 0xa6],
        ]
        last_words = expanded[40:44]
        last_matrix = self.transpose_key_schedule(last_words)
        self.assertEqual(last_matrix, expected_last)

    def test_add_round_key(self):
        state = [
            [0x32, 0x88, 0x31, 0xe0],
            [0x43, 0x5a, 0x31, 0x37],
            [0xf6, 0x30, 0x98, 0x07],
            [0xa8, 0x8d, 0xa2, 0x34],
        ]

        key_schedule = [
            [0x2b, 0x7e, 0x15, 0x16],
            [0x28, 0xae, 0xd2, 0xa6],
            [0xab, 0xf7, 0x15, 0x88],
            [0x09, 0xcf, 0x4f, 0x3c],
        ]

        round_num = 0

        result = add_round_key([row[:] for row in state], key_schedule, round_num)

        expected = [
            [0x32 ^ 0x2b, 0x88 ^ 0x28, 0x31 ^ 0xab, 0xe0 ^ 0x09],
            [0x43 ^ 0x7e, 0x5a ^ 0xae, 0x31 ^ 0xf7, 0x37 ^ 0xcf],
            [0xf6 ^ 0x15, 0x30 ^ 0xd2, 0x98 ^ 0x15, 0x07 ^ 0x4f],
            [0xa8 ^ 0x16, 0x8d ^ 0xa6, 0xa2 ^ 0x88, 0x34 ^ 0x3c],
        ]

        self.assertEqual(result, expected)


# Helper function to convert hex strings to bytes
def hex2bytes(s):
    return bytes.fromhex(s)


if __name__ == "__main__":
    unittest.main()
