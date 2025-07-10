import unittest
import os
from main import encrypt_cfb, decrypt_cfb

class AESCFBTestCase(unittest.TestCase):
    def test_partial_block(self):
        print("\nRunning Test 9: Partial Block (7 bytes)")
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = b"OpenAI!"  # 7 bytes
        ciphertext = encrypt_cfb(plaintext, key, iv)
        decrypted = decrypt_cfb(ciphertext, key, iv)
        self.assertEqual(decrypted, plaintext, "Partial block decryption failed")

    def test_long_plaintext(self):
        print("\nRunning Test 10: Long Plaintext (10,000 bytes)")
        key = os.urandom(16)
        iv = os.urandom(16)
        plaintext = os.urandom(10000)
        ciphertext = encrypt_cfb(plaintext, key, iv)
        decrypted = decrypt_cfb(ciphertext, key, iv)
        self.assertEqual(decrypted, plaintext, "Decryption failed for long input")

    def test_all_zero_input(self):
        print("\nRunning Test 12: All-Zero Input")
        key = b'\x00' * 16
        iv = b'\x00' * 16
        plaintext = b'\x00' * 16
        ciphertext = encrypt_cfb(plaintext, key, iv)
        decrypted = decrypt_cfb(ciphertext, key, iv)
        self.assertEqual(decrypted, plaintext, "Decryption failed for all-zero input")

    def test_01_nist_single_block(self):
        print("\nRunning Test 1: NIST AES-128-CFB single block")
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        expected_ciphertext = bytes.fromhex("3b3fd92eb72dad20333449f8e83cfb4a")

        ciphertext = encrypt_cfb(plaintext, key, iv)
        self.assertEqual(ciphertext, expected_ciphertext)

        decrypted = decrypt_cfb(ciphertext, key, iv)
        self.assertEqual(decrypted, plaintext)

    def test_02_nist_multi_block(self):
        print("\nRunning Test 2: NIST AES-128-CFB multi-block")
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        )
        expected_ciphertext = bytes.fromhex(
            "3b3fd92eb72dad20333449f8e83cfb4a"
            "c8a64537a0b3a93fcde3cdad9f1ce58b"
            "26751f67a3cbb140b1808cf187a4f4df"
            "c04b05357c5d1c0eeac4c66f9ff7f2e6"
        )

        ciphertext = encrypt_cfb(plaintext, key, iv)
        self.assertEqual(ciphertext, expected_ciphertext)

        decrypted = decrypt_cfb(ciphertext, key, iv)
        self.assertEqual(decrypted, plaintext)

    def test_03_empty_plaintext(self):
        print("\nRunning Test 3: Empty Plaintext")
        key = os.urandom(16)
        iv = os.urandom(16)
        plaintext = b""
        ciphertext = encrypt_cfb(plaintext, key, iv)
        self.assertEqual(ciphertext, b"")
        decrypted = decrypt_cfb(ciphertext, key, iv)
        self.assertEqual(decrypted, plaintext)

    def test_04_invalid_key_length(self):
        print("\nRunning Test 4: Invalid Key Length")
        key = os.urandom(15)  # 120 bits
        iv = os.urandom(16)
        plaintext = b"test"
        with self.assertRaises(AssertionError):
            encrypt_cfb(plaintext, key, iv)

    def test_05_invalid_iv_length(self):
        print("\nRunning Test 5: Invalid IV Length")
        key = os.urandom(16)
        iv = os.urandom(15)  # 120 bits
        plaintext = b"test"
        with self.assertRaises(AssertionError):
            encrypt_cfb(plaintext, key, iv)

    def test_06_randomized_round_trip(self):
        print("\nRunning Test 6: Randomized Round Trip")
        for _ in range(10):
            key = os.urandom(16)
            iv = os.urandom(16)
            plaintext = os.urandom(100)
            ciphertext = encrypt_cfb(plaintext, key, iv)
            decrypted = decrypt_cfb(ciphertext, key, iv)
            self.assertEqual(decrypted, plaintext)

    def test_07_same_plaintext_different_iv(self):
        print("\nRunning Test 7: Same Plaintext, Different IV")
        key = os.urandom(16)
        iv1 = os.urandom(16)
        iv2 = os.urandom(16)
        plaintext = b"Important message."
        ciphertext1 = encrypt_cfb(plaintext, key, iv1)
        ciphertext2 = encrypt_cfb(plaintext, key, iv2)
        self.assertNotEqual(ciphertext1, ciphertext2)

    def test_08_different_keys_same_iv(self):
        print("\nRunning Test 8: Different Keys, Same IV")
        key1 = os.urandom(16)
        key2 = os.urandom(16)
        iv = os.urandom(16)
        plaintext = b"Important message."
        ciphertext1 = encrypt_cfb(plaintext, key1, iv)
        ciphertext2 = encrypt_cfb(plaintext, key2, iv)
        self.assertNotEqual(ciphertext1, ciphertext2)

if __name__ == '__main__':
    unittest.main()
