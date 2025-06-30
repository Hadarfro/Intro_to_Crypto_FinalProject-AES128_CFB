# AES constants
Nb = 4
Nk = 4
Nr = 10

Sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]


Rcon = [
    0x00, 0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
]

def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = Sbox[state[i][j]]
    return state

def shift_rows(state):
    state[1][0], state[1][1], state[1][2], state[1][3] = \
        state[1][1], state[1][2], state[1][3], state[1][0]
    state[2][0], state[2][1], state[2][2], state[2][3] = \
        state[2][2], state[2][3], state[2][0], state[2][1]
    state[3][0], state[3][1], state[3][2], state[3][3] = \
        state[3][3], state[3][0], state[3][1], state[3][2]
    return state

def xtime(a):
    return ((a << 1) ^ 0x1b) & 0xff if (a & 0x80) else (a << 1)

def mix_single_column(a):
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)
    return a

def mix_columns(state):
    for i in range(4):
        col = [state[j][i] for j in range(4)]
        col = mix_single_column(col)
        for j in range(4):
            state[j][i] = col[j]
    return state

def add_round_key(state, key_schedule, round_num):
    for col in range(4):
        for row in range(4):
            state[row][col] ^= key_schedule[round_num * 4 + col][row]
    return state

def key_expansion(key):
    Rcon = [
        0x00, 0x01, 0x02, 0x04, 0x08,
        0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    ]
    key_schedule = [list(key[i:i+4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = key_schedule[i - 1][:]
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]  # RotWord
            temp = [Sbox[b] for b in temp]  # SubWord
            temp[0] ^= Rcon[i // 4]
        word = [a ^ b for a, b in zip(key_schedule[i - 4], temp)]
        key_schedule.append(word)
    return key_schedule

def cipher(input_bytes, key_schedule):
    # Build 4x4 state matrix in column-major order
    state = [[0] * 4 for _ in range(4)]
    for i in range(16):
        state[i % 4][i // 4] = input_bytes[i]

    # Initial round
    state = add_round_key(state, key_schedule, 0)

    # Rounds 1 to 9
    for round in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, key_schedule, round)

    # Final round (without mix_columns)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, key_schedule, 10)

    # Convert state matrix back to 16-byte output in column-major order
    output = bytearray(16)
    for col in range(4):
        for row in range(4):
            output[4 * col + row] = state[row][col]

    return bytes(output)

def xor_bytes(a, b):
    return bytes(i ^ j for i, j in zip(a, b))

# -----------------------
# AES-128 CFB mode logic
# -----------------------
def aes_128_encrypt_block(block, key_schedule):
    return cipher(block, key_schedule)

def encrypt_cfb(plaintext, key, iv):
    assert len(key) == 16 and len(iv) == 16
    key_schedule = key_expansion(key)
    ciphertext = b''
    prev = iv
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16].ljust(16, b'\x00')
        encrypted = aes_128_encrypt_block(prev, key_schedule)
        cipher_block = xor_bytes(block, encrypted)
        ciphertext += cipher_block[:len(plaintext[i:i+16])]
        prev = cipher_block
    return ciphertext

def decrypt_cfb(ciphertext, key, iv):
    assert len(key) == 16 and len(iv) == 16
    key_schedule = key_expansion(key)
    plaintext = b''
    prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16].ljust(16, b'\x00')
        encrypted = aes_128_encrypt_block(prev, key_schedule)
        plain_block = xor_bytes(block, encrypted)
        plaintext += plain_block[:len(ciphertext[i:i+16])]
        prev = block
    return plaintext

def main():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    expected_ciphertext = bytes.fromhex("3b3fd92eb72dad20333449f8e83cfb4a")

    ciphertext = encrypt_cfb(plaintext, key, iv)

    print("Ciphertext (hex):", ciphertext.hex())
    print("Matches expected:", ciphertext == expected_ciphertext)

    decrypted = decrypt_cfb(ciphertext, key, iv)
    print("Decrypted:", decrypted.hex())
    print("Matches original:", decrypted == plaintext)

def run_aes_cfb_tests():
    test_vectors = [
        {
            "key": "2b7e151628aed2a6abf7158809cf4f3c",
            "iv": "000102030405060708090a0b0c0d0e0f",
            "plaintext": "6bc1bee22e409f96e93d7e117393172a",
            "expected_ciphertext": "3b3fd92eb72dad20333449f8e83cfb4a",
            "description": "NIST AES-128-CFB single block test"
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
            "description": "NIST AES-128-CFB multi-block test"
        }
    ]

    for idx, vector in enumerate(test_vectors, 1):
        print(f"Running Test #{idx}: {vector['description']}")

        key = bytes.fromhex(vector["key"])
        iv = bytes.fromhex(vector["iv"])
        plaintext = bytes.fromhex(vector["plaintext"])
        expected_ciphertext = bytes.fromhex(vector["expected_ciphertext"])

        # Encrypt
        ciphertext = encrypt_cfb(plaintext, key, iv)
        encrypt_pass = ciphertext == expected_ciphertext

        # Decrypt
        decrypted = decrypt_cfb(ciphertext, key, iv)
        decrypt_pass = decrypted == plaintext

        print(f"  Encryption correct? {'PASS' if encrypt_pass else 'FAIL'}")
        print(f"  Decryption correct? {'PASS' if decrypt_pass else 'FAIL'}")

        if not encrypt_pass:
            print(f"  Expected ciphertext: {expected_ciphertext.hex()}")
            print(f"  Actual ciphertext:   {ciphertext.hex()}")

        if not decrypt_pass:
            print(f"  Expected plaintext: {plaintext.hex()}")
            print(f"  Actual plaintext:   {decrypted.hex()}")

        print("-" * 50)

if __name__ == "__main__":
    run_aes_cfb_tests()


if __name__ == '__main__':
    main()