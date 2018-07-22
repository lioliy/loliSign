import base64
import datetime
import math
import time

"""s_box is pre-computed multiplicative inverse in GF(2^8) used in SubBytes and KeyExpansion [§5.1.1]"""
s_box = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

"""r_con is Round Constant used for the Key Expansion [1st col is 2^(r-1) in GF(2^8)] [§5.2]"""
r_con = [
    [0x00, 0x00, 0x00, 0x00],
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1b, 0x00, 0x00, 0x00],
    [0x36, 0x00, 0x00, 0x00]
]


def cipher(input_, w):
    nb = 4
    nr = int(len(w) / nb - 1)

    state = [[0] * nb, [0] * nb, [0] * nb, [0] * nb]
    for i in range(0, 4 * nb):
        state[i % 4][i // 4] = input_[i]

    state = add_round_key(state, w, 0, nb)

    for round_ in range(1, nr):
        state = sub_bytes(state, nb)
        state = shift_rows(state, nb)
        state = mix_columns(state, nb)
        state = add_round_key(state, w, round_, nb)

    state = sub_bytes(state, nb)
    state = shift_rows(state, nb)
    state = add_round_key(state, w, nr, nb)

    output = [0] * 4 * nb
    for i in range(4 * nb):
        output[i] = state[i % 4][i // 4]
    return output


def sub_bytes(s, nb):
    for r in range(4):
        for c in range(nb):
            s[r][c] = s_box[s[r][c]]
    return s


def shift_rows(s, nb):
    t = [0] * 4
    for r in range(1, 4):
        for c in range(4):
            t[c] = s[r][(c + r) % nb]
        for c in range(4):
            s[r][c] = t[c]
    return s


# noinspection PyUnusedLocal
def mix_columns(s, nb_in):
    for c in range(4):
        a = [0] * 4
        b = [0] * 4
        for i in range(4):
            a[i] = s[i][c]
            b[i] = s[i][c] << 1 ^ 0x011b if s[i][c] & 0x80 else s[i][c] << 1
        s[0][c] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3]
        s[1][c] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3]
        s[2][c] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3]
        s[3][c] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3]
    return s


def add_round_key(state, w, rnd, nb):
    for r in range(4):
        for c in range(nb):
            state[r][c] ^= w[rnd * 4 + c][r]
    return state


def key_expansion(key):
    nb = 4
    nk = int(len(key) / 4)
    nr = nk + 6

    w = [0] * nb * (nr + 1)
    temp = [0] * 4

    for i in range(nk):
        r = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]
        w[i] = r

    for i in range(nk, nb * (nr + 1)):
        w[i] = [0] * 4
        for t in range(4):
            temp[t] = w[i - 1][t]
        if i % nk == 0:
            temp = sub_word(rot_word(temp))
            for t in range(4):
                temp[t] ^= r_con[int(i / nk)][t]
        elif nk > 6 and i % nk == 4:
            temp = sub_word(temp)
        for t in range(4):
            w[i][t] = w[i - nk][t] ^ temp[t]
    return w


def sub_word(w):
    for i in range(4):
        w[i] = s_box[w[i]]
    return w


def rot_word(w):
    tmp = w[0]
    for i in range(3):
        w[i] = w[i + 1]
    w[3] = tmp
    return w


def encrypt(plaintext, password, n_bits):
    block_size = 16
    if not (n_bits in (128, 192, 256)):
        return ""

    n_bytes = n_bits // 8
    pw_bytes = [0] * n_bytes

    for i in range(n_bytes):
        pw_bytes[i] = 0 if i >= len(password) else ord(password[i])

    key = cipher(pw_bytes, key_expansion(pw_bytes))
    key += key[:n_bytes - 16]

    counter_block = [0] * block_size
    now = datetime.datetime.now()
    nonce = time.mktime(now.timetuple()) * 1000 + now.microsecond // 1000
    nonce_sec = int(nonce // 1000)
    nonce_ms = int(nonce % 1000)

    for i in range(4):
        counter_block[i] = urs(nonce_sec, i * 8) & 0xff

    for i in range(4):
        counter_block[i + 4] = nonce_ms & 0xff

    ctr_txt = ""
    for i in range(8):
        ctr_txt += chr(counter_block[i])

    key_schedule = key_expansion(key)

    block_count = int(math.ceil(float(len(plaintext)) / float(block_size)))
    cipher_txt = [0] * block_count

    for b in range(block_count):
        for c in range(4):
            counter_block[15 - c] = urs(b, c * 8) & 0xff

        for c in range(4):
            counter_block[15 - c - 4] = urs(b / 0x100000000, c * 8)

        cipher_counter = cipher(counter_block, key_schedule)

        block_length = block_size if b < block_count - 1 else (len(plaintext) - 1) % block_size + 1
        cipher_char = [0] * block_length

        for i in range(block_length):
            cipher_char[i] = cipher_counter[i] ^ ord(plaintext[b * block_size + i])
            cipher_char[i] = chr(cipher_char[i])
        cipher_txt[b] = ''.join(cipher_char)

    cipher_text = ctr_txt + ''.join(cipher_txt)
    cipher_text = base64.b64encode(cipher_text.encode("latin"))

    return cipher_text


# noinspection PyTypeChecker
def decrypt(cipher_text, password, n_bits):
    block_size = 16

    if not (n_bits in (128, 192, 256)):
        return ""
    cipher_text = base64.b64decode(cipher_text).decode("latin")

    n_bytes = n_bits // 8
    pw_bytes = [0] * n_bytes
    for i in range(n_bytes):
        pw_bytes[i] = 0 if i >= len(password) else ord(password[i])

    key = cipher(pw_bytes, key_expansion(pw_bytes))
    key += key[:n_bytes - 16]

    counter_block = [0] * block_size
    ctr_txt = cipher_text[:8]

    for i in range(8):
        counter_block[i] = ord(ctr_txt[i])

    key_schedule = key_expansion(key)

    n_blocks = int(math.ceil(float(len(cipher_text) - 8) / float(block_size)))
    ct = [0] * n_blocks

    for b in range(n_blocks):
        ct[b] = cipher_text[8 + b * block_size: 8 + b * block_size + block_size]
    cipher_text = ct

    plain_txt = [0] * len(cipher_text)

    for b in range(n_blocks):
        for c in range(4):
            counter_block[15 - c] = urs(b, c * 8) & 0xff
        for c in range(4):
            counter_block[15 - c - 4] = urs(int(float(b + 1) / 0x100000000 - 1), c * 8) & 0xff

        cipher_counter = cipher(counter_block, key_schedule)
        plain_txt_byte = [0] * len(cipher_text[b])

        for i in range(len(cipher_text[b])):
            plain_txt_byte[i] = cipher_counter[i] ^ ord(cipher_text[b][i])
            plain_txt_byte[i] = chr(plain_txt_byte[i])

        plain_txt[b] = "".join(plain_txt_byte)

    plaintext = "".join(plain_txt)
    #   plaintext = plaintext.decode("utf-8")
    return plaintext


def urs(a, b):
    a, b = int(a), int(b)
    a &= 0xffffffff
    b &= 0x1f

    if a & 0x80000000 and b > 0:
        a = (a >> 1) & 0x7fffffff
        a = a >> (b - 1)
    else:
        a = (a >> b)
    return a
