import struct
from typing import List

# rol and ror stolen from https://www.falatic.com/index.php/108/python-and-bitwise-rotation
def rol(val, r_bits, *, max_bits=32):
    p1 = (val << r_bits % max_bits) & (2 ** max_bits - 1)
    p2 = (val & (2 ** max_bits - 1)) >> (max_bits - (r_bits % max_bits))
    return p1 | p2


def ror(val, r_bits, *, max_bits=32):
    p1 = (val & (2 ** max_bits - 1)) >> r_bits % max_bits
    p2 = val << (max_bits - (r_bits % max_bits)) & (2 ** max_bits - 1)
    return p1 | p2


def sha224(data: bytes) -> bytes:
    # fmt: off
    H = (
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
    )
    # fmt: on

    return struct.pack(">7L", *_sha2(data, H)[:-1])


GUARD = 0xFFFFFFFF


def sha256(data: bytes) -> bytes:
    # fmt: off
    H = (
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    )
    # fmt: on

    return struct.pack(">8L", *_sha2(data, H))


def _sha2(data: bytes, H: List[int]) -> List[int]:
    # fmt: off
    k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]
    # fmt: on

    ml = len(data) * 8
    buffer = bytearray(data)

    buffer.append(0x80)
    while len(buffer) * 8 % 512 != 448:
        buffer.append(0)

    buffer.extend(struct.pack(">Q", ml))

    assert len(buffer) % 64 == 0

    chunks = [buffer[i : i + 64] for i in range(0, len(buffer), 64)]

    for chunk in chunks:

        w = list(struct.unpack(">16L", chunk)) + [0] * 48

        for i in range(16, 64):
            s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = (w[i - 16] + w[i - 7] + s0 + s1) & GUARD

        a, b, c, d, e, f, g, h = H

        for i in range(64):
            s1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)
            ch = (e & f) ^ ((~e) & g)
            t1 = (h + s1 + ch + k[i] + w[i]) & GUARD
            s0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (s0 + maj) & GUARD

            a, b, c, d, e, f, g, h = ((t1 + t2) & GUARD, a, b, c, (d + t1) & GUARD, e, f, g)

        H = tuple((H[i] + v) & GUARD for i, v in enumerate((a, b, c, d, e, f, g, h)))

    return H
