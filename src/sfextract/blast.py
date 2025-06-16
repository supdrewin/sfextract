# Conversion from the original blast.c code found here:
# https://github.com/madler/zlib/blob/master/contrib/blast/blast.c
# Python specific optimizations added by gdesmar

import os
from io import BytesIO

MAXBITS = 13  # Maximum code length
MAXWIN = 4096  # Maximum window size


class BitReader:
    def __init__(self, f):
        self.input = f
        self.accumulator = ord(self.input.read(1))
        self.bitconsumed = 0

    def readbit(self):
        if self.bitconsumed == 8:
            self.accumulator = ord(self.input.read(1))
            self.bitconsumed = 0
        rv = (self.accumulator >> self.bitconsumed) & 1
        self.bitconsumed += 1
        return rv

    def readbits_plus(self, n):
        v = 0
        for i in range(n):
            v |= self.readbit() << i
        return v

    def readbits(self, n):
        if n == 0:
            return 0
        if n == 1:
            return self.readbit()
        if n == 8 and self.bitconsumed == 8:
            return ord(self.input.read(1))
        if n < 8 - self.bitconsumed:
            v = (self.accumulator >> self.bitconsumed) & (2**n - 1)
            self.bitconsumed += n
            return v
        if n > 8:
            return self.readbits_plus(n)
        v = self.accumulator >> self.bitconsumed
        self.accumulator = ord(self.input.read(1))
        more = n - (8 - self.bitconsumed)
        v |= (self.accumulator & (2**more - 1)) << (n - more)
        self.bitconsumed = more
        return v


class Huffman:
    def __init__(self, size):
        self.count = [0] * (MAXBITS + 1)
        self.symbol = [0] * size


def construct_huffman(h: Huffman, rep):
    n = len(rep)
    symbol = 0
    length = [0] * 256

    for _ in range(n):
        byte = rep.pop(0)
        count = (byte >> 4) + 1
        len_value = byte & 0x0F

        for _ in range(count):
            length[symbol] = len_value
            symbol += 1

    n = symbol

    for len_value in range(MAXBITS + 1):
        h.count[len_value] = 0

    for sym in range(n):
        h.count[length[sym]] += 1

    if h.count[0] == n:
        raise Exception("No code found. Huffman table would be complete, but decoding will fail.")

    left = 1
    for len_value in range(1, MAXBITS + 1):
        left <<= 1
        left -= h.count[len_value]
        if left < 0:
            raise Exception(f"Over-subscribed set of length in Huffman table construction: {left}.")

    offs = [0] * (MAXBITS + 1)
    offs[1] = 0
    for len_value in range(1, MAXBITS):
        offs[len_value + 1] = offs[len_value] + h.count[len_value]

    for sym in range(n):
        if length[sym] != 0:
            h.symbol[offs[length[sym]]] = sym
            offs[length[sym]] += 1

    # Remove first count since we do not need it in decode_symbol
    h.count.pop(0)
    return left


def decode_symbol(s, h):
    len_bits = code = first = count = index = 0

    while True:
        code |= s.readbit() ^ 1
        count = h.count[len_bits]
        if code < first + count:
            return h.symbol[index + (code - first)]
        index += count
        first += count
        first <<= 1
        code <<= 1
        len_bits += 1


# Huffman decoding setup
lit_table = Huffman(256)
len_table = Huffman(16)
dist_table = Huffman(64)

# Bit length arrays
# fmt: off
lit_lengths = [
    11, 124, 8, 7, 28, 7, 188, 13, 76, 4, 10, 8, 12, 10, 12, 10, 8, 23, 8,
    9, 7, 6, 7, 8, 7, 6, 55, 8, 23, 24, 12, 11, 7, 9, 11, 12, 6, 7, 22, 5,
    7, 24, 6, 11, 9, 6, 7, 22, 7, 11, 38, 7, 9, 8, 25, 11, 8, 11, 9, 12,
    8, 12, 5, 38, 5, 38, 5, 11, 7, 5, 6, 21, 6, 10, 53, 8, 7, 24, 10, 27,
    44, 253, 253, 253, 252, 252, 252, 13, 12, 45, 12, 45, 12, 61, 12, 45,
    44, 173
]
# fmt: on
len_lengths = [2, 35, 36, 53, 38, 23]
dist_lengths = [2, 20, 53, 230, 247, 151, 248]
length_base = [3, 2, 4, 5, 6, 7, 8, 9, 10, 12, 16, 24, 40, 72, 136, 264]
length_extra = [0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]


construct_huffman(lit_table, lit_lengths)
construct_huffman(len_table, len_lengths)
construct_huffman(dist_table, dist_lengths)


def decompress(compressedstring):
    # Header: First byte = lit flag, second byte = dictionary size (log base 2 minus 6)
    literals_coded = compressedstring[0]
    dict_size = compressedstring[1]

    if literals_coded > 1 or dict_size < 4 or dict_size > 6:
        raise ValueError("Invalid header in compressed data")

    s = BitReader(BytesIO(compressedstring[2:]))
    output = BytesIO()

    try:
        while True:
            if s.readbit():  # Length/Distance pair
                length_sym = decode_symbol(s, len_table)
                length = length_base[length_sym] + s.readbits(length_extra[length_sym])
                if length == 519:
                    return output.getvalue()

                symbol = 2 if length == 2 else dict_size
                distance = decode_symbol(s, dist_table) << symbol
                distance += s.readbits(symbol)
                distance += 1

                output.seek(-distance, os.SEEK_CUR)
                data = output.read(length)
                output.seek(0, os.SEEK_END)
                output.write((data * (length // len(data) + 1))[:length])
            else:  # Literal
                if literals_coded:
                    literal = decode_symbol(s, lit_table)
                else:
                    literal = s.readbits(8)
                output.write(literal.to_bytes())
    except EOFError:
        # Write any remaining output?
        return output.getvalue()
