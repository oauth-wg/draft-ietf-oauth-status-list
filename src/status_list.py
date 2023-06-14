from base64 import b64decode, b64encode
import gzip


class StatusList:
    list: bytearray
    bits: int
    size: int
    divisor: int

    def __init__(self, size: int, bits: int):
        self.divisor = 8 // bits
        self.list = bytearray([0] * (size // self.divisor))
        self.bits = bits
        self.size = size

    @classmethod
    def fromEncoded(cls, encoded: str, bits: int = 1):
        new = cls(0, bits)
        new.decode(encoded)
        return new

    def encode(self) -> str:
        zipped = gzip.compress(self.list)
        return b64encode(zipped).decode()

    def decode(self, input: str):
        zipped = b64decode(input)
        self.list = bytearray(gzip.decompress(zipped))
        self.size = len(self.list) * self.divisor

    def set(self, pos: int, value: int):
        assert value < 2**self.bits
        rest = pos % self.divisor
        floored = pos // self.divisor
        shift = rest * self.bits
        mask = 0xFF ^ (((1 << self.bits) - 1) << shift)
        self.list[floored] = (self.list[floored] & mask) + (value << shift)

    def get(self, pos: int) -> int:
        rest = pos % self.divisor
        floored = pos // self.divisor
        shift = rest * self.bits
        return (self.list[floored] & (((1 << self.bits) - 1) << shift)) >> shift

    def __str__(self):
        val = ""
        for x in range(0, self.size):
            val = val + format(self.get(x), "x")
        return val
