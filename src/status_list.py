import zlib
from base64 import urlsafe_b64decode, urlsafe_b64encode
from typing import Dict

from cbor2 import dumps, loads


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

    def encodeAsString(self) -> str:
        zipped = zlib.compress(self.list, level=9)
        return urlsafe_b64encode(zipped).decode().strip("=")

    def encodeAsBytes(self) -> bytes:
        return zlib.compress(self.list, level=9)

    def encodeAsJSON(self) -> Dict:
        encoded_list = self.encodeAsString()
        object = {
            "bits": self.bits,
            "lst": encoded_list,
        }
        return object

    def encodeAsCBOR(self) -> Dict:
        encoded_list = self.encodeAsBytes()
        object = {
            "bits": self.bits,
            "lst": encoded_list,
        }
        return object

    def encodeAsCBORRaw(self) -> Dict:
        object = self.encodeAsCBOR()
        return dumps(object)

    def decode(self, input: str):
        zipped = urlsafe_b64decode(f"{input}{'=' * divmod(len(input),4)[1]}")
        self.list = bytearray(zlib.decompress(zipped))
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
        return val
