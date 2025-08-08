import math
import zlib
from base64 import urlsafe_b64decode, urlsafe_b64encode
from typing import Dict

import brotli
from cbor2 import dumps

ALG_ZLIB = "zlib"
ALG_BROTLI = "brotli"

LEVEL_ZLIB = 9
LEVEL_BROTLI = 11


class StatusList:
    list: bytearray
    bits: int
    size: int
    divisor: int

    def __init__(self, size: int, bits: int, alg: str = ALG_ZLIB):
        self.divisor = 8 // bits
        self.list = bytearray([0] * math.ceil(size / self.divisor))
        self.bits = bits
        self.size = size
        self.alg = alg

    @classmethod
    def fromEncoded(cls, encoded: str, bits: int = 1, alg: str = ALG_ZLIB):
        new = cls(0, bits, alg)
        new.decode(encoded)
        return new

    def encodeAsString(self) -> str:
        compressed = self.encodeAsBytes()
        return urlsafe_b64encode(compressed).decode().strip("=")

    def encodeAsBytes(self) -> bytes:
        if self.alg == ALG_BROTLI:
            return brotli.compress(self.list, quality=LEVEL_BROTLI)
        else:
            return zlib.compress(self.list, level=LEVEL_ZLIB)

    def encodeAsJSON(self) -> Dict:
        encoded_list = self.encodeAsString()
        object = {
            "alg": self.alg,
            "bits": self.bits,
            "lst": encoded_list,
        }
        return object

    def encodeAsCBOR(self) -> Dict:
        encoded_list = self.encodeAsBytes()
        object = {
            "alg": self.alg,
            "bits": self.bits,
            "lst": encoded_list,
        }
        return object

    def encodeAsCBORRaw(self) -> Dict:
        object = self.encodeAsCBOR()
        return dumps(object)

    def decode(self, input: str):
        compressed = urlsafe_b64decode(f"{input}{'=' * divmod(len(input),4)[1]}")
        if self.alg == ALG_BROTLI:
            self.list = bytearray(zlib.decompress(compressed))
        else:
            self.list = bytearray(zlib.decompress(compressed))
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
