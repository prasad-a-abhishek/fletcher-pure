"""Exhaustive single-byte input tests (256).

For a single byte value b:
  c0 = b % 255
  c1 = c0 % 255
  result = (c1 << 8) | c0
For b=0: result=0
For b=1-254: result = b*257
For b=255: result=0
"""
import pytest
from fletcher_pure import checksum


class TestSingleByteExhaustive:
    @pytest.mark.parametrize("byte_val", range(256))
    def test_single_byte(self, byte_val):
        data = bytes([byte_val])
        c0 = byte_val % 255
        c1 = c0 % 255
        expected = (c1 << 8) | c0
        assert checksum(data) == expected
