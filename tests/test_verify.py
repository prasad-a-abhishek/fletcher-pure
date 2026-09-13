"""verify() roundtrip and corruption detection tests."""
import pytest
from fletcher_pure import checksum, verify


class TestVerifyRoundtrip:
    """AC5: verify(data, checksum(data)) is always True."""

    @pytest.mark.parametrize("data", [
        b"", b"\x00", b"\x01", b"\xff",
        b"a", b"ab", b"abc", b"abcd",
        b"hello", b"hello world",
        b"\x00\x01\x02\x03",
        b"\xff\xfe\xfd\xfc",
        b"\x00" * 100,
        b"\xff" * 100,
        bytes(range(256)),
        b"The quick brown fox",
        b"\x01\x02\x03\x04\x05\x06\x07\x08",
    ])
    def test_verify_true(self, data):
        assert verify(data, checksum(data)) is True


class TestVerifyCorruption:
    """AC6: verify(data, checksum(data) ^ 0x0001) is always False."""

    @pytest.mark.parametrize("data", [
        b"", b"\x00", b"\x01", b"\xff",
        b"a", b"ab", b"abc", b"abcd",
        b"hello", b"hello world",
        b"\x00\x01\x02\x03",
        bytes(range(256)),
    ])
    def test_verify_false_on_corruption(self, data):
        original = checksum(data)
        corrupted = original ^ 0x0001
        assert verify(data, corrupted) is False
        assert corrupted != original
