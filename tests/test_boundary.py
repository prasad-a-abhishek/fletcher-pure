"""Boundary and edge case tests."""
import pytest
from fletcher_pure import checksum, verify


class TestBoundary:
    def test_max_65535_zeros(self):
        """65535 zero bytes should not overflow."""
        data = b"\x00" * 65535
        result = checksum(data)
        assert isinstance(result, int)
        assert 0 <= result <= 65535

    def test_max_65535_ff(self):
        """65535 0xFF bytes should not overflow."""
        data = b"\xff" * 65535
        result = checksum(data)
        assert isinstance(result, int)
        assert 0 <= result <= 65535

    def test_1024_zeros(self):
        """1024 zero bytes."""
        data = b"\x00" * 1024
        result = checksum(data)
        assert isinstance(result, int)
        assert 0 <= result <= 65535

    def test_1024_ff(self):
        """1024 0xFF bytes."""
        data = b"\xff" * 1024
        result = checksum(data)
        assert isinstance(result, int)
        assert 0 <= result <= 65535

    def test_256_zeros(self):
        """256 zero bytes."""
        data = b"\x00" * 256
        result = checksum(data)
        assert 0 <= result <= 65535

    def test_all_bytes_once(self):
        """All 256 byte values once each."""
        data = bytes(range(256))
        result = checksum(data)
        assert 0 <= result <= 65535

    def test_empty_input(self):
        """Empty input edge case."""
        assert checksum(b"") == 0
        assert verify(b"", 0) is True

    def test_verify_type_errors(self):
        """Type safety: non-bytes/bytearray raises TypeError."""
        for bad in [None, "str", [1, 2], (1, 2), 42, 3.14]:
            with pytest.raises(TypeError):
                verify(bad, 0)
