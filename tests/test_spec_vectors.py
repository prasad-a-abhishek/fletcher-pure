"""Spec test vectors — one test per acceptance criterion."""
import pytest
from fletcher_pure import checksum, verify


class TestSpecVectors:
    def test_ac1_empty_input(self):
        """AC1: checksum(b"") == 0"""
        assert checksum(b"") == 0

    def test_ac2_single_zero_byte(self):
        """AC2: checksum(b"\\x00") == 0 (per spec pseudocode; mod-255 wrap)"""
        # Note: spec table says 257 but spec pseudocode (c0=c1=0 init) gives 0.
        # Implementation follows the pseudocode.
        assert checksum(b"\x00") == 0

    def test_ac3_two_bytes(self):
        """AC3: checksum(b"\\x01\\x02") == 1027 (0x0403)"""
        assert checksum(b"\x01\x02") == 1027

    def test_ac4_ff_wrap(self):
        """AC4: checksum(b"\\xff\\xff") == 0 (mod-255 wrap)"""
        assert checksum(b"\xff\xff") == 0

    def test_ac5_verify_roundtrip(self):
        """AC5: verify(data, checksum(data)) returns True for all valid inputs."""
        cases = [
            b"", b"\x00", b"\x01\x02", b"\xff\xff",
            b"123456789", b"\x01\x02\x03\x04\x05",
            b"Hello, world!", b"\x00\x00\x00",
            b"\xff" * 10, b"\x80\x7f\x3e\x01",
        ]
        for data in cases:
            assert verify(data, checksum(data)) is True, f"failed for {data!r}"

    def test_ac6_verify_detects_corruption(self):
        """AC6: verify(data, checksum(data) ^ 0x0001) returns False."""
        cases = [b"", b"\x00", b"\x01\x02", b"\xff\xff", b"123456789"]
        for data in cases:
            corrupted = checksum(data) ^ 0x0001
            assert verify(data, corrupted) is False, f"should detect corruption for {data!r}"

    def test_ac7_type_error_non_bytes(self):
        """AC7: verify raises TypeError if data is not bytes or bytearray."""
        bad = [None, "str", [1, 2], (1, 2), 42, 3.14]
        for val in bad:
            with pytest.raises(TypeError):
                verify(val, 0)

    def test_ac8_65535_byte_input(self):
        """AC8: Works on inputs up to 65535 bytes without overflow."""
        data = b"\x00" * 65535
        result = checksum(data)
        assert isinstance(result, int)
        assert 0 <= result <= 65535

    def test_ac9_result_range(self):
        """AC9: Result of checksum is always int in range [0, 65535]."""
        cases = [
            b"", b"\x00", b"\x01\x02", b"\xff\xff",
            b"123456789", b"\x01\x02\x03\x04\x05",
            b"x" * 1000, b"\xff" * 1000,
            b"\x00" * 65535, b"\xff" * 65535,
        ]
        for data in cases:
            result = checksum(data)
            assert isinstance(result, int), f"{data!r} -> {result!r} not int"
            assert 0 <= result <= 65535, f"{data!r} -> {result} out of range"

    def test_ac10_zero_deps(self):
        """AC10: Pure stdlib — import succeeds with 0 pip runtime deps."""
        import fletcher_pure
        assert hasattr(fletcher_pure, 'checksum')
        assert hasattr(fletcher_pure, 'verify')
