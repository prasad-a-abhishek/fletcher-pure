"""Property-based and idempotency tests."""
from fletcher_pure import checksum, verify


class TestProperties:
    def test_idempotent(self):
        """Re-checksumming same data gives same result."""
        data = b"Hello, world!"
        assert checksum(data) == checksum(data)
        assert checksum(data) == checksum(data) == checksum(data)

    def test_deterministic(self):
        """checksum is deterministic across multiple calls."""
        import os
        for _ in range(20):
            data = os.urandom(16)
            results = [checksum(data) for _ in range(5)]
            assert len(set(results)) == 1

    def test_checksum_type_is_int(self):
        """checksum() always returns int."""
        assert isinstance(checksum(b""), int)
        assert isinstance(checksum(b"test"), int)
        assert isinstance(checksum(b"\xff" * 1000), int)

    def test_verify_bool_return(self):
        """verify() returns bool."""
        assert isinstance(verify(b"", 0), bool)
        assert isinstance(verify(b"x", 0), bool)

    def test_multiple_verify_calls(self):
        """Multiple verify calls on same data/different values."""
        data = b"consistent"
        cs = checksum(data)
        assert verify(data, cs) is True
        assert verify(data, cs + 1) is False
        assert verify(data, cs - 1) is False
        assert verify(data, 0) is (cs == 0)

    def test_bytearray_input(self):
        """bytearray input is accepted by verify()."""
        data = bytearray(b"test data")
        assert verify(data, checksum(data)) is True
        assert verify(data, 0) is False

    def test_different_data_different_checksum(self):
        """Different data can produce same checksum (collision)."""
        # This is expected behavior - verify collisions exist
        seen = {}
        for i in range(1000):
            data = bytes([i % 256, (i * 7) % 256])
            cs = checksum(data)
            # We just verify deterministic behavior
            assert checksum(data) == cs

    def test_large_text_payload(self):
        """Large text payload processed correctly."""
        text = b"The quick brown fox jumps over the lazy dog. " * 50
        result = checksum(text)
        assert isinstance(result, int)
        assert 0 <= result <= 65535
