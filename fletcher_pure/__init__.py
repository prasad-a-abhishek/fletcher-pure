"""Fletcher-16 pure-stdlib checksum per RFC 3309 / ISO/IEC 3309."""

__version__ = "0.1.0"


def checksum(data: bytes) -> int:
    """Return Fletcher-16 checksum (mod 255) as unsigned 16-bit integer.

    Args:
        data: Byte string to checksum.

    Returns:
        Integer in range [0, 65535].
    """
    c0 = 0
    c1 = 0
    for byte in data:
        c0 = (c0 + byte) % 255
        c1 = (c1 + c0) % 255
    return (c1 << 8) | c0


def verify(data: bytes, expected: int) -> bool:
    """Return True if Fletcher-16 checksum of data equals expected.

    Args:
        data: Byte string to checksum.
        expected: Expected 16-bit checksum value.

    Returns:
        True iff checksum(data) == expected.

    Raises:
        TypeError: If data is not bytes or bytearray.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    return checksum(data) == expected
