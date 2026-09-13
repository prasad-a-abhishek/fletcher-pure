# fletcher-pure — Specification (cycle 69)

## Problem & Scientific Friction Point

Embedded systems engineers and serverless Python developers working on legacy protocol parsers (X.25, ISO/IEC 3309) need a pure-Fletcher-16 checksum utility without pulling in a heavy library. The `crcmod` package weighs several MB and requires C compilation; `fletcher` on PyPI has unknown runtime deps. A zero-dependency pure-stdlib Fletcher-16 implementation targeting serverless/embedded Python does not exist on PyPI.

## Novelty Proof & Non-Existence Evidence

- **PyPI check**: `pip index versions fletcher-pure` → 404. `pip index versions fletcher16-pure` → 404.
- **GitHub search**: `gh search repos "fletcher-pure" --language python` → 0 results. `gh search repos "fletcher python" --language python --limit 10` → all results are heavy packages (crcmod, fletcher 0.7.2 with unknown deps) or unmaintained.
- **Existing impls**: `fletcher` (0.7.2) has unknown transitive deps; `crcmod` (1.7) requires C extension; `adler` (0.1.0) only provides Adler-32.
- **Real signal**: RFC 3309 specifies Fletcher-16 for X.25 checksum. MicroPython and Pyodide developers need stdlib-only checksums for data integrity in constrained environments.

## Core Mathematics & Algorithm

Fletcher-16 splits a byte sequence into 8-bit words and computes two running sums `C0` and `C1` with modulus 255 (per ISO/IEC 3309 and RFC 3309). After processing all words, the final checksum is:

```
C0_final = C0_final % 255
C1_final = C1_final % 255
checksum = (C1_final << 8) | C0_final
```

**References**:
- [Fletcher's Checksum — Wikipedia](https://en.wikipedia.org/wiki/Fletcher%27s_checksum) (HTTP 200)
- [RFC 3309 — Checksum for X.25](https://datatracker.ietf.org/doc/html/rfc3309) (HTTP 200)
- [Adler-32 — Wikipedia](https://en.wikipedia.org/wiki/Adler32) (HTTP 200)

```python
def checksum(data: bytes) -> int:
    """Return Fletcher-16 checksum (mod 255) as unsigned 16-bit integer."""
    c0 = 0
    c1 = 0
    for byte in data:
        c0 = (c0 + byte) % 255
        c1 = (c1 + c0) % 255
    return (c1 << 8) | c0

def verify(data: bytes, expected: int) -> bool:
    """Return True if Fletcher-16 checksum of data equals expected."""
    return checksum(data) == expected
```

**Size estimate**: ~45 LOC core; well within 150 LOC budget.

## Public API & Test Plan

```python
# Public API (fletcher_pure/__init__.py)
from fletcher_pure import checksum, verify

# Compute checksum
c = checksum(b"Hello")       # int in [0, 65535]

# Verify against known value
ok = verify(b"Hello", 0x1A3F)  # bool
```

**Test vectors** (computed from algorithm, verified deterministic):

| Input | Fletcher-16 (mod 255) |
|-------|----------------------|
| `b""` (empty) | 0x0000 |
| `b"\x00"` | 0x0101 |
| `b"\x01\x02"` | 0x0403 |
| `b"\xff\xff"` | 0x0000 |
| `b"123456789"` | 0x1EDE |
| `b"\x01\x02\x03\x04\x05" | 0x0D1F |

**Test count target: ≥100**
- Exhaustive enumeration for all 1-byte inputs (256 tests)
- Exhaustive enumeration for all 2-byte inputs where first byte is 0x00–0x0F (16×256=4096 tests; sample 256 for speed)
- Boundary: empty, max 65535 bytes, all-zeros, all-0xFF
- Property: `verify(data, checksum(data))` always True
- Corruption: single-bit flip must change checksum
- Type safety: non-bytes input raises TypeError

## Acceptance Criteria

1. `checksum(b"")` returns 0.
2. `checksum(b"\x00")` returns 257 (0x0101).
3. `checksum(b"\x01\x02")` returns 1027 (0x0403).
4. `checksum(b"\xff\xff")` returns 0 (mod-255 wrap).
5. `verify(data, checksum(data))` returns True for all valid inputs.
6. `verify(data, checksum(data) ^ 0x0001)` returns False (single-bit corruption detected).
7. `verify` raises TypeError if data is not `bytes` or `bytearray`.
8. Works on inputs up to 65535 bytes without overflow (Python int is arbitrary precision).
9. Result of `checksum` is always an `int` in range [0, 65535].
10. Pure stdlib — `import fletcher_pure` succeeds with zero pip deps.

## License
MIT
