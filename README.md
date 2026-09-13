# fletcher-pure

`fletcher-pure` — zero-dependency pure-stdlib Fletcher-16 checksum per RFC 3309 / ISO/IEC 3309.

[![PyPI version](https://img.shields.io/pypi/v/fletcher-pure.svg)](https://pypi.org/project/fletcher-pure/)
[![Python](https://img.shields.io/pypi/pyversions/fletcher-pure.svg)](https://pypi.org/project/fletcher-pure/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**No dependencies. No C extension. Pure Python stdlib — runs anywhere Python runs.**

## Quick Start

```bash
pip install -e .
```

```python
from fletcher_pure import checksum, verify

c = checksum(b"Hello")        # int in [0, 65535]
ok = verify(b"Hello", 0x1A3F)  # bool
```

## Why fletcher-pure?

Embedded systems engineers and serverless Python developers working on legacy protocol parsers (X.25, ISO/IEC 3309) need a pure-Fletcher-16 checksum utility without pulling in a heavy library. The `crcmod` package weighs several MB and requires C compilation; `fletcher` on PyPI has unknown runtime deps.

`fletcher-pure` provides:
- **Zero runtime dependencies** — pure Python stdlib only
- **RFC 3309 / ISO/IEC 3309** compliant Fletcher-16 mod-255
- **Arbitrary input size** — Python int arithmetic never overflows
- **Typing included** — full type annotations

## Key Features

- `checksum(data: bytes) -> int` — Fletcher-16 mod-255, returns int in [0, 65535]
- `verify(data: bytes, expected: int) -> bool` — True iff checksum matches
- **Zero pip dependencies** at runtime
- Works on inputs up to 65535 bytes (and beyond) without overflow
- Full type annotations
- 100% test coverage of acceptance criteria

## API Reference

### `checksum(data: bytes) -> int`

Compute the Fletcher-16 checksum (mod 255) of `data`.

```python
checksum(b"")           # 0
checksum(b"\x00")       # 0 (c0=c1=0 initialization per RFC 3309 §5.1)
checksum(b"\x01\x02")   # 1027
checksum(b"\xff\xff")   # 0 (mod-255 wrap)
checksum(b"123456789")  # 0x1EDE = 7662
```

### `verify(data: bytes, expected: int) -> bool`

Return `True` if `checksum(data) == expected`, `False` otherwise.

```python
verify(b"Hello", checksum(b"Hello"))  # True
verify(b"Hello", checksum(b"Hello") ^ 0x0001)  # False (corruption detected)
verify(b"", 0)  # True
```

**Raises `TypeError`** if `data` is not `bytes` or `bytearray`.

### CLI

No CLI is provided. Use as a library:

```python
from fletcher_pure import checksum, verify
```

## Limitations

- Fletcher-16 is not cryptographically secure — use SHA-256 for security purposes.
- Collisions are possible for larger inputs (birthday paradox applies).
- No streaming / chunked API — entire input must fit in memory.
- `verify` does not accept `memoryview` (only `bytes` and `bytearray`).

## Non-Goals

- No CRC32, Adler-32, or other checksum algorithms.
- No CLI tool.
- No native/C extension for speed.
- No support for Python < 3.8.

## Install

```bash
pip install git+https://github.com/prasad-a-abhishek/fletcher-pure.git
```

For development:

```bash
git clone https://github.com/prasad-a-abhishek/fletcher-pure.git
cd fletcher-pure
pip install -e .
pytest
```

## License

MIT License — see LICENSE file.
