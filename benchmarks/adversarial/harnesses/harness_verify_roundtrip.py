#!/usr/bin/env python3
"""Fuzzing harness for fletcher_pure.verify() — roundtrip + type-guard invariants.

Surface under test
------------------
`fletcher_pure.verify(data: bytes, expected: int) -> bool`  (commit 5b8481a on wt/cycle_69-fix2)

Invariants asserted (per cycle_69/adversary/01 audit + spec AC5 + module
docstring)
--------------------------------------------------------------------
I1  Type-guard on data: `verify(non_bytes, any)` MUST raise TypeError
    (per the verify() docstring: "Raises: TypeError: If data is not bytes
    or bytearray" — this IS the documented contract). The audit's
    "caller-safe" wording in slot-01 was misleading; the harness probes
    the real contract: raise TypeError, do NOT silently return False.
    (See FUZZING_REPORT.md finding F-003 for the audit-doc drift.)

I2  Type-guard on expected: `verify(bytes_input, non_int)` MUST raise
    TypeError when Python's `==` comparison is fundamentally undefined
    (e.g. list vs int). For None/str/bool/int/float `expected`, Python's
    `==` evaluates cleanly against the int return of `checksum()` so
    no raise is expected.

I3  Roundtrip: `verify(data, checksum(data)) == True` for every fuzz
    bytes input. This is the central correctness invariant — a checksum
    whose verify() disagrees with its own checksum() is broken by
    construction.

I4  Negative roundtrip: `verify(data, checksum(data) ^ 0x1) == False`
    for any fuzz bytes input (flip the lowest bit of expected → must
    reject).

I5  Determinism: two consecutive verify() calls on the same args return
    the same bool (the function is referentially transparent).

I6  Range parity: for any `expected` value v in `[0, 65535]`,
    `verify(data, v) == (checksum(data) == v)`. Outside that range, the
    comparison must still evaluate cleanly (no raise) because
    `checksum()` is always `≤ 0xFFFF`, so any `expected > 0xFFFF` is by
    construction not equal — verify must return False.

I7  Reference-vector sanity: `verify(b"123456789", 0x1EDE) is True`
    (RFC 3309 §5.1 canonical, post-fix2).

Adversarial input generators
----------------------------
- random bytes slices, length 0..1500 (roundtrip target)
- all-zeros / all-ones / alternating (boundary stress)
- boundary lengths: 254, 255, 256, 257
- long random 10000-byte payload
- non-bytes sentinels for I1 probe (must raise TypeError):
    None, int, float, list, dict, str, memoryview, bytearray, tuple,
    object(), generator
- malformed `expected` values: None, -1, 0xFFFF+1, 2**64, True,
    "string", list (raise on fundamentally-undefined comparison)
- bytearray variants of every random sample (audit S7 — bytearray IS
    accepted, unlike memoryview)

Execution model
---------------
stdlib-only, no atheris/native deps. Each iteration:
    1. Draw an (x, expected) pair from the mixed generator pool.
    2. If x is non-bytes-like: apply I1 — assert TypeError is raised.
       If x is bytes-like: apply I2..I6 — assert verify returns bool
       without raise, and the structural invariants hold.
    3. Track counters.

Exit codes:
    0  — clean run, no invariant violations.
    1  — invariant violation (recorded in crash_log.txt + first repro
         printed).
    2  — harness setup error (e.g. import failure).

Usage
-----
    python harness_verify_roundtrip.py                # default 1,000,000 iterations
    python harness_verify_roundtrip.py --iters 10000  # quick smoke
    python harness_verify_roundtrip.py --seed 42      # deterministic replay

The harness is deterministic given --seed; crashes are reproducible.
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time

# Make sure the in-tree source is importable when run from this directory.
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import fletcher_pure  # noqa: E402

# ─────────────────────────────────────────────────────────────────────────────
# Seed corpus — RFC 3309 reference vectors + audit boundary surfaces
# ─────────────────────────────────────────────────────────────────────────────

SEED_VECTORS: list[tuple[bytes, int]] = [
    (b"", 0x0000),
    (b"\x00", 0x0000),
    (b"\xab", 0xABAB),
    (b"\x01\x02", 0x0403),
    (b"\xff\xff", 0x0000),
    (b"123456789", 0x1EDE),   # RFC 3309 §5.1 (fix2)
    (b"\x00" * 65535, 0x0000),
    (b"\xff" * 256, 0x0000),  # full c0 collapse
    (b"a", 0x6161),
    (b"abc", 0x4C27),
    (b"\xff", 0x0000),
    (b"\x01" * 255, 0x0000),
]

# Preflight — every seed must round-trip verify().
_PREFLIGHT_FAIL = []
for _data, _expected in SEED_VECTORS:
    try:
        if not fletcher_pure.verify(_data, _expected):
            _PREFLIGHT_FAIL.append(("seed_verify_false", (_data, hex(_expected))))
        if fletcher_pure.verify(_data, _expected ^ 0xFFFF):  # any other value → False
            _PREFLIGHT_FAIL.append(("seed_verify_true_on_wrong", (_data, hex(_expected ^ 0xFFFF))))
    except Exception as _exc:  # pragma: no cover — preflight only
        _PREFLIGHT_FAIL.append(("seed_raised", (_data, repr(_exc))))
if _PREFLIGHT_FAIL:
    sys.stderr.write(
        "FATAL: seed preflight failed (source regressed?):\n"
        + "\n".join(repr(x) for x in _PREFLIGHT_FAIL)
        + "\n"
    )
    sys.exit(2)


# ─────────────────────────────────────────────────────────────────────────────
# Input generators — bytes-like + non-bytes sentinels for verify's caller-safe
# contract.
# ─────────────────────────────────────────────────────────────────────────────


def _gen_random_bytes(rng: random.Random, maxlen: int) -> bytes:
    n = rng.randint(0, maxlen)
    return bytes(rng.randint(0, 255) for _ in range(n))


def _gen_all_zeros(rng: random.Random, maxlen: int) -> bytes:
    return b"\x00" * rng.randint(0, maxlen)


def _gen_all_ones(rng: random.Random, maxlen: int) -> bytes:
    return b"\xff" * rng.randint(0, maxlen)


def _gen_alternating(rng: random.Random, maxlen: int) -> bytes:
    n = rng.randint(0, maxlen)
    a, b = rng.randint(0, 255), rng.randint(0, 255)
    return bytes(a if i % 2 == 0 else b for i in range(n))


def _gen_boundary_length(rng: random.Random) -> bytes:
    n = rng.choice([254, 255, 256, 257, 510, 511, 765])
    return bytes(rng.randint(0, 255) for _ in range(n))


def _gen_long_random(rng: random.Random, length: int) -> bytes:
    return bytes(rng.randint(0, 255) for _ in range(length))


def _gen_non_bytes_sentinel(rng: random.Random):
    """A non-bytes value — verify() MUST return False, never raise (I1)."""
    bucket = rng.randint(0, 9)
    if bucket == 0:
        return None
    if bucket == 1:
        return rng.randint(-10000, 10000)
    if bucket == 2:
        # float edge cases
        sub = rng.randint(0, 3)
        if sub == 0:
            return rng.uniform(-1e6, 1e6)
        if sub == 1:
            return float("nan")
        if sub == 2:
            return float("inf")
        return -float("inf")
    if bucket == 3:
        return "string-not-bytes"  # str is iterable but not bytes-like
    if bucket == 4:
        return [rng.randint(0, 255)]  # list of int
    if bucket == 5:
        return {0: "zero"}  # dict
    if bucket == 6:
        return (b"x",)  # tuple
    if bucket == 7:
        return memoryview(b"abc")  # audit S10
    if bucket == 8:
        # generator yielding ints
        return (i for i in range(3))
    # bucket == 9: object()
    return object()


def _gen_expected(rng: random.Random, target_data: bytes) -> object:  # type: ignore[return-value]  # fuzz: int | None | str | bool
    """Pick an `expected` value relative to the actual checksum.

    Mix of: correct value, off-by-one low bit, totally random in range,
    out-of-range (negative, > 0xFFFF), and special non-int types for I2.
    """
    bucket = rng.randint(0, 9)
    actual = fletcher_pure.checksum(target_data)
    if bucket == 0:
        return actual  # correct → True
    if bucket == 1:
        return actual ^ 0x1  # I4: flip low bit → must be False
    if bucket == 2:
        return actual ^ rng.randint(1, 0xFFFF)  # some other value
    if bucket == 3:
        return rng.randint(0, 0xFFFF)  # random in range
    if bucket == 4:
        return -1  # negative
    if bucket == 5:
        return 0x10000  # just above range
    if bucket == 6:
        return rng.randint(0x10000, 2**32)  # way above range
    if bucket == 7:
        return None  # non-numeric — I2 says MUST NOT raise
    if bucket == 8:
        return "not-a-number"  # str — I2 must not raise
    # bucket == 9: True/False — bool is int subclass; must not raise
    return rng.choice([True, False])


def _draw_pair(rng: random.Random, counter: int):
    """Return (data, expected) for one iteration."""
    if counter % 1000 == 0:
        # Re-emit a seed with its known-good expected.
        d, e = rng.choice(SEED_VECTORS)
        return d, e

    bucket = rng.randint(0, 9)
    if bucket == 0:
        d = _gen_random_bytes(rng, 1500)
    elif bucket == 1:
        d = _gen_all_zeros(rng, 2048)
    elif bucket == 2:
        d = _gen_all_ones(rng, 2048)
    elif bucket == 3:
        d = _gen_alternating(rng, 2048)
    elif bucket == 4:
        d = _gen_boundary_length(rng)
    elif bucket == 5:
        d = _gen_long_random(rng, 10000)
    elif bucket == 6:
        # bytearray variant — audit S7
        d = bytearray(_gen_random_bytes(rng, 1000))  # type: ignore[assignment]
    elif bucket == 7:
        d = _gen_random_bytes(rng, 16)
    elif bucket == 8:
        # I1 probe — pass a non-bytes sentinel as `data`
        sentinel = _gen_non_bytes_sentinel(rng)
        # Use a numeric `expected`; result must be False, no raise.
        return sentinel, rng.randint(0, 0xFFFF)  # type: ignore[return-value]
    else:
        d = b""

    return d, _gen_expected(rng, d)


# ─────────────────────────────────────────────────────────────────────────────
# Invariant checks
# ─────────────────────────────────────────────────────────────────────────────


def _record_crash(kind: str, payload, detail, crash_log_path: str) -> None:
    """Append a single crash record to crash_log.txt and print first repro."""
    is_first = not os.path.exists(crash_log_path) or os.path.getsize(crash_log_path) == 0
    with open(crash_log_path, "a", encoding="utf-8") as fh:
        fh.write(f"{kind}\t{repr(payload)}\t{detail}\n")
    if is_first:
        sys.stderr.write(f"FIRST CRASH [{kind}] on input {repr(payload)}: {detail}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Main loop
# ─────────────────────────────────────────────────────────────────────────────


def main() -> int:
    ap = argparse.ArgumentParser(description=str(__doc__).split("\n")[0])  # type: ignore[arg-type]
    ap.add_argument("--iters", type=int, default=1_000_000,
                    help="number of iterations (default 1,000,000)")
    ap.add_argument("--seed", type=int, default=None,
                    help="RNG seed for deterministic replay")
    ap.add_argument("--log", default=os.path.join(_HERE, "crash_log_verify_roundtrip.txt"),
                    help="path to crash log (default: ./crash_log_verify_roundtrip.txt)")
    args = ap.parse_args()

    # Truncate any prior log so the FIRST crash signal is unambiguous.
    if os.path.exists(args.log):
        os.remove(args.log)

    rng = random.Random(args.seed)

    iters = 0
    raise_count = 0
    invariant_count = 0
    t0 = time.monotonic()

    while iters < args.iters:
        iters += 1
        data, expected = _draw_pair(rng, iters)

        is_bytes_like = isinstance(data, (bytes, bytearray))

        # I1 — type guard: non-bytes-like data MUST raise TypeError.
        if not is_bytes_like:
            try:
                result = fletcher_pure.verify(data, expected)  # type: ignore[arg-type]
            except TypeError:
                # Expected — this IS the documented contract.
                pass
            except BaseException as exc:  # noqa: BLE001 — different exception is a defect
                raise_count += 1
                _record_crash(
                    "i1_wrong_exception",
                    (data, expected),
                    f"verify raised {type(exc).__name__} (expected TypeError): {exc}",
                    args.log,
                )
                continue
            else:
                invariant_count += 1
                _record_crash(
                    "i1_no_raise_on_nonbytes",
                    (data, expected),
                    f"verify returned {result!r} instead of raising TypeError",
                    args.log,
                )
                continue
            # Non-bytes path done — move on.
            continue

        # I2 — totality on bytes-like path: should never raise on numeric
        # `expected`; may raise TypeError only on fundamentally-undefined
        # comparisons (list vs int, etc.).
        try:
            result = fletcher_pure.verify(data, expected)  # type: ignore[arg-type]
        except BaseException as exc:  # noqa: BLE001
            # Distinguish: TypeError on fundamentally-undefined `expected` is
            # fine; any other exception is a real defect.
            safe_expected_types = (type(None), bool, int, float, str, bytes, bytearray)
            if isinstance(expected, safe_expected_types):
                raise_count += 1
                _record_crash(
                    "i2_raise_on_safe_expected",
                    (data, expected),
                    f"verify raised {type(exc).__name__}: {exc}",
                    args.log,
                )
                continue
            raise_count += 1
            _record_crash(
                "raise_uncomparable_expected",
                (data, expected),
                f"{type(exc).__name__}: {exc}",
                args.log,
            )
            continue

        # I5 — determinism on bytes-like path.
        try:
            again = fletcher_pure.verify(data, expected)  # type: ignore[arg-type]
        except BaseException as exc:  # pragma: no cover
            raise_count += 1
            _record_crash("raise_repeat", (data, expected), f"{type(exc).__name__}: {exc}", args.log)
            continue
        if result != again:
            invariant_count += 1
            _record_crash(
                "i5_determinism",
                (data, expected),
                f"first={result!r} second={again!r}",
                args.log,
            )
            continue

        # I3 / I4 / I6 — roundtrip invariants (only meaningful when `expected`
        # is itself comparable to an int — i.e. numeric or None).
        actual_checksum = fletcher_pure.checksum(data)  # type: ignore[arg-type]
        # expected_numeric: bool/None compare as ints in `==` against int.
        expected_numeric_types = (type(None), bool, int, float)
        if isinstance(expected, expected_numeric_types):
            # I3 — verify(data, checksum(data)) == True
            if fletcher_pure.verify(data, actual_checksum) is not True:  # type: ignore[arg-type]
                invariant_count += 1
                _record_crash(
                    "i3_roundtrip",
                    (data, actual_checksum),
                    "verify(data, checksum(data)) did not return True",
                    args.log,
                )
                continue

            # I4 — flip the lowest bit, must return False
            flipped = actual_checksum ^ 0x1
            if fletcher_pure.verify(data, flipped) is not False:  # type: ignore[arg-type]
                invariant_count += 1
                _record_crash(
                    "i4_neg_roundtrip",
                    (data, flipped),
                    "verify(data, checksum(data)^1) did not return False",
                    args.log,
                )
                continue

            # I6 — for any expected v: verify(data, v) == (checksum(data) == v)
            # (Skip NaN — NaN != NaN makes the comparison undefined.)
            if not (isinstance(expected, float) and expected != expected):
                direct = (actual_checksum == expected)
                if result != direct:
                    invariant_count += 1
                    _record_crash(
                        "i6_parity",
                        (data, expected),
                        f"verify={result!r} but checksum(data)==expected is {direct}",
                        args.log,
                    )
                    continue

    elapsed = time.monotonic() - t0
    rate = iters / elapsed if elapsed > 0 else 0.0

    print("=" * 72)
    print(f"harness_verify_roundtrip  target=fletcher_pure.verify  commit=5b8481a")
    print(f"iters             = {iters:,}")
    print(f"elapsed           = {elapsed:.2f}s")
    print(f"rate              = {rate:,.0f} it/s")
    print(f"raises            = {raise_count}")
    print(f"invariant_viols   = {invariant_count}")
    print(f"seed_corpus_size  = {len(SEED_VECTORS)}")
    print(f"log               = {args.log}")
    print("=" * 72)

    if raise_count or invariant_count:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
