#!/usr/bin/env python3
"""Fuzzing harness for fletcher_pure.checksum() — totality + invariants + range.

Surface under test
------------------
`fletcher_pure.checksum(data: bytes) -> int`  (commit 5b8481a on wt/cycle_69-fix2)

Invariants asserted (per cycle_69/adversary/01 audit + RFC 3309 §5.1)
---------------------------------------------------------------------
I1  Totality on bytes-like input: `checksum(x)` MUST NEVER raise for any
    `bytes` or `bytearray` x (the documented input class). This is the
    baseline "no surprise crash" contract per audit S1.

I2  Range contract: `checksum(x)` always returns an int in `[0, 65535]`
    (audit S2 — both c0 and c1 are bounded `[0, 254]`, so
    `(c1 << 8) | c0 <= 0xFEFE` ⊂ `[0, 65535]`).

I3  Determinism: `checksum(x) == checksum(x)` (the loop is purely
    arithmetic on the input — no global state, no RNG).

I4  bytearray equivalence: `checksum(b) == checksum(bytearray(b))` for
    any bytes-like input b (audit S7 — bytearray iterates identically).

I5  Reference implementation parity: `checksum(x) == ref_fletcher16(x)`
    where `ref_fletcher16` is an independently-coded textbook Fletcher-16
    function in this file. If they ever diverge, the implementation has
    silently regressed from RFC 3309 §5.1 (audit S1 — CWE-682).

I6  Reference-vector sanity: the canonical RFC 3309 §5.1 vector
    `b"123456789"` -> `0x1EDE` (per the README and `tests/test_spec_vectors.py`).

Adversarial input generators
----------------------------
- random bytes slices, length 0..1500 (catches off-by-one in mod-255 wrap)
- all-zeros 0..2048 bytes (mod-255 edge: 0 stays 0)
- all-ones 0..2048 bytes (mod-255 wrap stress: each c1 += c0 every iter)
- alternating 0x00/0xFF up to 2048 bytes
- lengths hitting the mod-255 boundary exactly: 254, 255, 256, 257, 510, 511
- bytearray variants of every random sample (I4 probe)
- 10000-byte random (audit S9 — long-input performance & overflow safety)

Execution model
---------------
stdlib-only, no atheris/native deps. Each iteration:
    1. Draw an input from the mixed generator pool.
    2. Apply I1: assert checksum(x) does not raise.
    3. Apply I2: assert return type & range.
    4. Apply I3: assert determinism.
    5. Apply I4: assert bytearray equivalence.
    6. Apply I5: assert ref-impl parity.

Exit codes:
    0  — clean run, no invariant violations.
    1  — invariant violation (recorded in crash_log.txt + first repro printed).
    2  — harness setup error (e.g. import failure).

Usage
-----
    python harness_checksum.py                # default 1,000,000 iterations
    python harness_checksum.py --iters 10000  # quick smoke
    python harness_checksum.py --seed 42      # deterministic replay

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
# Independent reference implementation (textbook Fletcher-16 per RFC 3309 §5.1)
# If this ever diverges from fletcher_pure.checksum(), the package has
# silently regressed. We carry it inline on purpose — no shared code with
# the package under test.
# ─────────────────────────────────────────────────────────────────────────────


def _ref_fletcher16(data: bytes) -> int:
    """Textbook Fletcher-16 per RFC 3309 §5.1 — independent reference impl.

    Identical arithmetic to fletcher_pure.checksum but re-derived here so
    the harness cannot silently inherit a bug from the module under test.
    """
    c0 = 0
    c1 = 0
    for byte in data:
        c0 = (c0 + byte) % 255
        c1 = (c1 + c0) % 255
    return (c1 << 8) | c0


# ─────────────────────────────────────────────────────────────────────────────
# Seed corpus — RFC 3309 reference vectors + audit boundary surfaces
# ─────────────────────────────────────────────────────────────────────────────

# (input_bytes, expected_checksum_hex) — verified by running the RFC 3309 §5.1
# algorithm step by step; these are not hand-derived but algorithm-derived
# from a clean reimplementation of the textbook Fletcher-16. Any drift here
# means the package under test has diverged from the reference algorithm.
SEED_VECTORS: list[tuple[bytes, int]] = [
    (b"", 0x0000),                # audit S8: empty
    (b"\x00", 0x0000),            # audit S8: single zero (RFC 3309 §5.1)
    (b"\xab", 0xABAB),            # audit S8: single byte (after one iter)
    (b"\x01\x02", 0x0403),        # audit S1 hand-derived ✓
    (b"\xff\xff", 0x0000),        # mod-255 wrap: c0=0, c1=0
    (b"123456789", 0x1EDE),       # RFC 3309 §5.1 canonical (remediated in fix-2)
    (b"\x00" * 65535, 0x0000),    # audit S9: all zeros long
    (b"\xff" * 256, 0x0000),      # all ones 256 — full c0 collapse (mod 255)
    (b"a", 0x6161),               # sanity: ASCII 'a'
    (b"abc", 0x4C27),             # sanity: ASCII 'abc' (algorithm-derived)
    (b"\xff", 0x0000),            # single 0xFF: c0 = 255 % 255 = 0, c1 = 0
    (b"\x01" * 255, 0x0000),      # 255 of 0x01 — c0 cycles 1..0
]

# Preflight — every seed must round-trip through the package AND the ref impl.
# If a seed breaks, the harness is misconfigured before fuzz starts.
_PREFLIGHT_FAIL = []
for _data, _expected in SEED_VECTORS:
    try:
        _actual_pkg = fletcher_pure.checksum(_data)
        _actual_ref = _ref_fletcher16(_data)
    except Exception as _exc:  # pragma: no cover — preflight only
        _PREFLIGHT_FAIL.append(("seed_raised", (_data, repr(_exc))))
        continue
    if _actual_pkg != _expected:
        _PREFLIGHT_FAIL.append(("pkg_mismatch", (_data, hex(_expected), hex(_actual_pkg))))
    if _actual_ref != _expected:
        _PREFLIGHT_FAIL.append(("ref_mismatch", (_data, hex(_expected), hex(_actual_ref))))
if _PREFLIGHT_FAIL:
    sys.stderr.write(
        "FATAL: seed preflight failed (source or ref regressed?):\n"
        + "\n".join(repr(x) for x in _PREFLIGHT_FAIL)
        + "\n"
    )
    sys.exit(2)


# ─────────────────────────────────────────────────────────────────────────────
# Input generators — every fuzz input MUST be bytes or bytearray so I1 applies
# (Non-bytes types are reserved for harness_verify_roundtrip.py — that surface
# has a documented isinstance guard, this one doesn't.)
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
    """Hit the mod-255 boundary exactly: 254, 255, 256, 257, 510, 511."""
    n = rng.choice([254, 255, 256, 257, 510, 511, 765, 7650])
    return bytes(rng.randint(0, 255) for _ in range(n))


def _gen_long_random(rng: random.Random, length: int) -> bytes:
    return bytes(rng.randint(0, 255) for _ in range(length))


def _gen_pattern_byte(rng: random.Random, maxlen: int) -> bytes:
    """One byte repeated N times — exercises c1 += c0 every iter."""
    byte = rng.randint(0, 255)
    return bytes([byte]) * rng.randint(0, maxlen)


def _draw_input(rng: random.Random, counter: int) -> bytes:
    """Return a fuzz input. Periodically re-emit a seed to keep coverage."""
    if counter % 1000 == 0:
        return rng.choice(SEED_VECTORS)[0]

    bucket = rng.randint(0, 8)
    if bucket == 0:
        return _gen_random_bytes(rng, 1500)
    if bucket == 1:
        return _gen_all_zeros(rng, 2048)
    if bucket == 2:
        return _gen_all_ones(rng, 2048)
    if bucket == 3:
        return _gen_alternating(rng, 2048)
    if bucket == 4:
        return _gen_boundary_length(rng)
    if bucket == 5:
        return _gen_long_random(rng, 10000)
    if bucket == 6:
        return _gen_pattern_byte(rng, 2048)
    if bucket == 7:
        return _gen_random_bytes(rng, 16)  # small-input stress
    # bucket == 8: empty (special — c0=c1=0 always)
    return b""


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


def _check_invariants(
    payload: bytes,
    result: int,
    ref_result: int,
    crash_log_path: str,
) -> None:
    """All invariants from the harness docstring. Raises AssertionError on fail."""
    # I2 — return type & range.
    assert isinstance(result, int), (
        f"I2 violation: checksum returned non-int {type(result).__name__} for {payload!r}"
    )
    assert 0 <= result <= 0xFFFF, (
        f"I2 violation: checksum returned {hex(result)} (outside [0, 0xFFFF]) for {payload!r}"
    )

    # I3 — determinism is already proven by computing once; assert it here.
    # (We recompute from the same payload and compare.) Done at call site.

    # I5 — ref-impl parity.
    assert result == ref_result, (
        f"I5 violation: pkg={hex(result)} != ref={hex(ref_result)} for {payload!r}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main loop
# ─────────────────────────────────────────────────────────────────────────────


def main() -> int:
    ap = argparse.ArgumentParser(description=str(__doc__).split("\n")[0])  # type: ignore[arg-type]
    ap.add_argument("--iters", type=int, default=1_000_000,
                    help="number of iterations (default 1,000,000)")
    ap.add_argument("--seed", type=int, default=None,
                    help="RNG seed for deterministic replay")
    ap.add_argument("--log", default=os.path.join(_HERE, "crash_log_checksum.txt"),
                    help="path to crash log (default: ./crash_log_checksum.txt)")
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
        payload = _draw_input(rng, iters)

        # I1 — totality on bytes-like input.
        try:
            result = fletcher_pure.checksum(payload)
        except BaseException as exc:  # noqa: BLE001 — we want to catch literally everything
            raise_count += 1
            _record_crash("raise", payload, f"{type(exc).__name__}: {exc}", args.log)
            continue

        # I3 — determinism: re-run and compare.
        try:
            again = fletcher_pure.checksum(payload)
        except BaseException as exc:  # pragma: no cover — determinism implies totality
            raise_count += 1
            _record_crash("raise_repeat", payload, f"{type(exc).__name__}: {exc}", args.log)
            continue
        if result != again:
            invariant_count += 1
            _record_crash(
                "i3_determinism",
                payload,
                f"first={hex(result)} second={hex(again)}",
                args.log,
            )
            continue

        # I4 — bytearray equivalence.
        try:
            ba_result = fletcher_pure.checksum(bytearray(payload))  # type: ignore[arg-type]  # fuzz: probe bytearray acceptance
        except BaseException as exc:
            raise_count += 1
            _record_crash(
                "raise_bytearray",
                payload,
                f"{type(exc).__name__}: {exc}",
                args.log,
            )
            continue
        if result != ba_result:
            invariant_count += 1
            _record_crash(
                "i4_bytearray",
                payload,
                f"bytes={hex(result)} bytearray={hex(ba_result)}",
                args.log,
            )
            continue

        # I5 — ref-impl parity.
        ref_result = _ref_fletcher16(payload)
        try:
            _check_invariants(payload, result, ref_result, args.log)
        except AssertionError as exc:
            invariant_count += 1
            _record_crash("invariant", payload, str(exc), args.log)
            continue

    elapsed = time.monotonic() - t0
    rate = iters / elapsed if elapsed > 0 else 0.0

    print("=" * 72)
    print(f"harness_checksum   target=fletcher_pure.checksum  commit=5b8481a")
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
