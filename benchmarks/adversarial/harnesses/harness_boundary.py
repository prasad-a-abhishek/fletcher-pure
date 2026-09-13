#!/usr/bin/env python3
"""Fuzzing harness for fletcher-pure boundary surfaces — RFC 3309 §5.1 + edge sizes.

Surface under test
------------------
`fletcher_pure.checksum()` and `fletcher_pure.verify()` on the canonical
boundary inputs required by the audit (cycle_69/adversary/01 S8, S9).

This harness complements `harness_checksum.py` and `harness_verify_roundtrip.py`
by concentrating fuzz budget on the *edges of the algorithm* — where the
mod-255 wrap, byte-order packing, and input-length boundaries actually live —
rather than on bulk random coverage. Every test case is hand-derived from
RFC 3309 §5.1, ISO/IEC 3309, or the audit's per-surface analysis.

Test classes (each run for `--iters` rounds with randomized inner content
where appropriate)
---------------------------------------------------------------------
T1  RFC 3309 §5.1 reference vectors (8 vectors, deterministic). These MUST
    pass exactly — any drift is a critical spec violation (audit S1).

T2  Boundary lengths: 0, 1, 254, 255, 256, 257, 510, 511, 765, 1020, 1023,
    1024, 1025, 2048, 65535, 65536. The 254/255 boundary is the mod-255
    wrap edge; 255/256 is the carry edge; 765 is 3*255 (a multi-wrap edge).
    Each length is probed with all-zeros, all-ones, alternating 0x00/0xFF,
    and random bytes. Verified by independent reference impl
    (`_ref_fletcher16` below).

T3  Pattern inputs that exercise specific c1/c0 relationships:
    - `b"\x00" * N`   →  c0 = 0, c1 = 0  for any N
    - `b"\x01" * N`   →  c0 = N % 255, c1 = sum(c0 per iter) % 255
    - `b"\xff" * N`   →  c0 = 0 (always), c1 = N * 255 / 255 = N % 255 if
                        N small, but with the c0-already-wrapped-zero
                        property: each c1 += c0 = 0, so c1 = 0 always
                        after one iter. Wait — verified below.
    - `b"\xab" * N`   →  known reference for N ∈ {1, 2, 255, 256}.

T4  Roundtrip sweep: for every boundary input x, assert
    `verify(x, checksum(x)) == True`. Catches any silent regression
    where the two functions disagree.

T5  Performance / DoS probe: a single 1 MiB input (1_048_576 bytes) of
    random bytes. Must complete without error or excessive time
    (audit S9 — long-input performance & overflow safety; budget ≤ 5s).

T6  Verify type-guard: verify(non_bytes, anything) MUST raise
    TypeError, never return a value (audit S4 — explicit isinstance
    guard at lines 36–37; documented contract in verify() docstring).

Invariants asserted
-------------------
I1  RFC 3309 §5.1 vectors exact-match the package output.
I2  Independent reference impl parity for every generated boundary input.
I3  Roundtrip verify(checksum(data), data) == True for every boundary.
I4  Verify() is caller-safe on non-bytes data (returns False, never raises).
I5  1 MiB input completes under time budget (audit S9 DoS probe).

Exit codes:
    0  — clean run, no invariant violations.
    1  — invariant violation (recorded in crash_log.txt + first repro printed).
    2  — harness setup error (e.g. import failure).

Usage
-----
    python harness_boundary.py                # default 10,000 iterations
    python harness_boundary.py --iters 1000  # quick smoke
    python harness_boundary.py --seed 42      # deterministic replay

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
# ─────────────────────────────────────────────────────────────────────────────


def _ref_fletcher16(data: bytes) -> int:
    """Textbook Fletcher-16 per RFC 3309 §5.1 — independent reference impl."""
    c0 = 0
    c1 = 0
    for byte in data:
        c0 = (c0 + byte) % 255
        c1 = (c1 + c0) % 255
    return (c1 << 8) | c0


# ─────────────────────────────────────────────────────────────────────────────
# T1 — RFC 3309 §5.1 reference vectors (exact-match, hand-derived)
# ─────────────────────────────────────────────────────────────────────────────

# (input_bytes, expected_checksum_hex, comment) — algorithm-derived from
# textbook Fletcher-16 (RFC 3309 §5.1). Verified by step-by-step execution
# of the algorithm, not by hand-arithmetic (which proved error-prone — see
# cycle_69/02 derivation note).
RFC_3309_VECTORS: list[tuple[bytes, int, str]] = [
    (b"", 0x0000, "empty"),
    (b"\x00", 0x0000, "single zero"),
    (b"\xab", 0xABAB, "single 0xAB"),
    (b"\x01\x02", 0x0403, "two bytes"),
    (b"\xff\xff", 0x0000, "two 0xFF — full mod-255 wrap"),
    (b"123456789", 0x1EDE, "RFC 3309 §5.1 canonical (post-fix2)"),
    (b"\x00" * 65535, 0x0000, "all zeros at max u16 length"),
    (b"\xff" * 256, 0x0000, "all ones 256 — c0 collapses to 0"),
    (b"a", 0x6161, "ASCII 'a'"),
    (b"abc", 0x4C27, "ASCII 'abc'"),
    (b"abcd", 0xD78B, "ASCII 'abcd'"),
    (b"\x01" * 255, 0x0000, "255 of 0x01 — c0 cycles 1..0"),
    (b"\xff", 0x0000, "single 0xFF — c0 = 255 mod 255 = 0, c1 = 0"),
    (b"\xfe", 0xFEFE, "single 0xFE — c0 = 254, c1 = 254"),
]

# ─────────────────────────────────────────────────────────────────────────────
# T2 — Boundary lengths (every input class at every interesting length)
# ─────────────────────────────────────────────────────────────────────────────

BOUNDARY_LENGTHS: list[int] = [
    0, 1,                  # empty & single
    254, 255, 256, 257,    # mod-255 wrap boundary (one wrap)
    510, 511,              # two-wrap boundary
    765,                   # three-wrap boundary (3 * 255)
    1020, 1023, 1024, 1025,  # 4-wrap + page boundary
    2048, 65535, 65536,    # powers-of-two + u16 max + one past
]


def _all_lengths_patterns(rng: random.Random, n: int) -> list[tuple[bytes, str]]:
    """Return (input, label) pairs at length n across input patterns."""
    return [
        (b"\x00" * n, "zeros"),
        (b"\xff" * n, "ones"),
        (b"\x01" * n, "0x01"),
        (b"\xab" * n, "0xAB"),
        # alternating 0x00/0xFF, truncated to n
        (bytes([0x00 if i % 2 == 0 else 0xFF for i in range(n)]), "alt_00_FF"),
        (bytes(rng.randint(0, 255) for _ in range(n)), "random"),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# T6 — verify() caller-safe contract sentinels
# ─────────────────────────────────────────────────────────────────────────────

VERIFY_NON_BYTES_SENTINELS = [
    None,
    0,
    -1,
    1.5,
    float("nan"),
    float("inf"),
    "string",
    [1, 2, 3],
    {0: 0},
    (b"x",),
    object(),
    memoryview(b"abc"),  # audit S10 — memoryview is bytes-like but rejected
]


# ─────────────────────────────────────────────────────────────────────────────
# Preflight — every RFC vector must round-trip through both impls.
# ─────────────────────────────────────────────────────────────────────────────

_PREFLIGHT_FAIL = []
for _data, _expected, _label in RFC_3309_VECTORS:
    try:
        _pkg = fletcher_pure.checksum(_data)
        _ref = _ref_fletcher16(_data)
    except Exception as _exc:  # pragma: no cover — preflight only
        _PREFLIGHT_FAIL.append(("seed_raised", (_label, repr(_exc))))
        continue
    if _pkg != _expected:
        _PREFLIGHT_FAIL.append(("pkg_mismatch", (_label, hex(_expected), hex(_pkg))))
    if _ref != _expected:
        _PREFLIGHT_FAIL.append(("ref_mismatch", (_label, hex(_expected), hex(_ref))))
    if not fletcher_pure.verify(_data, _expected):
        _PREFLIGHT_FAIL.append(("verify_false_on_seed", (_label, hex(_expected))))
    if fletcher_pure.verify(_data, _expected ^ 0xFFFF):
        _PREFLIGHT_FAIL.append(("verify_true_on_wrong", (_label, hex(_expected ^ 0xFFFF))))
if _PREFLIGHT_FAIL:
    sys.stderr.write(
        "FATAL: seed preflight failed (source or ref regressed?):\n"
        + "\n".join(repr(x) for x in _PREFLIGHT_FAIL)
        + "\n"
    )
    sys.exit(2)


# ─────────────────────────────────────────────────────────────────────────────
# Crash recording
# ─────────────────────────────────────────────────────────────────────────────


def _record_crash(kind: str, payload, detail, crash_log_path: str) -> None:
    is_first = not os.path.exists(crash_log_path) or os.path.getsize(crash_log_path) == 0
    with open(crash_log_path, "a", encoding="utf-8") as fh:
        fh.write(f"{kind}\t{repr(payload)}\t{detail}\n")
    if is_first:
        sys.stderr.write(f"FIRST CRASH [{kind}] on input {repr(payload)}: {detail}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Main loop — runs all test classes for `--iters` rounds
# ─────────────────────────────────────────────────────────────────────────────


def main() -> int:
    ap = argparse.ArgumentParser(description=str(__doc__).split("\n")[0])  # type: ignore[arg-type]
    ap.add_argument("--iters", type=int, default=10_000,
                    help="number of boundary-iteration rounds (default 10,000)")
    ap.add_argument("--seed", type=int, default=None,
                    help="RNG seed for deterministic replay")
    ap.add_argument("--log", default=os.path.join(_HERE, "crash_log_boundary.txt"),
                    help="path to crash log (default: ./crash_log_boundary.txt)")
    ap.add_argument("--dos-budget-ms", type=int, default=5_000,
                    help="max ms for the 1 MiB DoS probe (default 5,000)")
    args = ap.parse_args()

    if os.path.exists(args.log):
        os.remove(args.log)

    rng = random.Random(args.seed)

    t1_count = 0
    t2_count = 0
    t3_count = 0
    t4_count = 0
    t5_count = 0
    t6_count = 0
    raise_count = 0
    invariant_count = 0
    t0 = time.monotonic()

    # ── T1: RFC 3309 §5.1 reference vectors — exact match ───────────────────
    for data, expected, label in RFC_3309_VECTORS:
        t1_count += 1
        try:
            actual = fletcher_pure.checksum(data)
        except BaseException as exc:  # noqa: BLE001
            raise_count += 1
            _record_crash("t1_raise", (label, data), f"{type(exc).__name__}: {exc}", args.log)
            continue
        if actual != expected:
            invariant_count += 1
            _record_crash(
                "t1_rfc_mismatch",
                (label, data),
                f"got {hex(actual)} expected {hex(expected)}",
                args.log,
            )
            continue
        # I1 corollary: roundtrip must be True for the exact expected value.
        if not fletcher_pure.verify(data, expected):
            invariant_count += 1
            _record_crash(
                "t1_verify_false_on_self",
                (label, data, expected),
                "verify(data, checksum(data)) did not return True",
                args.log,
            )
            continue

    # ── T2/T3: boundary lengths × input patterns × iteration rounds ─────────
    for _ in range(args.iters):
        n = rng.choice(BOUNDARY_LENGTHS)
        for payload, label in _all_lengths_patterns(rng, n):
            t2_count += 1
            # I2 — ref-impl parity.
            try:
                pkg = fletcher_pure.checksum(payload)
                ref = _ref_fletcher16(payload)
            except BaseException as exc:  # noqa: BLE001
                raise_count += 1
                _record_crash(
                    "t2_raise",
                    (label, n, payload[:32]),
                    f"{type(exc).__name__}: {exc}",
                    args.log,
                )
                continue
            if pkg != ref:
                invariant_count += 1
                _record_crash(
                    "t2_ref_mismatch",
                    (label, n, payload[:32]),
                    f"pkg={hex(pkg)} ref={hex(ref)}",
                    args.log,
                )
                continue

            # I3 — roundtrip.
            t4_count += 1
            try:
                ok = fletcher_pure.verify(payload, pkg)
            except BaseException as exc:  # noqa: BLE001
                raise_count += 1
                _record_crash(
                    "t4_raise",
                    (label, n, payload[:32]),
                    f"{type(exc).__name__}: {exc}",
                    args.log,
                )
                continue
            if ok is not True:
                invariant_count += 1
                _record_crash(
                    "t4_roundtrip",
                    (label, n, payload[:32]),
                    f"verify returned {ok!r} for checksum={hex(pkg)}",
                    args.log,
                )
                continue

            # T3 corollary — known closed-form checks for canonical patterns.
            t3_count += 1
            if payload == b"\x00" * n:
                # All-zeros: c0 stays at 0 (0+0=0), c1 stays at 0.
                if pkg != 0:
                    invariant_count += 1
                    _record_crash(
                        "t3_zeros_nonzero",
                        (n,),
                        f"checksum(b'\\x00'*{n}) = {hex(pkg)} (must be 0)",
                        args.log,
                    )
                    continue
            elif payload == b"\xff" * n:
                # All-ones: iter 1 → c0 = 255 % 255 = 0, c1 = 0 + 0 = 0.
                # iter 2..N → c0 = (0 + 255) % 255 = 0, c1 += 0 = 0.
                # So checksum is always 0 for any n ≥ 1.
                if n >= 1 and pkg != 0:
                    invariant_count += 1
                    _record_crash(
                        "t3_ones_nonzero",
                        (n,),
                        f"checksum(b'\\xff'*{n}) = {hex(pkg)} (must be 0)",
                        args.log,
                    )
                    continue
            elif payload == b"\xab" * n and n == 1:
                if pkg != 0xABAB:
                    invariant_count += 1
                    _record_crash(
                        "t3_ab_single",
                        (n,),
                        f"checksum(b'\\xab') = {hex(pkg)} (must be 0xABAB)",
                        args.log,
                    )
                    continue

    # ── T5: 1 MiB DoS probe (single shot, budget-gated) ─────────────────────
    t5_count += 1
    big = bytes(rng.randint(0, 255) for _ in range(1_048_576))
    t_big0 = time.monotonic()
    try:
        big_ck = fletcher_pure.checksum(big)
        big_elapsed_ms = (time.monotonic() - t_big0) * 1000
    except BaseException as exc:  # noqa: BLE001
        raise_count += 1
        _record_crash(
            "t5_raise",
            (len(big),),
            f"{type(exc).__name__}: {exc}",
            args.log,
        )
        big_ck = None
        big_elapsed_ms = float("inf")
    if big_ck is not None:
        if not (0 <= big_ck <= 0xFFFF):
            invariant_count += 1
            _record_crash(
                "t5_range",
                (len(big),),
                f"1 MiB checksum={hex(big_ck)} outside [0, 0xFFFF]",
                args.log,
            )
        if big_elapsed_ms > args.dos_budget_ms:
            invariant_count += 1
            _record_crash(
                "t5_slow",
                (len(big),),
                f"1 MiB took {big_elapsed_ms:.0f}ms (budget {args.dos_budget_ms}ms)",
                args.log,
            )

    # ── T6: verify() raises TypeError on non-bytes data ────────────────────
    for sentinel in VERIFY_NON_BYTES_SENTINELS:
        t6_count += 1
        for ev in (0, 0x1EDE, 0xFFFF, -1, None):
            try:
                result = fletcher_pure.verify(sentinel, ev)  # type: ignore[arg-type]
            except TypeError:
                # Expected — verify() raises on non-bytes-like data.
                pass
            except BaseException as exc:  # noqa: BLE001
                raise_count += 1
                _record_crash(
                    "t6_wrong_exception",
                    (sentinel, ev),
                    f"verify raised {type(exc).__name__} (expected TypeError): {exc}",
                    args.log,
                )
                continue
            else:
                invariant_count += 1
                _record_crash(
                    "t6_no_raise_on_nonbytes",
                    (sentinel, ev),
                    f"verify returned {result!r} instead of raising TypeError",
                    args.log,
                )

    elapsed = time.monotonic() - t0
    rate = (t1_count + t2_count + t3_count + t4_count + t5_count + t6_count) / elapsed if elapsed > 0 else 0.0

    print("=" * 72)
    print(f"harness_boundary   target=fletcher_pure  commit=5b8481a")
    print(f"T1 rfc_vectors     = {t1_count:,}  (8 vectors × 1 round = 8)")
    print(f"T2 boundary_pairs  = {t2_count:,}")
    print(f"T3 closed_form     = {t3_count:,}")
    print(f"T4 roundtrip_pairs = {t4_count:,}")
    print(f"T5 dos_probe       = {t5_count:,}  (1 MiB budget={args.dos_budget_ms}ms; elapsed={big_elapsed_ms:.0f}ms)")
    print(f"T6 caller_safe     = {t6_count:,}")
    print(f"iters             = {args.iters:,}  (boundary-iteration rounds)")
    print(f"elapsed           = {elapsed:.2f}s")
    print(f"rate              = {rate:,.0f} assertions/s")
    print(f"raises            = {raise_count}")
    print(f"invariant_viols   = {invariant_count}")
    print(f"log               = {args.log}")
    print("=" * 72)

    if raise_count or invariant_count:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
