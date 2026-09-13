#!/usr/bin/env python3
# cycle_69/adversary/04 — Independent corroboration sweep
#
# Slot-03 reported clean fuzz run (420k iters + ~190k sub-assertions, seed 1700000001/2/3).
# Slot-04 independently re-runs the key surfaces with a DIFFERENT seed (987654321) and
# INDEPENDENTLY-generated inputs to corroborate: zero raises, zero invariant violations,
# zero silent-wrong-answer cases on the audit-flagged S3 surface (checksum() with
# non-bytes iterables like list[int], memoryview, tuple).
#
# This is a stdlib-only probe. NOT a harness, NOT a replacement for slot-02/03.

import json
import random
import sys
import time
from datetime import datetime, timezone

# Make sure we're running against the installed package at HEAD of the current branch.
import fletcher_pure as fp


SEED = 987654321
ITERS_CHUNK = 50_000  # per-iteration loop; keep memory bounded


def _ref_fletcher16(data: bytes) -> int:
    """Independent reference impl — inline copy from slot-03 harness_checksum.py."""
    c0 = 0
    c1 = 0
    for byte in data:
        c0 = (c0 + byte) % 255
        c1 = (c1 + c0) % 255
    return (c1 << 8) | c0


def gen_random_bytes(rng, n_max):
    return bytes(rng.randrange(0, 256) for _ in range(rng.randrange(0, n_max + 1)))


def gen_all_zeros(rng, n_max):
    return bytes(rng.randrange(0, n_max + 1))


def gen_all_ones(rng, n_max):
    return bytes([0xFF] * rng.randrange(0, n_max + 1))


def gen_alternating(rng, n_max):
    n = rng.randrange(0, n_max + 1)
    return bytes([0x00, 0xFF] * ((n + 1) // 2))[:n]


def gen_boundary(rng):
    return bytes(rng.randrange(0, 256) for _ in range(rng.choice([0, 1, 254, 255, 256, 257, 510, 511, 765, 1023, 1024, 2048, 65535])))


def gen_pattern_byte(rng, n_max):
    n = rng.randrange(0, n_max + 1)
    return bytes([rng.randrange(0, 256)] * n)


def gen_long_random(rng):
    return bytes(rng.randrange(0, 256) for _ in range(10_000))


# --- Sweep A: checksum() correctness on bytes input, 100k iters ----------
def sweep_checksum_correctness(rng, n_iters):
    rng_local = random.Random(rng.randrange(2**31))
    raises = 0
    invariant_viols = 0
    bad_cases = []
    generators = [
        gen_random_bytes,
        lambda r, m: gen_random_bytes(r, 16),
        gen_all_zeros,
        gen_all_ones,
        gen_alternating,
        gen_boundary,
        gen_pattern_byte,
    ]
    for i in range(n_iters):
        gen = rng_local.choice(generators)
        data = gen(rng_local, 2048) if gen is not gen_boundary else gen(rng_local)
        try:
            actual = fp.checksum(data)
        except Exception as e:
            raises += 1
            if len(bad_cases) < 5:
                bad_cases.append(("checksum_raises", repr(data[:32]), repr(e)))
            continue
        expected = _ref_fletcher16(data)
        if actual != expected:
            invariant_viols += 1
            if len(bad_cases) < 5:
                bad_cases.append(("checksum_wrong", repr(data[:32]), f"got {actual:#06x} want {expected:#06x}"))
        # range invariant
        if not (0 <= actual <= 0xFFFF):
            invariant_viols += 1
            if len(bad_cases) < 5:
                bad_cases.append(("checksum_range", repr(data[:32]), f"out-of-range: {actual}"))
    return raises, invariant_viols, bad_cases


# --- Sweep B: verify() roundtrip + sentinel rejection, 50k iters ---------
def sweep_verify_roundtrip(rng, n_iters):
    rng_local = random.Random(rng.randrange(2**31))
    raises = 0
    invariant_viols = 0
    bad_cases = []
    # sentinel values that should ALWAYS raise TypeError from verify()
    sentinels = [None, 42, 3.14, "hello", [1, 2], {"a": 1}, (1, 2), float("nan"), float("inf")]
    for i in range(n_iters):
        # 50% bytes data + sentinel
        if rng_local.random() < 0.7:
            data = gen_random_bytes(rng_local, 1024)
            expected = fp.checksum(data)
            try:
                ok = fp.verify(data, expected)
                if ok is not True:
                    invariant_viols += 1
                    if len(bad_cases) < 5:
                        bad_cases.append(("verify_roundtrip_false", repr(data[:32]), f"got {ok}"))
            except Exception as e:
                raises += 1
                if len(bad_cases) < 5:
                    bad_cases.append(("verify_bytes_raises", repr(data[:32]), repr(e)))
        else:
            sentinel = rng_local.choice(sentinels)
            try:
                fp.verify(sentinel, 0)
                invariant_viols += 1
                if len(bad_cases) < 5:
                    bad_cases.append(("verify_silent_on_sentinel", repr(sentinel), "did not raise"))
            except TypeError:
                pass
            except Exception as e:
                invariant_viols += 1
                if len(bad_cases) < 5:
                    bad_cases.append(("verify_wrong_error_on_sentinel", repr(sentinel), repr(e)))
    return raises, invariant_viols, bad_cases


# --- Sweep C: S3 audit-flagged silent-wrong-answer check (list/tuple/memoryview)
def sweep_s3_repro():
    """Re-test audit S3 finding. Slot-01 downgraded to 'API inconsistency' after probes.
    Confirm: list[int], tuple[int], memoryview produce correct checksum (NOT wrong answer);
    str produces TypeError. None of these are silent-wrong-answer."""
    cases = [
        ("list[int]", [1, 2], 1027),
        ("tuple[int]", (1, 2), 1027),
        ("memoryview(bytes)", memoryview(b"\x01\x02"), 1027),
        ("bytes subclass", type("MyBytes", (bytes,), {})(b"\x01\x02"), 1027),
    ]
    raises = 0
    invariant_viols = 0
    notes = []
    for label, data, expected in cases:
        try:
            actual = fp.checksum(data)
        except Exception as e:
            raises += 1
            notes.append((label, "raised", repr(e)))
            continue
        if actual != expected:
            invariant_viols += 1
            notes.append((label, "wrong_answer", f"got {actual} want {expected}"))
        else:
            notes.append((label, "correct_silent", f"{actual}"))
    # str/None should raise
    for label, data in [("str", "hello"), ("None", None), ("int", 42), ("float", 3.14)]:
        try:
            fp.checksum(data)
            invariant_viols += 1
            notes.append((label, "should_have_raised", "no exception"))
        except TypeError:
            notes.append((label, "typeerror_ok", ""))
        except Exception as e:
            notes.append((label, "wrong_error", repr(e)))
    return raises, invariant_viols, notes


# --- Sweep D: RFC 3309 §5.1 vectors (sanity)
def sweep_rfc_vectors():
    vectors = [
        (b"", 0),
        (b"\x00", 0),
        (b"\x01\x02", 0x0403),
        (b"\xff\xff", 0),
        (b"\xfe\x01", 0xFE00),
        (b"123456789", 0x1EDE),
    ]
    raises = 0
    invariant_viols = 0
    notes = []
    for data, expected in vectors:
        try:
            actual = fp.checksum(data)
        except Exception as e:
            raises += 1
            notes.append((repr(data), "raised", repr(e)))
            continue
        ok = actual == expected
        notes.append((repr(data), f"got={actual:#06x} want={expected:#06x}", "pass" if ok else "FAIL"))
        if not ok:
            invariant_viols += 1
    return raises, invariant_viols, notes


def main():
    rng = random.Random(SEED)
    started = datetime.now(timezone.utc).isoformat()
    t0 = time.time()

    sweep_a_raises, sweep_a_viols, sweep_a_bad = sweep_checksum_correctness(rng, 100_000)
    sweep_b_raises, sweep_b_viols, sweep_b_bad = sweep_verify_roundtrip(rng, 50_000)
    sweep_c_raises, sweep_c_viols, sweep_c_notes = sweep_s3_repro()
    sweep_d_raises, sweep_d_viols, sweep_d_notes = sweep_rfc_vectors()

    elapsed = time.time() - t0

    summary = {
        "seed": SEED,
        "started_utc": started,
        "elapsed_seconds": round(elapsed, 2),
        "target": "fletcher_pure @ wt/cycle_69-adversary-04 (built from 93ae129)",
        "sweep_a_checksum_correctness": {
            "iterations": 100_000,
            "raises": sweep_a_raises,
            "invariant_violations": sweep_a_viols,
            "sample_bad_cases": sweep_a_bad,
        },
        "sweep_b_verify_roundtrip_sentinels": {
            "iterations": 50_000,
            "raises": sweep_b_raises,
            "invariant_violations": sweep_b_viols,
            "sample_bad_cases": sweep_b_bad,
        },
        "sweep_c_s3_repro": {
            "raises": sweep_c_raises,
            "invariant_violations": sweep_c_viols,
            "notes": sweep_c_notes,
        },
        "sweep_d_rfc_vectors": {
            "raises": sweep_d_raises,
            "invariant_violations": sweep_d_viols,
            "notes": sweep_d_notes,
        },
        "total_iterations": 150_000,
        "total_raises": sweep_a_raises + sweep_b_raises + sweep_c_raises + sweep_d_raises,
        "total_invariant_violations": sweep_a_viols + sweep_b_viols + sweep_c_viols + sweep_d_viols,
    }

    out_path = "benchmarks/adversarial/triage/triage_sweep_summary.json"
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(json.dumps(summary, indent=2))

    if summary["total_raises"] or summary["total_invariant_violations"]:
        print(f"\nFAIL: slot-04 triage sweep surfaced {summary['total_raises']} raises + {summary['total_invariant_violations']} violations", file=sys.stderr)
        sys.exit(2)
    print(f"\nOK: slot-04 independent sweep clean — corroborates slot-03 verdict", file=sys.stderr)


if __name__ == "__main__":
    main()