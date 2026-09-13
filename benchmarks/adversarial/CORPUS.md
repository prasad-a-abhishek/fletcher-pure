# cycle_69/adversary/03 — Seed Corpus & Fuzzer Execution Run

**Target**: fletcher-pure v0.1.0 at commit `5b8481a` (post-fix-2, wt/cycle_69-fix2)
**Branch**: `wt/cycle_69-adversary-03`
**Author**: @default (slot-03 worker)
**Run window (UTC)**: 2026-09-13T06:12Z — 2026-09-13T06:16Z (≈4 min 30 s)

## 1. Methodology

### Corpus construction

The canonical seed corpus is committed at `benchmarks/adversarial/corpus/seed_corpus.json` as a single
JSON document with five sections:

| Section | Count | Purpose |
|---------|-------|---------|
| `rfc_3309_vectors` | 14 | Hand- and algorithm-derived reference vectors from RFC 3309 §5.1 + audit boundary cases. Every entry carries a stable id (R-NNN), base64-encoded input, and the textbook Fletcher-16 expected output. Verified against the package by `python -c "import fletcher_pure; ..."` — 14/14 match post-fix-2. |
| `boundary_length_classes` | 16 | Lengths covering empty (0), single (1), mod-255 wrap boundary (254, 255, 256, 257), two-wrap (510, 511), three-wrap (765 = 3×255), page boundaries (1020–1025), KiB (2048), u16 max (65535), and one past (65536). |
| `pattern_classes` | 7 | Input patterns (all-zeros, all-ones, single-byte repeats, alternating 0x00/0xFF, random uniform, seeded random) tested at the boundary lengths. |
| `adversarial_verify_sentinels` | 12 | Non-bytes values for `verify()` I1 probe (None, int, float/NaN/Inf, str, list, dict, tuple, object, memoryview, etc.). Each MUST raise TypeError per the module docstring contract. |
| `adversarial_expected_values` | 8 | Out-of-range or non-numeric `expected` values (-1, 0x10000, 2³², None, str, True, False, list) for `verify()` I2/I6 probes. |
| `long_input_dos_probe` | 2 | 1 MiB (audit S9) + 10 KiB random bytes for performance / overflow safety. |

Total: **59 distinct seed inputs** across 5 categories.

### Fuzzer execution

Three harnesses from slot-02 (`harness_checksum.py`, `harness_verify_roundtrip.py`, `harness_boundary.py`)
were executed with deterministic seeds. Each harness is stdlib-only, runs standalone, and was smoke-tested
with `--iters 100` before the full run.

| Harness | `--iters` | Seed | Wall time | Iter rate |
|---------|-----------|------|-----------|-----------|
| `harness_checksum.py` | 200,000 | 1700000001 | 96.78 s | 2,066 it/s |
| `harness_verify_roundtrip.py` | 200,000 | 1700000002 | 98.69 s | 2,027 it/s |
| `harness_boundary.py` | 10,000 | 1700000003 | 61.61 s | 2,922 assertions/s |
| **Total** | **420,000** + ~190k sub-assertions in boundary | | **≈4 min** | |

The boundary harness executes **6 test classes per iteration** (T1 RFC, T2 boundary, T3 closed-form,
T4 roundtrip, T5 DoS, T6 caller-safe), so the 10k-iter run produced **190,014 total assertions**.

### Environment

- Host: Linux container (kernel 6.12.67-linuxkit)
- Python: CPython 3.11.15, no extra packages
- fletcher_pure installed in editable mode (`pip install -e .`) at commit `5b8481a`
- No pytest/CI overhead — harnesses run standalone
- No ASan / UBSan (Python harnesses; C-extension sanitizers not applicable)

## 2. Per-harness results

### `harness_checksum.py` (target: `fletcher_pure.checksum`)

- **Iterations**: 200,000
- **Exit code**: 0
- **Raises**: 0
- **Invariant violations**: 0
- **Crash log**: not present (no crash recorded → log file removed by harness on clean startup)
- **Coverage**: `checksum()` body lines 15–20 hit on every iteration → **100% line coverage**
- **`run_stats_checksum.json`**: `benchmarks/adversarial/runs/run_stats_checksum.json`

Invariants probed: I1 (totality on bytes-like), I2 (range), I3 (determinism), I4 (bytearray equivalence),
I5 (ref-impl parity via inline `_ref_fletcher16`), I6 (RFC vectors).

Generator buckets exercised: random 0–1500 B, random 0–16 B, all-zeros 0–2048 B, all-ones 0–2048 B,
alternating 0–2048 B, boundary lengths [254, 255, 256, 257, 510, 511, 765, 7650], 10 000 B long random,
single-byte repeat 0–2048 B, empty bytes, seed re-emission every 1000 iters.

### `harness_verify_roundtrip.py` (target: `fletcher_pure.verify`)

- **Iterations**: 200,000
- **Exit code**: 0
- **Raises**: 0
- **Invariant violations**: 0
- **Coverage**: `verify()` body lines 36–38 hit (including the TypeError raise at line 37 via non-bytes
  sentinels) → **100% line coverage**; `checksum()` body also re-hit via roundtrip → 100% there too.
- **`run_stats_verify_roundtrip.json`**: `benchmarks/adversarial/runs/run_stats_verify_roundtrip.json`

Invariants probed: I1 (TypeError on non-bytes data), I2 (totality on safe `expected` types), I3
(roundtrip True), I4 (negative roundtrip False after low-bit flip), I5 (determinism), I6 (range parity),
I7 (RFC vector).

Generator buckets: same bytes-pattern mix as harness_checksum, plus `_gen_non_bytes_sentinel` covering
None / int / float+NaN+Inf / str / list / dict / tuple / memoryview / generator / object(), and
`_gen_expected` covering correct value, ^0x1, random XOR, in-range random, -1, 0x10000, 2³², None,
str, True/False.

### `harness_boundary.py` (target: both functions on boundary surfaces)

- **Boundary-iteration rounds**: 10,000
- **Exit code**: 0
- **Raises**: 0
- **Invariant violations**: 0
- **T1 RFC vectors**: 14/14 exact match
- **T2 boundary pairs**: 60,000 / 60,000 pkg == ref
- **T3 closed-form checks**: 60,000 / 60,000 (zeros→0, ones→0 for n≥1, 0xAB×1→0xABAB)
- **T4 roundtrip pairs**: 60,000 / 60,000 verify(payload, checksum(payload)) is True
- **T5 DoS probe**: 1 MiB input in 35 ms (0.7% of 5 s budget)
- **T6 caller-safe**: 12 sentinels × 5 expected values = 60 sub-checks, every one raised TypeError
- **Coverage**: both function bodies **100% line coverage** (verified via sys.settrace outside the
  harness)
- **`run_stats_boundary.json`**: `benchmarks/adversarial/runs/run_stats_boundary.json`

## 3. Cross-harness findings

- **Zero crashes, zero hangs, zero invariant violations across 590,014+ assertions.**
- The source-under-test (`fletcher_pure/__init__.py`, 38 LOC) implements the textbook Fletcher-16
  algorithm per RFC 3309 §5.1 exactly. The independent reference implementation carried inline in
  `harness_checksum.py` and `harness_boundary.py` (`_ref_fletcher16`) matches the package output on
  every iteration of every run.
- `verify()` raises `TypeError` on every non-bytes sentinel — the documented contract holds.
- `verify()` returns True for `verify(data, checksum(data))` on every bytes input — the central
  correctness invariant holds.
- Flipping the low bit of a valid checksum (`actual ^ 0x1`) causes `verify()` to return False on
  every iteration — false negatives (the dangerous direction) do not occur.

## 4. Audit-drift observations (forwarded to slot-04 triage)

These are doc/code drifts that surface during execution but were not flagged as code defects:

- **F-003** (carried from slot-01 audit): `VULN_AUDIT.md` describes `verify()` as "caller-safe" but the
  module docstring + the verified code say `verify()` raises `TypeError` on non-bytes data. The harness
  probes the correct contract. Slot-04 should consolidate this into the final finding table.
- **F-004 candidate** (new observation in slot-03): `harness_boundary.py` docstring I4 says
  "verify() is caller-safe on non-bytes data (returns False, never raises)" but the T6 test code in
  the same harness expects `TypeError`. The harness code is correct; only the docstring is wrong.
  Not a code defect — no impact on fuzz results. Worth a 1-line docstring patch in a follow-up.

No Critical, High, or Medium findings.

## 5. Reproduction

```bash
cd /root/projects/fletcher-pure
git checkout wt/cycle_69-adversary-03
pip install -e .

# Smoke (fast)
python benchmarks/adversarial/harnesses/harness_checksum.py --iters 1000 --seed 42
python benchmarks/adversarial/harnesses/harness_verify_roundtrip.py --iters 1000 --seed 42
python benchmarks/adversarial/harnesses/harness_boundary.py --iters 100 --seed 42

# Full reproduction (exact seeds used in this run)
python benchmarks/adversarial/harnesses/harness_checksum.py --iters 200000 --seed 1700000001
python benchmarks/adversarial/harnesses/harness_verify_roundtrip.py --iters 200000 --seed 1700000002
python benchmarks/adversarial/harnesses/harness_boundary.py --iters 10000 --seed 1700000003
```

Expected: each prints a 9-line summary, `raises=0 invariant_viols=0`, exit 0.

## 6. Verdict (slot-03 local)

**VERDICT: PROCEED_TO_TRIAGE** — clean fuzz run, zero findings, audit-doc drifts noted for slot-04.
