# cycle_69/adversary/04 — Triage, Minimize, and Rank Findings (fletcher-pure)

**Target**: fletcher-pure v0.1.0 at commit `5b8481a` (post-fix-2)
**Branch**: `wt/cycle_69-adversary-04` (built from `wt/cycle_69-adversary-03` @ `93ae129`)
**Slot**: 04 of 5 in the canonical adversary chain (cycle_69)
**Author**: @default (slot-04 worker)
**Window**: 2026-09-13 (one-shot triage pass)
**Inputs**:
- `benchmarks/adversarial/VULN_AUDIT.md` (slot-01, 509 lines, 10 surfaces)
- `benchmarks/adversarial/harnesses/{harness_checksum,harness_verify_roundtrip,harness_boundary}.py` (slot-02)
- `benchmarks/adversarial/CORPUS.md` + `benchmarks/adversarial/corpus/seed_corpus.json` + `benchmarks/adversarial/runs/run_stats_*.json` (slot-03)

---

## 1. Methodology

### 1.1 Slot-03 evidence reviewed

| Harness | Iters | Sub-assertions | Raises | Invariant viols | Crash | Coverage |
|---------|-------|----------------|--------|-----------------|-------|----------|
| `harness_checksum.py` | 200,000 | — | 0 | 0 | 0 | `checksum()` body 100% |
| `harness_verify_roundtrip.py` | 200,000 | — | 0 | 0 | 0 | `verify()` body 100% (incl. TypeError raise path at line 37) |
| `harness_boundary.py` | 10,000 | 190,014 | 0 | 0 | 0 | both bodies 100% |
| **Total (slot-03)** | **420,000** | **190,014** | **0** | **0** | **0** | **both 100%** |

Verdict per slot-03: **CLEAN** (3/3 harnesses exit 0; reference impl parity on every iteration).

### 1.2 Slot-04 independent corroboration sweep

To rule out slot-03 being a lucky-seed false negative, slot-04 ran an INDEPENDENT sweep with
a DIFFERENT seed (`987654321`, vs slot-03's `1700000001/2/3`) and INDEPENDENTLY-generated inputs:

| Sweep | Iters | Raises | Invariant viols | Verdict |
|-------|-------|--------|-----------------|---------|
| **A** — `checksum()` correctness across 7 generator buckets | 100,000 | 0 | 0 | CLEAN |
| **B** — `verify()` roundtrip + 9-sentinel rejection | 50,000 | 0 | 0 | CLEAN |
| **C** — S3 audit-flagged silent-wrong-answer hypothesis probe (8 cases: list/tuple/memoryview/bytes-subclass + str/None/int/float) | 8 | 0 | 0 | CLEAN; **S3 silent-wrong-answer hypothesis REFUTED** |
| **D** — RFC 3309 §5.1 reference vectors (6 vectors) | 6 | 0 | 0 | 6/6 PASS |
| **Total (slot-04)** | **150,014** | **0** | **0** | **CLEAN** |

**Combined slot-03 + slot-04: 570,000 iterations + 190,014 sub-assertions + 8 targeted S3 probes = zero crashes, zero raises, zero invariant violations, zero silent-wrong-answer cases.**

The independent reference implementation `_ref_fletcher16` (inline copy from slot-03
harness_checksum.py) matched the package output on every iteration of every sweep.

### 1.3 Reproduction artifacts (slot-04)

- `benchmarks/adversarial/triage/triage_independent_sweep.py` — standalone stdlib-only probe (no atheris, no native deps), 4 sweeps A/B/C/D
- `benchmarks/adversarial/triage/triage_sweep_summary.json` — machine-readable summary of slot-04 sweep results
- `benchmarks/adversarial/findings.jsonl` — canonical 5-finding record (1 INFO clean + 2 Medium + 1 Low + 1 Info)

---

## 2. Findings ranked by severity

| # | ID       | Sev     | Category            | Status                     | Cycle 70? |
|---|----------|---------|---------------------|----------------------------|-----------|
| 1 | FIND-NONE| INFO    | fuzz_no_finding     | none                       | —         |
| 2 | FIND-M1  | MEDIUM  | api_consistency     | accepted-known-deferrable  | ✓         |
| 3 | FIND-M2  | MEDIUM  | docs_drift          | accepted-known-deferrable  | ✓         |
| 4 | FIND-L1  | LOW     | harness_docstring_drift | accepted-known-deferrable | ✓         |
| 5 | FIND-I1  | INFO    | algorithmic_limitation | info-only                | —         |

### Severity counts

| Severity | Count | Code defects? | Ship-blocking? |
|----------|-------|---------------|----------------|
| Critical | 0     | —             | —              |
| High     | 0     | —             | —              |
| Medium   | 2     | 0             | No (audit-deferred; defensive-coding only) |
| Low      | 1     | 0             | No (doc drift only) |
| Info     | 2     | 0             | No             |
| **Total**| **5** | **0**         | **No**         |

---

## 3. Per-finding minimization + disposition

### FIND-NONE — INFO / fuzz_no_finding

- **Min repro**: `python benchmarks/adversarial/harnesses/harness_checksum.py --iters 200000 --seed 1700000001 && python benchmarks/adversarial/harnesses/harness_verify_roundtrip.py --iters 200000 --seed 1700000002 && python benchmarks/adversarial/harnesses/harness_boundary.py --iters 10000 --seed 1700000003 && python benchmarks/adversarial/triage/triage_independent_sweep.py`
- **Expected**: clean exit (0 raises, 0 invariant violations)
- **Actual**: clean exit — 570k iters + 190k sub-assertions + 8 S3 probes, every invariant held
- **Disposition**: recorded for FUZZING_REPORT.md context in slot-05

### FIND-M1 — MEDIUM / api_consistency (S3 from audit)

- **Audit claim (cycle_69/01 §3 S3)**: `checksum()` "silent wrong answer" hypothesis on `str`/`list`/`memoryview` input
- **Probe downgrade (audit §3 S3 inline + slot-01 Appendix A2)**: downgraded to "API inconsistency / contract enforcement gap" after targeted probes showed:
  - `str` input → `TypeError: unsupported operand +: 'int' and 'str'` (NOT silent)
  - `list[int]`, `tuple[int]`, `memoryview(bytes)`, `bytes subclass` → all produce CORRECT Fletcher-16 value (NOT silent wrong)
  - `None`, `int`, `float`, `dict`, `list[bytearray]` → all raise TypeError cleanly
- **Slot-04 sweep_c re-verification** with independent seed `987654321`: 8/8 cases match the audit's downgraded assessment
- **Min repro**: `python -c 'import fletcher_pure as fp; fp.checksum("hello")'` (1 line; TypeError raised with arithmetic message, not the symmetric "data must be bytes or bytearray" that verify() would give)
- **Disposition**: ACCEPTED-KNOWN-DEFERRABLE. Audit-recommended fix (cycle 70 candidate):
  ```python
  def checksum(data: bytes) -> int:
      if not isinstance(data, (bytes, bytearray)):
          raise TypeError("data must be bytes or bytearray")
      c0 = 0; c1 = 0
      for byte in data:
          c0 = (c0 + byte) % 255
          c1 = (c1 + c0) % 255
      return (c1 << 8) | c0
  ```
  Pure API symmetry; ~50 ns runtime cost per call; makes the two functions raise the same TypeError for the same logical misuse. **Not blocking ship.** No security or correctness impact — only an inconsistent error surface.

### FIND-M2 — MEDIUM / docs_drift (D1 from audit)

- **Location**: `tests/COVERAGE.md` line 6 — single AC2 cell still says `checksum(b"\\x00") == 257`
- **Audit evidence**: `spec.md` AC2 (line 81-82) was fixed at commit 5b8481a to say `== 0`; `tests/test_spec_vectors.py::test_ac2_single_zero_byte` line 15 asserts `== 0`; only `COVERAGE.md` is stale
- **Min repro**: `grep -n 'AC2' tests/COVERAGE.md spec.md tests/test_spec_vectors.py` (3-line command)
- **Disposition**: ACCEPTED-KNOWN-DEFERRABLE. Trivial 1-line doc edit. **Not blocking ship.**

### FIND-L1 — LOW / harness_docstring_drift (F-003 + F-004 consolidated)

- **Location**: `benchmarks/adversarial/harnesses/harness_verify_roundtrip.py` module docstring — one bullet says "verify() is caller-safe on non-bytes data (returns False, never raises)" but the actual contract is "raises TypeError"
- **Evidence**: harness code itself is correct (T6 in boundary + verify_roundtrip both assert TypeError); only the docstring is wrong
- **Min repro**: `grep -n 'caller-safe' benchmarks/adversarial/harnesses/harness_verify_roundtrip.py`
- **Disposition**: ACCEPTED-KNOWN-DEFERRABLE. Trivial docstring fix. **Not blocking ship.**

### FIND-I1 — INFO / algorithmic_limitation

- **Source**: audit cycle_69/01 §5 I-3 (Fletcher-16 16-bit state; README disclaims cryptographic use)
- **Disposition**: INFO-ONLY. Recorded for slot-05 FUZZING_REPORT.md completeness.

---

## 4. Reproduction instructions (slot-04 independent sweep)

```bash
cd /root/projects/fletcher-pure
git checkout wt/cycle_69-adversary-04
pip install -e .

# Slot-04 independent corroboration sweep (seed 987654321, ~30s wall)
python benchmarks/adversarial/triage/triage_independent_sweep.py

# Inspect summary
cat benchmarks/adversarial/triage/triage_sweep_summary.json
```

Expected: exit 0; prints "OK: slot-04 independent sweep clean — corroborates slot-03 verdict" to stderr; JSON summary shows `total_raises=0` + `total_invariant_violations=0` + every RFC vector passes.

To also reproduce slot-03 (different seeds, ~4 min):

```bash
python benchmarks/adversarial/harnesses/harness_checksum.py --iters 200000 --seed 1700000001
python benchmarks/adversarial/harnesses/harness_verify_roundtrip.py --iters 200000 --seed 1700000002
python benchmarks/adversarial/harnesses/harness_boundary.py --iters 10000 --seed 1700000003
```

---

## 5. Verdict

**VERDICT: PROCEED_TO_REPORT**

Rationale:
- 0 Critical, 0 High findings
- 2 Medium findings are audit-deferred to cycle 70 (defensive-coding + docs drift only)
- 1 Low finding is doc drift only
- 1 Info finding is documented algorithmic limitation (16-bit state)
- **0 ship-blocking findings**
- Independent slot-04 sweep (150k iters, different seed, independent inputs) corroborates the clean slot-03 fuzz run (420k iters + 190k sub-assertions)
- The audit's initial S3 "silent wrong answer" hypothesis is **REFUTED by probe evidence** — `list[int]`/`tuple[int]`/`memoryview(bytes)`/`bytes subclass` all produce CORRECT Fletcher-16 values; `str`/`None`/`int`/`float` raise TypeError cleanly
- Combined slot-03 + slot-04: **570,000 iterations + 190,014 sub-assertions + 8 targeted S3 probes — zero crashes, zero raises, zero invariant violations**

Slot-05 may now author the canonical FUZZING_REPORT.md with confidence that the verdict line will read `VERDICT: SHIP` (no Critical/High; Medium findings are deferred-only and non-blocking per cycle_64 anti-chronic breakthrough triage threshold rule: Critical/High ONLY triggers a fix card; Medium/Low continue to ship).

---

## 6. Carry-forward to cycle 70

| ID      | Sev    | Fix one-liner |
|---------|--------|---------------|
| FIND-M1 | MEDIUM | Add `if not isinstance(data, (bytes, bytearray)): raise TypeError("data must be bytes or bytearray")` to `checksum()` line 15 |
| FIND-M2 | MEDIUM | Edit `tests/COVERAGE.md` line 6 to `AC2: checksum(b\"\\x00\") == 0` |
| FIND-L1 | LOW    | Update `harness_verify_roundtrip.py` module docstring: replace "verify() is caller-safe on non-bytes data (returns False, never raises)" with "verify() raises TypeError on non-bytes data" |

All three are 1-line doc/code edits. No code defect is ship-blocking.

---

*End of cycle_69/adversary/04 triage.*