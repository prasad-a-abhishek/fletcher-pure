# QA Report — fletcher-pure v0.1.0 (cycle 69 re-run)

## Summary
The builder fixed one of two prior CRITICAL findings (README Quick Start section now has working `pip install -e .`). However, the spec-integrity finding was only partially remediated: the README and implementation now both agree on `checksum(b"\x00") == 0`, but the README still contains a broken GitHub install URL (line 94) AND the spec.md AC2 value (257) contradicts both the implementation (0) and the README's stated `checksum(b"\x00") == 0`. A third spec-integrity discrepancy also surfaced: the spec's reference vector `checksum(b"123456789") == 7662` doesn't match the implementation (7902). 567/567 tests pass in fresh-venv smoke.

## Test results
- Tests total: 567
- Tests passed: 567
- Tests failed: 0
- Coverage gaps: None — all 10 ACs have ≥1 test mapped in COVERAGE.md

## Adversarial findings

### Critical (block SHIP)
- **Finding C1 (ORIGINAL — still present): README line 94 contains broken GitHub install URL.**
  - File: `README.md:94`
  - Issue: `pip install git+https://github.com/prasad-a-abhishek/fletcher-pure.git` — repo does not exist.
  - The fix card updated the Quick Start section (line 14) to `pip install -e .` but left the Install section (line 94) with the broken git+https URL unchanged.
  - Proposed fix: Remove or replace line 94 with the same `pip install -e .` from Quick Start, or delete the entire Install section since the repo has no remote.

- **Finding C2 (NEW): README line 54 claims `checksum(b"123456789") == 7662` but implementation returns 7902.**
  - File: `README.md:54`
  - Issue: README says `checksum(b"123456789")  # 0x1EDE = 7662`. Actual execution: `checksum(b"123456789") == 7902`.
  - The spec.md table also says 7662 (0x1EDE), but implementation produces 7902.
  - This is a spec/code inconsistency that makes the README's API reference dishonest.
  - Proposed fix: Update README line 54 to show `7902` instead of `7662`; update spec.md test vector table to `7902`.

### High (should fix)
- **Finding H1: spec.md AC2 says `checksum(b"\x00") == 257` but implementation/README say `0`.**
  - File: `spec.md:81`
  - Issue: spec.md AC2 still states `checksum(b"\x00")` returns 257, contradicting the fix which aligned implementation and README to RFC 3309 §5.1 (which yields 0). The fix card only updated the README example and implementation; spec.md AC2 was not updated.
  - This is a spec-integrity failure — the spec and implementation must agree.
  - Proposed fix: Change spec.md AC2 to `checksum(b"\x00") == 0` to match the implementation.

## Spec compliance
- [x] AC1: `checksum(b"") == 0` — test_ac1 passes
- [x] AC2: `checksum(b"\x00") == 0` — test_ac2 passes (implementation=0, but spec.md says 257 — see H1)
- [x] AC3: `checksum(b"\x01\x02") == 1027` — test_ac3 passes
- [x] AC4: `checksum(b"\xff\xff") == 0` — test_ac4 passes
- [x] AC5: `verify(data, checksum(data)) == True` — test_ac5 + test_verify.py pass
- [x] AC6: `verify(data, checksum(data) ^ 0x0001) == False` — test_ac6 passes
- [x] AC7: TypeError for non-bytes — test_ac7 passes (6/6 type errors caught)
- [x] AC8: 65535-byte input — test_ac8 passes
- [x] AC9: result in [0, 65535] — test_ac9 passes
- [x] AC10: zero deps — test_ac10 passes
- [ ] RFC 3309 §5.1 reference in spec.md — spec.md does NOT cite RFC 3309 §5.1 for AC2 (H1 above)

## Smoke verification
- [x] `pip install -e .` works clean (Quick Start section)
- [x] `pytest -q` all green (567/567)
- [x] CLI --help shows expected flags — N/A (library only)
- [x] End-to-end smoke: checksum/verify roundtrip on real data — OK
- [x] No files committed outside /root/projects/fletcher-pure/ (only README.md, spec.md, fletcher_pure/, tests/)
- [x] README install instructions (Quick Start section line 14) actually work on a fresh venv

## Adversarial fuzzing (ran these)
- `b""` empty input → checksum=0, verify(b"",0)=True ✓
- `b"\xff" * 65535` max-length → checksum=0, in range ✓
- `bytes(range(256)) * 256` (~65KB all byte values) → checksum=21760, no crash ✓
- 50x random 1KB payloads → 50/50 passed (all roundtrip, all in range) ✓
- `verify(b"data", 65536)` → False ✓ (out-of-range expected)
- TypeError on non-bytes (None, str, list, int, tuple) → 6/6 correct ✓
- Single-bit corruption on `b"123456789"` → detected (7902 vs 7902^1) ✓

## Risk callouts
- **The README Install section (line 94) still points to a non-existent GitHub repo.** Users who scroll past Quick Start will hit the broken git+https URL.
- **Spec/code inconsistency on the RFC reference vector `b"123456789"`** (7662 in spec table vs 7902 actual). This is a correctness concern — either the implementation is wrong or the spec table is wrong.
- **Spec.md AC2 was not updated** during the fix pass — it still says 257 while the implementation says 0. The spec and implementation must agree.

---

## Prior findings status
| Finding | Status |
|---|---|
| README install URL (CRITICAL) | PARTIALLY FIXED — Quick Start (line 14) fixed; Install section (line 94) still broken |
| AC2 spec integrity (CRITICAL) | PARTIALLY FIXED — implementation+README now agree on 0; but spec.md AC2 still says 257 (NEW H1); README reference vector (7662) doesn't match implementation (7902) (NEW C2) |

---

VERDICT: FIX
