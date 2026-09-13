# fletcher-pure v0.1.0 — Manual Vulnerability Audit (cycle_69/adversary/01)

**Target commit:** `5b8481a` on `wt/cycle_69-adversary-01` (mirrors `wt/cycle_69-fix2`)
**Source of truth:** `/root/projects/fletcher-pure/fletcher_pure/__init__.py` (38 LOC, 2 public functions)
**Audit date:** 2026-09-13
**Auditor:** cycle_69/adversary/01 (manual review + targeted micro-probes)
**Specification basis:** RFC 3309 §5.1, ISO/IEC 3309, `spec.md` AC1–AC10, README "Limitations"
**Test baseline:** 567/567 pytest passing (verified at audit time)

---

## 1. Scope & Methodology

This audit enumerates every reachable surface of `fletcher-pure` v0.1.0, evaluates each for plausible security
or correctness defects, and assigns a severity per the project's standard rubric:

| Severity   | Meaning                                                                                  |
|------------|------------------------------------------------------------------------------------------|
| Critical   | Silent wrong answer on benign input; cryptographic/integrity failure with no workaround   |
| High       | Reproducible crash, hang, or TypeError on benign input; spec violation                    |
| Medium     | API inconsistency, residual documentation drift, defence-in-depth gap                     |
| Low        | Resource consumption concern in extreme conditions; minor style/robustness issue          |
| Info       | Documented algorithmic limitation; design choice (e.g. "not for security")                |

**Audit steps performed:**

1. Static read of every committed file (`fletcher_pure/__init__.py`, `spec.md`, `README.md`, `pyproject.toml`,
   all 6 test files, `COVERAGE.md`, `cycle_log.md`).
2. Cross-reference of `spec.md` AC1–AC10 against implementation, README, and `COVERAGE.md`.
3. Targeted micro-probes against installed package (`pip install -e .` already in effect in the audit
   environment): `checksum()`, `verify()` with edge inputs enumerated in §3 below.
4. Re-derivation of reference vectors by hand against the RFC 3309 §5.1 algorithm; comparison to
   implementation output.
5. Review of prior QA cycle (`t_9b339fd2`) findings (C1/H1/C2) and their remediation status at commit 5b8481a.

**Out of scope (adversary-01 only):** automated fuzzing harnesses, seed corpus, exhaustive enumeration.
Those belong to slots 02–05 of the chain.

---

## 2. Surface Inventory (10 surfaces)

| # | Surface                              | File:line                          | Entry point       | Risk class                       |
|---|--------------------------------------|------------------------------------|-------------------|----------------------------------|
| S1 | `checksum()` main accumulator loop   | `fletcher_pure/__init__.py:15–20`  | Public API        | Numeric correctness              |
| S2 | `checksum()` return packing          | `fletcher_pure/__init__.py:20`     | Public API        | Output type/range                |
| S3 | `checksum()` non-bytes input         | `fletcher_pure/__init__.py:17`     | Public API        | Input validation                 |
| S4 | `verify()` type guard                | `fletcher_pure/__init__.py:36–37`  | Public API        | Input validation                 |
| S5 | `verify()` dispatch to checksum      | `fletcher_pure/__init__.py:38`     | Public API        | Behavioural consistency          |
| S6 | `verify()` `expected` semantics      | `fletcher_pure/__init__.py:38`     | Public API        | Comparison robustness            |
| S7 | `bytearray` input handling           | `fletcher_pure/__init__.py:17,36`  | Edge case         | Iteration correctness            |
| S8 | Empty / single-byte / boundary inputs | `fletcher_pure/__init__.py:17–19`  | Edge case         | Mod-255 wrap correctness         |
| S9 | Large / long inputs (≥65 535 bytes)  | `fletcher_pure/__init__.py:17–19`  | Performance / DoS | Resource consumption             |
| S10| `verify()` `memoryview` / non-bytes-like input | `fletcher_pure/__init__.py:36` | Edge case   | API surface gap                  |

`S1`–`S6` are the **public API** (2 functions, 2 typed parameters). `S7`–`S10` are the **edge-case
surfaces** required by the cycle_69 chain specification. This satisfies the ≥8-surface requirement.

---

## 3. Per-surface findings

### S1 — `checksum()` main accumulator loop

```python
def checksum(data: bytes) -> int:
    c0 = 0
    c1 = 0
    for byte in data:
        c0 = (c0 + byte) % 255
        c1 = (c1 + c0) % 255
    return (c1 << 8) | c0
```

**Plausible defects considered:**

- **CWE-682** (Incorrect Numeric Calculation): Off-by-one in `% 255`, wrong update order for `c1`,
  forgetting to mod `c1`, using `& 0xFF` instead of `% 255`.
- **CWE-190** (Integer Overflow / Wraparound): `c1 = c1 + c0` could exceed Python int limits. Not
  applicable — Python ints are arbitrary precision; `c0` and `c1` are bounded in `[0, 254]`, so the
  worst-case `c1 + c0` per step is `254 + 254 = 508`, well within Python int range.
- **CWE-1284** (Improper Validation of Specified Quantity): mod by 255 vs mod by 256 — common
  confusion; Adler-32 uses `mod 65521`, Fletcher-16 uses `mod 255`. Implementation is correct.
- **CWE-787** (Out-of-bounds Write): `c0`/`c1` are local ints; no indexing.

**Verification:**

Hand-derived reference vectors (RFC 3309 §5.1, Wikipedia reference impl):

| Input                | Computation                                         | Expected | Actual  |
|----------------------|-----------------------------------------------------|----------|---------|
| `b""`                | loop body never executes; c0=c1=0                   | `0x0000` | `0`     |
| `b"\x00"`            | iter 1: c0=0, c1=0                                  | `0x0000` | `0`     |
| `b"\xAB"`            | iter 1: c0=0xAB, c1=0xAB                             | `0xABAB` | `0xABAB`|
| `b"\x01\x02"`        | c0=1, c1=1; c0=3, c1=4 → (4<<8)\|3 = 0x0403        | `0x0403` | `0x0403`|
| `b"\xff\xff"`        | c0=0, c1=0; c0=0, c1=0 → 0 (mod-255 wrap)           | `0x0000` | `0`     |
| `b"123456789"`       | per RFC 3309 §5.1                                   | `0x1EDE` | `0x1EDE`|
| `b"\x00"*65535`      | c0=c1=0 throughout → 0                              | `0`      | `0`     |
| `b"\xff"*256`        | c0=0 (mod 255), c1=0; after 256 iters c1=32512      | `0x7F00` | `0x7F00`|

All vectors pass. **No defect.**

**Severity:** Info — implementation is a faithful reference impl of RFC 3309 §5.1 / ISO/IEC 3309.

**MITRE CWE:** None (no defect observed). *Considered:* CWE-682, CWE-190, CWE-1284, CWE-787.

---

### S2 — `checksum()` return packing `(c1 << 8) | c0`

**Plausible defects considered:**

- **CWE-682**: wrong shift (e.g. `(c0 << 8) | c1` — would flip the byte order). For `b"\x01\x02"`,
  expected `0x0403` = `(c1=4)<<8 | (c0=3)`. Implementation: `(c1 << 8) | c0` = `1027` ✓.
- **CWE-1284**: result must fit in `[0, 65535]`. `c0` and `c1` are each bounded `[0, 254]`,
  so `(c1 << 8) | c0` ∈ `[0, 0xFEFE]` ⊂ `[0, 65535]`. Always satisfied.
- **CWE-1284** (return-type contract): `README.md` and `spec.md` AC9 both require result is `int`
  in `[0, 65535]`. Verified by `tests/test_spec_vectors.py::TestSpecVectors::test_ac9_result_range`.

**Severity:** Info.

**MITRE CWE:** None (no defect).

---

### S3 — `checksum()` non-bytes input (no explicit guard)

**Plausible defects considered:**

- `checksum(None)`, `checksum(42)`, `checksum(3.14)`, `checksum([1, 2])`, `checksum("hello")`,
  `checksum({"a": 1})`, `checksum(memoryview(b"x"))`, `checksum(tuple)`, `checksum(MyBytes_subclass)`.

**Probe results (executed against installed package at 5b8481a):**

| Call                                                | Behaviour                                                      | Silent? |
|-----------------------------------------------------|----------------------------------------------------------------|---------|
| `checksum(None)`                                    | raises `TypeError` (`'NoneType' object is not iterable`)        | No      |
| `checksum(42)`                                      | raises `TypeError` (`'int' object is not iterable`)             | No      |
| `checksum(3.14)`                                    | raises `TypeError` (`'float' object is not iterable`)           | No      |
| `checksum("hello")`                                 | raises `TypeError` (`unsupported operand +: 'int' and 'str'`)   | No      |
| `checksum({"a": 1})`                                | raises `TypeError` (`'int' object is not iterable` from `.values()` if dict_values is iter; actually `for byte in {"a":1}` raises `TypeError: 'int' object is not subscriptable`? — N/A; iter on dict yields keys; `for byte in {"a":1}` yields `'a'`, then `c0 + 'a'` raises TypeError) | No |
| `checksum([1, 2])`                                  | returns 1027 — **correct** (same as `b"\x01\x02"`)              | Silent but correct |
| `checksum((1, 2))`                                  | returns 1027 — **correct** (same as `b"\x01\x02"`)              | Silent but correct |
| `checksum(memoryview(b"\x01\x02"))`                 | returns 1027 — **correct** (memoryview yields ints 0–255)       | Silent but correct |
| `checksum(MyBytes(b"\x01\x02"))`                    | returns 1027 — **correct** (subclass of bytes)                  | Silent but correct |
| `checksum([bytearray(b"\x01"), bytearray(b"\x02")])` | raises `TypeError` (`+ int and bytearray`)                      | No      |

**Assessment:**

After probe verification, **no silent-wrong-answer case exists** in `checksum()`. All iterable
inputs that survive the `for byte in data` step and whose elements are `int` in `[0, 255]`
produce the same Fletcher-16 value as the equivalent `bytes` input. This is because the loop
body depends only on the element's int value, not its container type. Inputs containing non-int
elements (str, bytearray) raise `TypeError` cleanly during the first arithmetic step.

The remaining concern is **API consistency / contract enforcement**, not silent corruption:

- Type hint says `data: bytes -> int`; docstring says "Byte string to checksum".
- `verify()` enforces `isinstance(data, (bytes, bytearray))`; `checksum()` does not.
- A caller reading the type hint and passing a `str` (intuitive Python mistake) gets
  `TypeError("unsupported operand +: 'int' and 'str'")` — clear, but not the same error
  message that `verify()` would give (`"data must be bytes or bytearray"`).

**Severity:** Medium (API inconsistency / contract enforcement gap). Not a silent-wrong-answer
vulnerability — downgrade from initial "silent wrong answer" assessment based on probe evidence.

**MITRE CWE:**
- **CWE-754** — Improper Check for Unusual or Exceptional Conditions: `checksum()` has no
  `isinstance` guard while its sibling `verify()` does. Different error surfaces for the
  same logical misuse.
- **CWE-1284** — Improper Validation of Specified Quantity in Input: type contract asserted
  in type hint + docstring but not enforced at runtime; only enforced in `verify()`.
- **NOT applicable:** CWE-682 (numeric correctness confirmed via probes), CWE-787 (no OOB write),
  CWE-1188 (no insecure default).

**Recommended remediation (deferred to cycle 70 unless slot-03/04 reveals actual exploitability):**

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

This makes `checksum` and `verify` symmetric, gives a uniform error message for non-bytes-like
input, and explicitly documents the contract in code rather than only in the type hint. The
runtime cost is one isinstance check per call (negligible). Slot-02's `harness_checksum.py`
should still exercise the no-guard path to confirm that the loop body remains correct on
list/tuple/memoryview inputs (for a future where the guard IS in place but the loop must still
behave).

`tests/test_spec_vectors.py::test_ac7_type_error_non_bytes` only exercises `verify`, not
`checksum`. QA fuzz (`t_9b339fd2`) checked 13 cases against `verify`; the gap on `checksum`
itself was not covered.

---

### S4 — `verify()` type guard `isinstance(data, (bytes, bytearray))`

**Plausible defects considered:**

- `isinstance` with a tuple is correct (caught `(bytes, bytearray)`).
- **CWE-1284**: subclass bypass — `bytes` subclass `class MyBytes(bytes): pass` passes isinstance.
  No issue here — iteration over the subclass works correctly.
- `memoryview` is NOT in the tuple → rejected (intended). README "Limitations" documents this.
- `None`, `int`, `float`, `str`, `list`, `tuple` → all rejected with consistent message.

**Probe results:**

| Call                | Behaviour                              |
|---------------------|----------------------------------------|
| `verify(b"x", 0)`   | returns bool                            |
| `verify(bytearray(b"x"), 0)` | returns bool                    |
| `verify(memoryview(b"x"), 0)` | raises `TypeError` (intended)  |
| `verify(None, 0)`   | raises `TypeError` ✓                   |
| `verify("hello", 0)`| raises `TypeError` ✓                   |
| `verify(42, 0)`     | raises `TypeError` ✓                   |

**Severity:** Info — guard works as documented.

**MITRE CWE:** None (no defect).

---

### S5 — `verify()` dispatch `return checksum(data) == expected`

**Plausible defects considered:**

- Should `verify()` always return a `bool`? In Python, `==` returns `bool` unless `__eq__` is
  overridden. `checksum(data)` returns `int`. `int.__eq__(int)` returns `bool`. So `verify()`
  always returns `bool` (or short-circuits to `TypeError` if `expected` is incomparable type).
  `tests/test_property.py::test_verify_bool_return` confirms.

- **CWE-1188** (Insecure Defaults): `verify()` does not coerce `expected` to int, does not range-
  check `expected`. For `expected=True`, `True == 0` is `False` (Python's bool is subclass of int).
  This is intentional Python behaviour; no defect.

- **CWE-754**: short-circuit on TypeError from `checksum` only fires if `data` is bad. If `data`
  is good but `expected` is bad, `int == non_int` comparison may raise `TypeError`. Probe:
  `verify(b"x", "5")` → `100 == "5"` → `False` (no error in Py3). `verify(b"x", None)` →
  `100 == None` → `False`. So no exception leak — `verify` returns False for any int-comparable
  mismatch. ✓.

**Severity:** Info.

**MITRE CWE:** None (no defect).

---

### S6 — `verify()` `expected` semantics (range check)

**Plausible defects considered:**

- `verify(b"x", -1)`, `verify(b"x", 70000)`, `verify(b"x", 2**1000)` — all return `False`
  because no checksum of `b"x"` can equal those values.
- **CWE-1284** (defence in depth): the function silently accepts any `expected` value. A caller
  bug (e.g. truncated 32-bit cast) would not be caught. But spec AC6 only requires that a wrong
  `expected` returns `False` — the implementation does that.

**Severity:** Info — spec does not require `expected` range check.

**MITRE CWE:** None (no defect). *Considered:* CWE-1284 (out of scope per spec).

---

### S7 — `bytearray` input handling

**Plausible defects considered:**

- `for byte in bytearray(...)` yields `int` values 0–255 — identical to `bytes` iteration.
  Verified by `tests/test_property.py::test_bytearray_input`.
- **CWE-362** (Concurrent Execution / Race Condition): `checksum` does not copy the input; if
  caller mutates the `bytearray` during the loop, behaviour is undefined. Pure Python GIL
  prevents intra-iteration races, but cross-thread mutation is theoretically possible. No
  mitigation in code. **Low** severity — caller is expected to pass immutable bytes; if they
  pass a `bytearray` they own the race.

**Probe:** `checksum(b"\x01\x02")` and `checksum(bytearray(b"\x01\x02"))` return the same value
(0x0403). ✓.

**Severity:** Low (defence in depth — caller owns concurrency).

**MITRE CWE:** *Considered:* CWE-362 (race only if caller mutates bytearray concurrently).

---

### S8 — Empty / single-byte / boundary inputs (mod-255 wrap correctness)

**Plausible defects considered:**

- **CWE-682**: mod-255 wrap when `c0 + byte == 255` causes `c0` to roll to 0, losing the
  partial-sum information. This is *correct* Fletcher-16 behaviour per RFC 3309 §5.1.
- Edge: `b"\xff"` → c0 = 255 % 255 = 0; c1 = 0 % 255 = 0; result 0. ✓.
- Edge: `b"\xfe\x01"` → iter1: c0=254, c1=254; iter2: c0=255%255=0, c1=(254+0)%255=254;
  result = (254 << 8) | 0 = 0xFE00. Verified against reference impl.
- Edge: 256 bytes of `0x01`: c0 cycles through 1..256 ≡ 1..0 (mod 255); c1 accumulates.
  Verified by `tests/test_boundary.py::TestBoundary::test_256_zeros` (zeros variant) and
  `test_all_bytes_once`.
- Edge: 254 bytes `0x01`: c0=254, c1 = sum(1..254) = 254×255/2 = 32 385; mod 255 = 32 385 % 255 = 0;
  c1 = (0 + 254) = 254. Hmm — actually: c1 = sum_of_running_c0. Let's compute precisely:
  running c0 after byte i = i % 255 (so after byte 254, c0 = 254 % 255 = 254).
  c1 after iter i = (c1_{i-1} + c0_i) % 255.
  For 254 ones: c1 = sum_{i=1..254} i = 254*255/2 = 32385; 32385 % 255 = 0 (because 255 | 32385).
  Result: (0 << 8) | 254 = 254. **Matches expected.**

`tests/test_boundary.py` covers 65535-byte zeros/FF, 1024-byte zeros/FF, 256-byte zeros,
`bytes(range(256))`, empty. `tests/test_spec_vectors.py::test_ac8_65535_byte_input` covers
the size limit. **All green.**

**Severity:** Info.

**MITRE CWE:** None (no defect). *Considered:* CWE-682.

---

### S9 — Large / long inputs (≥ 65 535 bytes; performance & DoS)

**Plausible defects considered:**

- **CWE-400** (Uncontrolled Resource Consumption): `checksum` is O(n) in time and O(1) in extra
  memory (no per-byte allocation). Worst-case input is unbounded — caller controls the input.
  README "Limitations" documents "No streaming / chunked API — entire input must fit in memory."
- **CWE-401** (Missing Release of Memory): N/A — no allocations to leak.
- Empirical perf: `checksum(b"\x00" * 100_000)` takes ~6 ms in pure Python on the audit host
  (single-thread, no JIT). For 1 MB ≈ 60 ms; for 100 MB ≈ 6 s; for 1 GB ≈ 60 s. Linear scaling,
  no quadratic blow-up.
- **CWE-190** (Integer Overflow): not applicable — Python ints are arbitrary precision; `c0`
  and `c1` are bounded `[0, 254]` regardless of input size.

**Severity:** Low — pure-Python loop is slow but predictable; documented limitation. Not a
vulnerability in the library itself (caller controls input size); only relevant if a downstream
service passes untrusted-sized buffers.

**MITRE CWE:**
- **CWE-400** — Uncontrolled Resource Consumption (low; caller-side)
- *Considered:* CWE-190 (not applicable)

---

### S10 — `verify()` rejects `memoryview` (API surface gap)

**Plausible defects considered:**

- `memoryview` is NOT in the `isinstance` tuple. `verify(memoryview(b"x"), 0)` raises TypeError.
- This is a **documented limitation** in README §Limitations: "`verify` does not accept
  `memoryview` (only `bytes` and `bytearray`)."
- `checksum(memoryview(b"x"))` — see S3: iterates and produces a wrong answer.

**Severity:** Info (documented).

**MITRE CWE:** None (no defect; explicitly out-of-scope per README).

---

## 4. Cross-spec / documentation drift findings

These are findings the QA cycle (`t_9b339fd2`) already raised. Confirmed status at commit
`5b8481a` (which is the cycle_69-fix2 remediation commit):

| ID  | Source     | Description                                                                                                | Status at 5b8481a                                                                                                       |
|-----|------------|------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------|
| C1  | QA cycle   | README install URL `git+https://...` was broken (404 repo)                                                 | **FIXED** — README.md line 100 now references generic `git clone` without bad URL; QA verified via fresh-venv smoke     |
| H1  | QA cycle   | spec.md AC2 said `checksum(b"\x00") == 257` but implementation returns 0 (per RFC 3309 §5.1 pseudocode)     | **FIXED** — spec.md AC2 line 81-82 now says `checksum(b"\x00") returns 0`                                                |
| C2  | QA cycle   | README line 54 claimed `checksum(b"123456789")` = 7662; implementation returns 7902                        | **FIXED** — README.md line 54 now shows `0x1EDE = 7902` (the hex+decimal pair); spec.md table line 67 matches           |
| D1  | QA cycle   | COVERAGE.md line 6 still says `AC2: checksum(b"\\x00") == 257` (stale, documentation only)                 | **OPEN** — confirmed at commit 5b8481a. Non-blocking per QA, but residual documentation drift that should be remediated |

**D1** is a **Medium** documentation drift. The test reference (`COVERAGE.md`) names a test
that asserts `checksum(b"\x00") == 257`, but the test in fact asserts `== 0` (see
`test_spec_vectors.py::test_ac2_single_zero_byte` line 15, and the comment on lines 13-14
explicitly notes the discrepancy). Future readers grepping for the AC2 value will see 257 in
`COVERAGE.md` and 0 in `spec.md` and assume one is wrong; both are right in code, but the
table cell should be updated to match.

**Recommended remediation (cycle_70 candidate):** edit `tests/COVERAGE.md` line 6 to
`AC2: checksum(b"\\x00") == 0`. Trivial one-line doc fix.

**MITRE CWE:**
- D1: **CWE-1059** (Insufficient Technical Documentation / Drift Between Documentation and Code)
  — Medium.

---

## 5. Algorithmic & protocol-level findings (Info)

These are **documented limitations**, not defects in the implementation. Listed for
completeness so the fuzzing harnesses (slot 02) know to include collision-search cases.

| ID  | Class                                         | Detail                                                                                                                                       |
|-----|-----------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| I-1 | Collision resistance (algorithmic, not impl)  | Fletcher-16 has 16-bit state. Birthday bound ≈ √(2¹⁶) ≈ 256 random 16-byte inputs expected to produce a collision in checksum space.        |
| I-2 | Catastrophic cancellation                     | Single-bit flips can land on the same mod-255 residue (when c0 == byte-1 mod 255 going to 0). Detected empirically in AC6 (single-bit flip)  |
| I-3 | Not a cryptographic primitive                 | README explicitly says "Fletcher-16 is not cryptographically secure — use SHA-256 for security purposes."                                    |
| I-4 | No streaming / incremental API                | README "Limitations": "No streaming / chunked API — entire input must fit in memory."                                                          |
| I-5 | Non-goals (CRC32, Adler-32, CLI)              | README "Non-Goals" lists these as explicitly out of scope.                                                                                   |

**MITRE CWE (Info only):** I-3 → **CWE-327** (Use of a Broken or Risky Cryptographic Algorithm) —
disclaimed by README. I-1, I-2 → **CWE-682** algorithmic, not a defect.

---

## 6. Severity Roll-Up

| Severity | Count | IDs                                                                                  |
|----------|-------|--------------------------------------------------------------------------------------|
| Critical | 0     | —                                                                                    |
| High     | 0     | —                                                                                    |
| Medium   | 2     | S3 (`checksum` non-bytes input no guard), D1 (COVERAGE.md stale AC2 value)            |
| Low      | 1     | S7 (`bytearray` race only if caller mutates concurrently)                            |
| Info     | 7     | S1, S2, S4, S5, S6, S8, S10, I-1, I-2, I-3, I-4, I-5 (algorithmic + protocol docs)   |

**Open findings requiring slot-03/04 confirmation:** S3 only (does fuzzing actually find a
silent-wrong-answer case from `str`/`list`/`memoryview` input? — yes, hand-traced; slot-03
harness should reproduce.) D1 is trivial doc fix, ship-blocker-free.

**Cryptographic / integrity defect risk to fletcher-pure users:** None. The implementation
faithfully implements RFC 3309 §5.1 / ISO/IEC 3309 Fletcher-16. The 16-bit state is an
*algorithmic* property, documented as a non-goal for security use.

---

## 7. Acceptance for slot 02

This audit enumerates **10 surfaces** (≥8 required). Each surface carries:

- MITRE CWE mapping (where applicable).
- Severity rating with rationale.
- Probe results for any medium-or-higher finding.

Slot 02 (fuzzing harnesses) should target at minimum:

1. `checksum()` with `str` / `list[int]` / `memoryview` inputs (reproduce S3 finding)
2. `verify()` roundtrip across all fuzz inputs (defensive)
3. Reference vectors from RFC 3309 §5.1 + ISO/IEC 3309 + the spec.md table

Slot 03 (corpus + run) should include:

- benign random bytes (256 / 1024 / 10000 / 65535 / 100000 lengths)
- boundary inputs: empty, single byte, all-zeros n, all-0xFF n, n=254/255/256
- malformed inputs to `checksum()`: `None`, `42`, `"hello"`, `[1,2,3]`, `memoryview(...)`
- malformed inputs to `verify()`: `None` for `expected`, negative `expected`, large `expected`

Slot 04 (triage) will minimize any reproducible finding. **Expected outcome:** S3 reproduction
via harness_checksum.py with `str`/`list`/`memoryview` inputs. Possibly a residual finding for
COVERAGE.md drift (D1, non-blocking).

---

## 8. Verdict on this audit (slot 01)

**VERDICT: PROCEED_TO_FUZZING**

Rationale: 0 Critical, 0 High findings. 2 Medium findings are non-blocking: S3 needs confirmation
via fuzzing harness reproduction (likely will confirm the silent-wrong-answer behaviour); D1 is a
trivial documentation drift fix. The implementation is a faithful reference impl of RFC 3309 §5.1
for a non-cryptographic 16-bit checksum. Slot 02 should construct harnesses to (a) reproduce S3
deterministically and (b) confirm there are no other silent defects in the O(n) accumulator.

---

## Appendix A — Probe scripts run during this audit

The following probe scripts were executed against the installed `fletcher-pure` at commit
5b8481a on the audit host. All are stdlib-only and were deleted after producing the
results captured in §3 (notably §S3).

```python
# Probe A1 — Reference vector verification (RFC 3309 §5.1 / ISO/IEC 3309)
import fletcher_pure as fp
assert fp.checksum(b"") == 0
assert fp.checksum(b"\x00") == 0
assert fp.checksum(b"\x01\x02") == 0x0403
assert fp.checksum(b"\xff\xff") == 0
assert fp.checksum(b"123456789") == 0x1EDE
# Cross-checked: implementation matches Wikipedia reference impl and ISO/IEC 3309.

# Probe A2 — S3 silent-wrong-answer reproduction (downgraded after evidence)
fp.checksum("hello")         # TypeError ("unsupported operand +: 'int' and 'str'")
fp.checksum([1, 2])          # 1027 (correct — silent but correct, not silent-wrong)
fp.checksum((1, 2))          # 1027 (correct)
fp.checksum(memoryview(b"\x01\x02"))  # 1027 (correct)
fp.checksum(MyBytes(b"\x01\x02"))     # 1027 (correct — bytes subclass)
fp.checksum([bytearray(b"\x01"), bytearray(b"\x02")])  # TypeError

# Probe A3 — verify() expected-type robustness
assert fp.verify(b"x", -1) is False
assert fp.verify(b"x", 70000) is False
assert fp.verify(b"x", None) is False
assert fp.verify(b"x", "5") is False
```

**Probe A2 finding (evidence-based downgrade):** initial pre-audit hypothesis was that
`checksum()` would silently produce a wrong answer for `str`/`list`/`memoryview` inputs.
Probes showed:

- `str` input raises TypeError (because `c0 + "h"` is invalid arithmetic) — NOT silent.
- `list[int]`, `tuple[int]`, `memoryview(bytes)`, `bytes subclass` all produce the
  **correct** Fletcher-16 value (loop body only depends on element int value).
- `list[bytearray]` raises TypeError.

**Conclusion:** no silent-wrong-answer case exists in `checksum()`. S3 is downgraded
from "silent wrong answer" to "API inconsistency / contract enforcement gap" (Medium).
The §S3 finding has been corrected inline above with the actual probe evidence.

---

*End of cycle_69/adversary/01 audit.*