# Test coverage map

| spec criterion | test(s) |
|---|---|
| AC1: checksum(b"") == 0 | test_spec_vectors.py::TestSpecVectors::test_ac1_empty_input |
| AC2: checksum(b"\\x00") == 0 | test_spec_vectors.py::TestSpecVectors::test_ac2_single_zero_byte |
| AC3: checksum(b"\\x01\\x02") == 1027 | test_spec_vectors.py::TestSpecVectors::test_ac3_two_bytes |
| AC4: checksum(b"\\xff\\xff") == 0 | test_spec_vectors.py::TestSpecVectors::test_ac4_ff_wrap |
| AC5: verify(data, checksum(data)) True | test_spec_vectors.py::TestSpecVectors::test_ac5_verify_roundtrip; test_verify.py::TestVerifyRoundtrip |
| AC6: verify(data, checksum(data) ^ 0x0001) False | test_spec_vectors.py::TestSpecVectors::test_ac6_verify_detects_corruption; test_verify.py::TestVerifyCorruption |
| AC7: verify raises TypeError for non-bytes | test_spec_vectors.py::TestSpecVectors::test_ac7_type_error_non_bytes; test_boundary.py::TestBoundary::test_verify_type_errors |
| AC8: 65535-byte input no overflow | test_spec_vectors.py::TestSpecVectors::test_ac8_65535_byte_input; test_boundary.py::TestBoundary::test_max_65535_zeros; test_boundary.py::TestBoundary::test_max_65535_ff |
| AC9: result in [0, 65535] | test_spec_vectors.py::TestSpecVectors::test_ac9_result_range |
| AC10: zero pip deps | test_spec_vectors.py::TestSpecVectors::test_ac10_zero_deps |
