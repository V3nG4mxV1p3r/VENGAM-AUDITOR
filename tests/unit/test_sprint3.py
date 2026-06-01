"""
VENGAM Auditor — Sprint 3 Native Engine Unit Tests
Run: pytest tests/unit/test_sprint3.py -v
"""
import pytest
import os
import struct
import tempfile
from pathlib import Path


# ── so_analyzer (Python fallback — no Rust required) ─────────────────────────

class TestSoAnalyzer:

    def test_import_no_crash(self):
        from vengam.native.so_analyzer import (
            extract_strings, shannon_entropy,
            scan_high_entropy_strings, find_il2cpp_binary,
        )
        assert callable(extract_strings)
        assert callable(shannon_entropy)

    def test_extract_strings_python_fallback(self, tmp_path):
        from vengam.native.so_analyzer import extract_strings
        binary = tmp_path / "test.so"
        binary.write_bytes(b"\x00\x00hello_world_test\x00\x00short\x00")
        result = extract_strings(str(binary), min_length=8)
        assert "hello_world_test" in result
        assert "short" not in result

    def test_extract_strings_missing_file(self):
        from vengam.native.so_analyzer import extract_strings
        result = extract_strings("/nonexistent/lib.so", min_length=8)
        assert result == []

    def test_shannon_entropy_uniform(self):
        from vengam.native.so_analyzer import shannon_entropy
        assert shannon_entropy("aaaaaaaaaa") < 1.0

    def test_shannon_entropy_high(self):
        from vengam.native.so_analyzer import shannon_entropy
        key = "AIzaSyABCDEF1234567890abcdefghijk"
        assert shannon_entropy(key) > 4.0

    def test_shannon_entropy_empty(self):
        from vengam.native.so_analyzer import shannon_entropy
        assert shannon_entropy("") == 0.0

    def test_scan_high_entropy_filters(self):
        from vengam.native.so_analyzer import scan_high_entropy_strings
        strings = [
            "aaaaaaaaaaaaa",
            "AIzaSyABCDEF1234567890abcdefghijk",
        ]
        results = scan_high_entropy_strings(strings, threshold=4.0, min_len=8)
        values = [r[0] for r in results]
        assert any("AIza" in v for v in values)

    def test_find_il2cpp_binary_empty_dir(self, tmp_path):
        from vengam.native.so_analyzer import find_il2cpp_binary
        result = find_il2cpp_binary(str(tmp_path))
        assert result == []

    def test_find_il2cpp_binary_finds_metadata(self, tmp_path):
        from vengam.native.so_analyzer import find_il2cpp_binary
        meta = tmp_path / "assets" / "bin" / "Data"
        meta.mkdir(parents=True)
        (meta / "global-metadata.dat").write_bytes(b"\xAF\x1B\xB1\xFA")
        result = find_il2cpp_binary(str(tmp_path))
        assert any("global-metadata.dat" in r for r in result)

    def test_find_il2cpp_binary_finds_so(self, tmp_path):
        from vengam.native.so_analyzer import find_il2cpp_binary
        lib = tmp_path / "lib" / "arm64-v8a"
        lib.mkdir(parents=True)
        (lib / "libil2cpp.so").write_bytes(b"\x7fELF")
        result = find_il2cpp_binary(str(tmp_path))
        assert any("libil2cpp.so" in r for r in result)


# ── IL2CPP parser (Python fallback) ──────────────────────────────────────────

class TestIl2CppParser:

    IL2CPP_MAGIC = b"\xAF\x1B\xB1\xFA"

    def _make_metadata(self, tmp_path, extra: bytes = b"") -> str:
        """Write a minimal valid IL2CPP metadata file."""
        header = self.IL2CPP_MAGIC + struct.pack("<i", 24) + b"\x00" * 56
        path = tmp_path / "global-metadata.dat"
        path.write_bytes(header + extra)
        return str(path)

    def test_invalid_magic_returns_invalid(self, tmp_path):
        from vengam.native.so_analyzer import parse_il2cpp_metadata
        path = tmp_path / "bad.dat"
        path.write_bytes(b"\x00\x00\x00\x00some data here")
        result = parse_il2cpp_metadata(str(path))
        assert result.get("valid") is False

    def test_valid_magic_returns_valid(self, tmp_path):
        from vengam.native.so_analyzer import parse_il2cpp_metadata
        fpath = self._make_metadata(tmp_path)
        result = parse_il2cpp_metadata(fpath)
        assert result.get("valid") is True

    def test_security_keywords_detected(self, tmp_path):
        from vengam.native.so_analyzer import parse_il2cpp_metadata
        # Embed a suspicious string after header
        payload = b"\x00" + b"api_key=AIzaSyABCDEF1234567890abcde\x00"
        fpath   = self._make_metadata(tmp_path, payload)
        result  = parse_il2cpp_metadata(fpath)
        findings = result.get("security_findings", [])
        severities = [f["severity"] for f in findings]
        assert any(s in ("CRITICAL", "HIGH") for s in severities)

    def test_missing_file_returns_error(self):
        from vengam.native.so_analyzer import parse_il2cpp_metadata
        result = parse_il2cpp_metadata("/nonexistent/global-metadata.dat")
        assert result.get("valid") is False


# ── scan_so_files integration ─────────────────────────────────────────────────

class TestScanSoFiles:

    def test_no_so_files_returns_empty(self, tmp_path):
        from vengam.native.so_analyzer import scan_so_files
        result = scan_so_files(str(tmp_path))
        assert result == []

    def test_non_elf_so_does_not_crash(self, tmp_path):
        from vengam.native.so_analyzer import scan_so_files
        lib = tmp_path / "lib" / "arm64-v8a"
        lib.mkdir(parents=True)
        # Not a valid ELF — should not crash
        (lib / "libgame.so").write_bytes(b"NOT_AN_ELF_FILE_JUST_GARBAGE_DATA")
        result = scan_so_files(str(tmp_path))
        assert isinstance(result, list)

    def test_finding_structure(self, tmp_path):
        from vengam.native.so_analyzer import scan_so_files
        lib = tmp_path / "lib" / "armeabi-v7a"
        lib.mkdir(parents=True)
        (lib / "libtest.so").write_bytes(b"\x7fELF" + b"\x00" * 100)
        results = scan_so_files(str(tmp_path))
        for r in results:
            assert "title" in r
            assert "severity" in r
            assert "score_value" in r
            assert "locations" in r


# ── scan_il2cpp integration ───────────────────────────────────────────────────

class TestScanIl2Cpp:

    IL2CPP_MAGIC = b"\xAF\x1B\xB1\xFA"

    def test_no_metadata_returns_empty(self, tmp_path):
        from vengam.native.so_analyzer import scan_il2cpp
        result = scan_il2cpp(str(tmp_path))
        assert result == []

    def test_metadata_found_returns_findings(self, tmp_path):
        from vengam.native.so_analyzer import scan_il2cpp
        meta_dir = tmp_path / "assets" / "bin" / "Data"
        meta_dir.mkdir(parents=True)
        header = self.IL2CPP_MAGIC + struct.pack("<i", 24) + b"\x00" * 56
        (meta_dir / "global-metadata.dat").write_bytes(header)

        results = scan_il2cpp(str(tmp_path))
        assert isinstance(results, list)
        titles = [r["title"] for r in results]
        assert any("IL2CPP" in t for t in titles)

    def test_finding_has_required_fields(self, tmp_path):
        from vengam.native.so_analyzer import scan_il2cpp
        meta_dir = tmp_path / "assets"
        meta_dir.mkdir(parents=True)
        header = self.IL2CPP_MAGIC + struct.pack("<i", 24) + b"\x00" * 56
        (meta_dir / "global-metadata.dat").write_bytes(header)

        results = scan_il2cpp(str(tmp_path))
        required = {"title", "severity", "confidence", "score_value",
                    "description", "simulation", "category", "locations"}
        for r in results:
            missing = required - r.keys()
            assert not missing, f"Missing fields: {missing}"


# ── Rust extension availability check ─────────────────────────────────────────

class TestNativeAvailability:

    def test_native_flag_is_bool(self):
        from vengam.native.so_analyzer import NATIVE_AVAILABLE
        assert isinstance(NATIVE_AVAILABLE, bool)

    def test_fallback_works_when_rust_absent(self):
        """Ensure all public functions work even without Rust extension."""
        from vengam.native import so_analyzer
        # Temporarily pretend native is unavailable
        original = so_analyzer.NATIVE_AVAILABLE
        so_analyzer.NATIVE_AVAILABLE = False
        so_analyzer._native          = None
        try:
            e = so_analyzer.shannon_entropy("test_string_abc")
            assert e > 0
            s = so_analyzer.scan_high_entropy_strings(["AIzaSyABC123456789abcdefghij"], 4.0, 8)
            assert isinstance(s, list)
        finally:
            so_analyzer.NATIVE_AVAILABLE = original
