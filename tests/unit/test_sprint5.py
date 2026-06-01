"""
VENGAM Auditor — Sprint 5 Unit Tests
PDF report + Diff scan
Run: pytest tests/unit/test_sprint5.py -v
"""
import pytest
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
import datetime

from vengam.core.models import (
    Finding, FindingLocation, ScanResult,
    AttackSurface, EngineStats, DynamicFinding,
)
from vengam.reports.diff_report import (
    diff_scans, FindingDiff, DiffResult,
    generate_text_diff, generate_json_diff,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_finding(
    title:     str,
    severity:  str  = "HIGH",
    score:     int  = 20,
    category:  str  = "General",
    triage:    str  = "",
) -> Finding:
    return Finding(
        title=title, severity=severity, confidence="HIGH",
        exploitability="CONFIRMED", secret_type="Test",
        description="Test description", simulation="Test simulation",
        score_value=score, category=category, triage_note=triage,
    )


def _make_scan(
    apk_name: str,
    findings: list[Finding],
    score:    int = 0,
) -> ScanResult:
    from vengam.core.risk_engine import calculate_risk
    surface = AttackSurface()
    total, verdict = calculate_risk(findings, surface)
    return ScanResult(
        apk_name=apk_name,
        apk_sha256="abc123",
        scan_timestamp=datetime.datetime.utcnow().isoformat() + "Z",
        findings=findings,
        dynamic_findings=[],
        attack_surface=surface,
        total_score=total,
        verdict=verdict,
        engine_stats=EngineStats(files_scanned=10, lines_scanned=1000),
        platform="android",
    )


# ── DiffResult model ──────────────────────────────────────────────────────────

class TestDiffResult:

    def test_new_finding_detected(self):
        old = _make_scan("v1.apk", [])
        new = _make_scan("v2.apk", [_make_finding("Firebase Key", "CRITICAL", 30)])
        diff = diff_scans(old, new)
        assert len(diff.new_findings) == 1
        assert diff.new_findings[0].title == "Firebase Key"

    def test_fixed_finding_detected(self):
        f = _make_finding("AWS Key", "CRITICAL", 30)
        old = _make_scan("v1.apk", [f])
        new = _make_scan("v2.apk", [])
        diff = diff_scans(old, new)
        assert len(diff.fixed_findings) == 1
        assert diff.fixed_findings[0].title == "AWS Key"
        assert diff.fixed_findings[0].score_delta == -30

    def test_worsened_finding_detected(self):
        old_f = _make_finding("Debug Flag", "MEDIUM", 10)
        new_f = _make_finding("Debug Flag", "CRITICAL", 30)
        old   = _make_scan("v1.apk", [old_f])
        new   = _make_scan("v2.apk", [new_f])
        diff  = diff_scans(old, new)
        assert len(diff.worsened_findings) == 1
        assert diff.worsened_findings[0].old_severity == "MEDIUM"
        assert diff.worsened_findings[0].new_severity == "CRITICAL"

    def test_improved_finding_detected(self):
        old_f = _make_finding("Debug Flag", "CRITICAL", 30)
        new_f = _make_finding("Debug Flag", "MEDIUM", 10)
        old   = _make_scan("v1.apk", [old_f])
        new   = _make_scan("v2.apk", [new_f])
        diff  = diff_scans(old, new)
        assert len(diff.improved_findings) == 1

    def test_unchanged_finding_detected(self):
        f   = _make_finding("Some Finding", "HIGH", 20)
        old = _make_scan("v1.apk", [f])
        new = _make_scan("v2.apk", [_make_finding("Some Finding", "HIGH", 20)])
        diff = diff_scans(old, new)
        assert len(diff.unchanged_findings) == 1

    def test_score_delta_calculated(self):
        old = _make_scan("v1.apk", [_make_finding("A", "CRITICAL", 30)])
        new = _make_scan("v2.apk", [])
        diff = diff_scans(old, new)
        assert diff.score_delta < 0   # score went down (improved)

    def test_empty_scans_diff(self):
        old = _make_scan("v1.apk", [])
        new = _make_scan("v2.apk", [])
        diff = diff_scans(old, new)
        assert len(diff.diffs) == 0
        assert diff.score_delta == 0

    def test_mixed_diff(self):
        f_common  = _make_finding("Common",  "HIGH",     20)
        f_old     = _make_finding("OldOnly", "CRITICAL", 30)
        f_new     = _make_finding("NewOnly", "HIGH",     20)
        f_changed = _make_finding("Changed", "MEDIUM",   10)
        f_changed2= _make_finding("Changed", "HIGH",     20)

        old = _make_scan("v1.apk", [f_common, f_old, f_changed])
        new = _make_scan("v2.apk", [f_common, f_new, f_changed2])
        diff = diff_scans(old, new)

        statuses = {d.title: d.status for d in diff.diffs}
        assert statuses["Common"]  == "UNCHANGED"
        assert statuses["OldOnly"] == "FIXED"
        assert statuses["NewOnly"] == "NEW"
        assert statuses["Changed"] == "WORSENED"


# ── Text diff report ──────────────────────────────────────────────────────────

class TestTextDiffReport:

    def _make_diff(self) -> DiffResult:
        old = _make_scan("v1.0.apk", [
            _make_finding("Firebase Key", "CRITICAL", 30),
            _make_finding("Common Issue", "HIGH",     20),
        ])
        new = _make_scan("v1.1.apk", [
            _make_finding("Common Issue", "HIGH",     20),
            _make_finding("New Vuln",     "MEDIUM",   10),
        ])
        return diff_scans(old, new)

    def test_generates_text_file(self, tmp_path):
        diff = self._make_diff()
        out  = str(tmp_path / "diff.txt")
        generate_text_diff(diff, out)
        assert Path(out).exists()
        assert Path(out).stat().st_size > 0

    def test_text_contains_key_sections(self, tmp_path):
        diff    = self._make_diff()
        out     = str(tmp_path / "diff.txt")
        generate_text_diff(diff, out)
        content = Path(out).read_text()
        assert "COMPARISON OVERVIEW"  in content
        assert "NEW"                  in content
        assert "FIXED"                in content
        assert "Firebase Key"         in content
        assert "New Vuln"             in content

    def test_text_contains_score_info(self, tmp_path):
        diff = self._make_diff()
        out  = str(tmp_path / "diff.txt")
        generate_text_diff(diff, out)
        content = Path(out).read_text()
        assert "Risk Score" in content
        assert "DIFF SUMMARY" in content


# ── JSON diff report ──────────────────────────────────────────────────────────

class TestJsonDiffReport:

    def _make_diff(self) -> DiffResult:
        old = _make_scan("v1.0.apk", [_make_finding("Firebase Key", "CRITICAL", 30)])
        new = _make_scan("v1.1.apk", [_make_finding("New Issue",    "HIGH",     20)])
        return diff_scans(old, new)

    def test_generates_json_file(self, tmp_path):
        diff = self._make_diff()
        out  = str(tmp_path / "diff.json")
        generate_json_diff(diff, out)
        assert Path(out).exists()

    def test_json_valid_structure(self, tmp_path):
        diff = self._make_diff()
        out  = str(tmp_path / "diff.json")
        generate_json_diff(diff, out)
        data = json.loads(Path(out).read_text())

        assert data["schema_version"] == "vengam-diff-v7"
        assert "old_apk"     in data
        assert "new_apk"     in data
        assert "score_delta" in data
        assert "summary"     in data
        assert "diffs"       in data

    def test_json_summary_counts_correct(self, tmp_path):
        old = _make_scan("v1.apk", [
            _make_finding("A", "CRITICAL", 30),
            _make_finding("B", "HIGH",     20),
        ])
        new = _make_scan("v2.apk", [
            _make_finding("B", "HIGH",     20),
            _make_finding("C", "MEDIUM",   10),
        ])
        diff = diff_scans(old, new)
        out  = str(tmp_path / "diff.json")
        generate_json_diff(diff, out)
        data = json.loads(Path(out).read_text())

        assert data["summary"]["fixed"]     == 1  # A fixed
        assert data["summary"]["new"]       == 1  # C new
        assert data["summary"]["unchanged"] == 1  # B unchanged

    def test_json_diffs_have_required_fields(self, tmp_path):
        diff = self._make_diff()
        out  = str(tmp_path / "diff.json")
        generate_json_diff(diff, out)
        data  = json.loads(Path(out).read_text())
        required = {"status", "title", "category", "score_delta"}
        for d in data["diffs"]:
            missing = required - d.keys()
            assert not missing, f"Missing fields: {missing}"


# ── PDF report (mock WeasyPrint) ──────────────────────────────────────────────

class TestPdfReport:

    def _make_result(self) -> ScanResult:
        return _make_scan("TestGame.apk", [
            _make_finding("Firebase Key", "CRITICAL", 30,
                         triage="Rotate at Firebase console."),
            _make_finding("Debug Flag",  "HIGH",     20,
                         category="AntiCheat"),
        ])

    def test_pdf_html_builds_without_crash(self):
        from vengam.reports.pdf_report import _build_html
        result   = self._make_result()
        html_out = _build_html(result)
        assert "<html" in html_out
        assert "VENGAM" in html_out
        assert "Firebase Key" in html_out

    def test_pdf_html_contains_score(self):
        from vengam.reports.pdf_report import _build_html
        result   = self._make_result()
        html_out = _build_html(result)
        assert str(result.total_score) in html_out

    def test_pdf_html_contains_verdict(self):
        from vengam.reports.pdf_report import _build_html
        result   = self._make_result()
        html_out = _build_html(result)
        assert result.verdict in html_out

    def test_pdf_html_contains_triage(self):
        from vengam.reports.pdf_report import _build_html
        result   = self._make_result()
        html_out = _build_html(result)
        assert "Rotate at Firebase console." in html_out

    def test_pdf_generate_calls_weasyprint(self, tmp_path):
        from vengam.reports import pdf_report
        result  = self._make_result()
        out     = str(tmp_path / "test.pdf")
        mock_html_instance = MagicMock()
        with patch.dict("sys.modules", {
            "weasyprint": MagicMock(
                HTML=MagicMock(return_value=mock_html_instance)
            )
        }):
            # Re-import to pick up mock
            import importlib
            importlib.reload(pdf_report)
            pdf_report.generate(result, out)
            mock_html_instance.write_pdf.assert_called_once_with(out)

    def test_pdf_generate_raises_if_weasyprint_missing(self, tmp_path):
        import sys
        result = self._make_result()
        out    = str(tmp_path / "test.pdf")
        # Temporarily hide weasyprint
        orig = sys.modules.pop("weasyprint", None)
        try:
            from vengam.reports.pdf_report import generate
            with pytest.raises(ImportError):
                generate(result, out)
        finally:
            if orig:
                sys.modules["weasyprint"] = orig

    def test_pdf_html_ios_platform(self):
        from vengam.reports.pdf_report import _build_html
        result          = self._make_result()
        result.platform = "ios"
        result.apk_name = "TestGame.ipa"
        html_out        = _build_html(result)
        assert "IOS" in html_out or "ios" in html_out.lower()

    def test_pdf_html_escapes_special_chars(self):
        from vengam.reports.pdf_report import _build_html
        result = self._make_result()
        result.findings[0].title = "<script>alert('xss')</script>"
        html_out = _build_html(result)
        assert "<script>" not in html_out
        assert "&lt;script&gt;" in html_out


# ── DiffResult properties ─────────────────────────────────────────────────────

class TestDiffResultProperties:

    def test_score_delta_positive_means_regression(self):
        old = _make_scan("v1.apk", [])
        new = _make_scan("v2.apk", [_make_finding("A", "CRITICAL", 30)])
        diff = diff_scans(old, new)
        assert diff.score_delta > 0

    def test_score_delta_negative_means_improvement(self):
        old = _make_scan("v1.apk", [_make_finding("A", "CRITICAL", 30)])
        new = _make_scan("v2.apk", [])
        diff = diff_scans(old, new)
        assert diff.score_delta < 0

    def test_property_counts_consistent(self):
        old = _make_scan("v1.apk", [
            _make_finding("A", "CRITICAL", 30),
            _make_finding("B", "HIGH",     20),
            _make_finding("C", "MEDIUM",   10),
        ])
        new = _make_scan("v2.apk", [
            _make_finding("B", "CRITICAL", 30),  # worsened
            _make_finding("C", "MEDIUM",   10),  # unchanged
            _make_finding("D", "LOW",       5),  # new
        ])
        diff = diff_scans(old, new)
        total = (
            len(diff.new_findings) +
            len(diff.fixed_findings) +
            len(diff.worsened_findings) +
            len(diff.improved_findings) +
            len(diff.unchanged_findings)
        )
        assert total == len(diff.diffs)
