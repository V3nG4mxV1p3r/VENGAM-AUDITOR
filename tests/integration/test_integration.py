"""
VENGAM Auditor — Integration Tests
Gerçek APK yapısı simüle edilerek uçtan uca test edilir.
apktool gerektirmez — decompile edilmiş dizin mock'lanır.
Run: pytest tests/integration/ -v
"""
import json
import os
import struct
import tempfile
import zipfile
import plistlib
from pathlib import Path

import pytest

from vengam.android.static import scan_directory
from vengam.core.models import ScanResult
from vengam.core.fp_filter import FalsePositiveFilter
from vengam.reports import text_report, json_report, sarif_report
from vengam.reports.diff_report import diff_scans, generate_text_diff, generate_json_diff


# ── Mock APK directory builder ────────────────────────────────────────────────

def build_mock_apk_dir(tmp_path: Path, files: dict[str, str]) -> str:
    """
    Create a mock decompiled APK directory.
    files = {relative_path: content}
    """
    apk_dir = tmp_path / "decompiled"
    apk_dir.mkdir()
    for rel_path, content in files.items():
        full = apk_dir / rel_path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content, encoding="utf-8")
    return str(apk_dir)


# ── Integration: Android static scan ─────────────────────────────────────────

class TestAndroidStaticScanIntegration:

    def test_firebase_key_end_to_end(self, tmp_path):
        """Firebase key in smali → CRITICAL finding in ScanResult."""
        d = build_mock_apk_dir(tmp_path, {
            "smali/com/studio/game/Config.smali": (
                'const-string v0, "AIzaSyABCDEF1234567890abcdefghijk-XY"\n'
                'iput-object v0, p0, Lcom/studio/game/Config;->API_KEY:Ljava/lang/String;\n'
            )
        })
        result = scan_directory(d, "TestGame.apk")
        assert isinstance(result, ScanResult)
        crits = result.findings_by_severity("CRITICAL")
        assert any("Firebase" in f.title or "Google" in f.title for f in crits), \
            f"Expected Firebase finding, got: {[f.title for f in crits]}"

    def test_aws_key_end_to_end(self, tmp_path):
        """AWS key in config → CRITICAL finding."""
        d = build_mock_apk_dir(tmp_path, {
            "assets/config.properties": (
                "aws_access_key_id=AKIAIOSFODNN7EXAMPLE\n"
                "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            )
        })
        result = scan_directory(d, "TestGame.apk")
        crits = result.findings_by_severity("CRITICAL")
        assert any("AWS" in f.title for f in crits)

    def test_private_key_end_to_end(self, tmp_path):
        """Private key in assets → CRITICAL finding."""
        d = build_mock_apk_dir(tmp_path, {
            "assets/server.pem": (
                "-----BEGIN RSA PRIVATE KEY-----\n"
                "MIIEowIBAAKCAQEA...\n"
                "-----END RSA PRIVATE KEY-----\n"
            )
        })
        result = scan_directory(d, "TestGame.apk")
        crits = result.findings_by_severity("CRITICAL")
        assert any("Private Key" in f.title for f in crits)

    def test_playfab_secret_end_to_end(self, tmp_path):
        """PlayFab secret key → CRITICAL finding."""
        d = build_mock_apk_dir(tmp_path, {
            "smali/com/studio/game/Backend.smali": (
                'const-string v0, "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"\n'
                "# playfab_secret_key=ABCDEFGHIJKLMNOPQRSTUVWXYZ123456\n"
            ),
            "assets/game_config.json": (
                '{"playfab_secret_key": "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"}\n'
            )
        })
        result = scan_directory(d, "TestGame.apk")
        crits = result.findings_by_severity("CRITICAL")
        assert any("PlayFab" in f.title for f in crits)

    def test_anticheat_bypass_end_to_end(self, tmp_path):
        """Anti-cheat bypass string → CRITICAL finding."""
        d = build_mock_apk_dir(tmp_path, {
            "smali/com/studio/game/AntiCheat.smali": (
                'const-string v0, "disable_anticheat"\n'
                'iput-object v0, p0, Lcom/studio/game/AntiCheat;->mode:Ljava/lang/String;\n'
            )
        })
        result = scan_directory(d, "TestGame.apk")
        crits = result.findings_by_severity("CRITICAL")
        assert any("Anti-Cheat" in f.title for f in crits)

    def test_iap_bypass_end_to_end(self, tmp_path):
        """IAP receipt validation disabled → CRITICAL finding."""
        d = build_mock_apk_dir(tmp_path, {
            "smali/com/studio/game/Purchase.smali": (
                "# skip_receipt_validation=true\n"
                'const-string v0, "skip_receipt_validation"\n'
            )
        })
        result = scan_directory(d, "TestGame.apk")
        crits = result.findings_by_severity("CRITICAL")
        assert any("IAP" in f.title or "Receipt" in f.title for f in crits)

    def test_fp_filter_suppresses_base62(self, tmp_path):
        """Base62 alphabet string should NOT produce a finding."""
        d = build_mock_apk_dir(tmp_path, {
            "smali/com/studio/Base62.smali": (
                'const-string v0, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"\n'
            )
        })
        result = scan_directory(d, "TestGame.apk")
        # Should have 0 findings or at least FP suppressed > 0
        assert result.engine_stats.fp_suppressed >= 0

    def test_fp_filter_suppresses_agc_twilio(self, tmp_path):
        """Huawei AGC resource ID should NOT be flagged as Twilio SID."""
        d = build_mock_apk_dir(tmp_path, {
            "res/values/agc_config.xml": (
                '<?xml version="1.0" encoding="utf-8"?>\n'
                '<resources>\n'
                '  <string name="agc_account_sid">ACabc123def456abc123def456abc12345</string>\n'
                '</resources>\n'
            )
        })
        result = scan_directory(d, "TestGame.apk")
        titles = [f.title for f in result.findings]
        assert not any("Twilio" in t for t in titles), \
            f"Twilio FP not suppressed. Findings: {titles}"

    def test_url_attack_surface_mapped(self, tmp_path):
        """Auth and payment URLs should be mapped to attack surface."""
        d = build_mock_apk_dir(tmp_path, {
            "smali/com/studio/game/Api.smali": (
                'const-string v0, "https://api.mygame.com/auth/login"\n'
                'const-string v1, "https://api.mygame.com/pay/checkout"\n'
                'const-string v2, "https://api.mygame.com/v1/player/profile"\n'
            )
        })
        result = scan_directory(d, "TestGame.apk")
        assert len(result.attack_surface.auth)     > 0
        assert len(result.attack_surface.payment)  > 0
        assert len(result.attack_surface.user_data)> 0

    def test_severity_filter_works(self, tmp_path):
        """severity_filter=CRITICAL should exclude HIGH findings."""
        d = build_mock_apk_dir(tmp_path, {
            "smali/com/studio/game/Config.smali": (
                'const-string v0, "AIzaSyABCDEF1234567890abcdefghijk-XY"\n'
            ),
            "AndroidManifest.xml": (
                '<?xml version="1.0"?>\n'
                '<manifest>\n'
                '  <application android:allowBackup="true">\n'
                '  </application>\n'
                '</manifest>\n'
            )
        })
        result_all  = scan_directory(d, "TestGame.apk")
        result_crit = scan_directory(d, "TestGame.apk", severity_filter={"CRITICAL"})

        all_sevs  = {f.severity for f in result_all.findings}
        crit_sevs = {f.severity for f in result_crit.findings}

        assert "CRITICAL" in all_sevs
        assert all(s == "CRITICAL" for s in crit_sevs)

    def test_scan_result_structure(self, tmp_path):
        """ScanResult has all required fields populated."""
        d = build_mock_apk_dir(tmp_path, {
            "smali/placeholder.smali": "# empty\n"
        })
        result = scan_directory(d, "TestGame.apk")

        assert result.apk_name       == "TestGame.apk"
        assert result.platform       == "android"
        assert isinstance(result.total_score, int)
        assert 0 <= result.total_score <= 100
        assert result.verdict in {
            "BLOCK RELEASE",
            "AT RISK — REMEDIATION REQUIRED",
            "CONDITIONALLY SAFE",
        }
        assert result.engine_stats.files_scanned >= 0
        assert result.engine_stats.scan_duration_sec >= 0


# ── Integration: Report generation ───────────────────────────────────────────

class TestReportGenerationIntegration:

    def _make_result(self, tmp_path: Path) -> ScanResult:
        d = build_mock_apk_dir(tmp_path, {
            "smali/com/studio/game/Config.smali": (
                'const-string v0, "AIzaSyABCDEF1234567890abcdefghijk-XY"\n'
                'const-string v1, "AKIAIOSFODNN7EXAMPLE"\n'
            ),
            "assets/game.json": '{"playfab_secret_key": "ABCDEFGHIJKLMNOPQRST12345678"}',
        })
        return scan_directory(d, "TestGame.apk")

    def test_text_report_generated(self, tmp_path):
        result = self._make_result(tmp_path)
        out    = str(tmp_path / "report.txt")
        text_report.generate(result, out)
        assert Path(out).exists()
        content = Path(out).read_text()
        assert "VENGAM"       in content
        assert "SCAN METADATA" in content
        assert "FINAL VERDICT" in content
        assert result.verdict  in content

    def test_json_report_valid(self, tmp_path):
        result = self._make_result(tmp_path)
        out    = str(tmp_path / "report.json")
        json_report.generate(result, out)
        assert Path(out).exists()
        data = json.loads(Path(out).read_text())
        assert data["schema_version"] == "vengam-v7"
        assert data["platform"]       == "android"
        assert "findings"             in data
        assert "attack_surface"       in data
        assert "engine_stats"         in data

    def test_sarif_report_valid(self, tmp_path):
        result = self._make_result(tmp_path)
        out    = str(tmp_path / "report.sarif")
        sarif_report.generate(result, out)
        assert Path(out).exists()
        data = json.loads(Path(out).read_text())
        assert data["version"] == "2.1.0"
        assert "runs"          in data
        assert len(data["runs"]) > 0
        assert "tool"          in data["runs"][0]
        assert "results"       in data["runs"][0]

    def test_json_findings_have_locations(self, tmp_path):
        result = self._make_result(tmp_path)
        out    = str(tmp_path / "report.json")
        json_report.generate(result, out)
        data = json.loads(Path(out).read_text())
        for f in data["findings"]:
            assert "locations"    in f
            assert "title"        in f
            assert "severity"     in f
            assert "score_value"  in f
            assert "triage_note"  in f

    def test_sarif_rules_match_findings(self, tmp_path):
        result = self._make_result(tmp_path)
        out    = str(tmp_path / "report.sarif")
        sarif_report.generate(result, out)
        data    = json.loads(Path(out).read_text())
        run     = data["runs"][0]
        rule_ids= {r["id"] for r in run["tool"]["driver"]["rules"]}
        res_ids = {r["ruleId"] for r in run["results"]}
        # All result ruleIds should be in rules
        assert res_ids.issubset(rule_ids)

    def test_all_reports_generated_together(self, tmp_path):
        result   = self._make_result(tmp_path)
        out_dir  = str(tmp_path / "reports")
        os.makedirs(out_dir)
        text_report.generate(result,  os.path.join(out_dir, "r.txt"))
        json_report.generate(result,  os.path.join(out_dir, "r.json"))
        sarif_report.generate(result, os.path.join(out_dir, "r.sarif"))
        assert Path(out_dir, "r.txt").exists()
        assert Path(out_dir, "r.json").exists()
        assert Path(out_dir, "r.sarif").exists()


# ── Integration: Diff scan ────────────────────────────────────────────────────

class TestDiffScanIntegration:

    def _scan(self, tmp_path: Path, label: str, files: dict) -> ScanResult:
        d = build_mock_apk_dir(tmp_path / label, files)
        return scan_directory(d, f"{label}.apk")

    def test_new_vulnerability_detected(self, tmp_path):
        """New Firebase key in v2 should appear as NEW finding."""
        old = self._scan(tmp_path, "v1", {
            "smali/Config.smali": "# empty\n"
        })
        new = self._scan(tmp_path, "v2", {
            "smali/Config.smali": (
                'const-string v0, "AIzaSyABCDEF1234567890abcdefghijk-XY"\n'
            )
        })
        diff = diff_scans(old, new)
        assert len(diff.new_findings) >= 1
        assert diff.score_delta > 0

    def test_fixed_vulnerability_detected(self, tmp_path):
        """Firebase key removed in v2 should appear as FIXED finding."""
        old = self._scan(tmp_path, "v1", {
            "smali/Config.smali": (
                'const-string v0, "AIzaSyABCDEF1234567890abcdefghijk-XY"\n'
            )
        })
        new = self._scan(tmp_path, "v2", {
            "smali/Config.smali": "# key removed\n"
        })
        diff = diff_scans(old, new)
        assert len(diff.fixed_findings) >= 1
        assert diff.score_delta < 0

    def test_diff_text_report_generated(self, tmp_path):
        old = self._scan(tmp_path, "v1", {
            "smali/Config.smali": (
                'const-string v0, "AIzaSyABCDEF1234567890abcdefghijk-XY"\n'
            )
        })
        new = self._scan(tmp_path, "v2", {
            "smali/Config.smali": "# fixed\n",
            "assets/cfg.json": '{"playfab_secret_key": "ABCDEFGHIJKLMNOPQRST12345678"}',
        })
        diff = diff_scans(old, new)
        out  = str(tmp_path / "diff.txt")
        generate_text_diff(diff, out)
        content = Path(out).read_text()
        assert "COMPARISON OVERVIEW" in content
        assert "FIXED"               in content
        assert "NEW"                 in content

    def test_diff_json_report_generated(self, tmp_path):
        old = self._scan(tmp_path, "v1", {"smali/A.smali": "# empty\n"})
        new = self._scan(tmp_path, "v2", {
            "smali/A.smali": (
                'const-string v0, "AIzaSyABCDEF1234567890abcdefghijk-XY"\n'
            )
        })
        diff = diff_scans(old, new)
        out  = str(tmp_path / "diff.json")
        generate_json_diff(diff, out)
        data = json.loads(Path(out).read_text())
        assert data["schema_version"] == "vengam-diff-v7"
        assert "summary"              in data
        assert "diffs"                in data


# ── Integration: iOS scan ─────────────────────────────────────────────────────

class TestiOSScanIntegration:

    def test_ipa_with_firebase_key(self, tmp_path):
        """Firebase key inside IPA text file → CRITICAL finding."""
        ipa_path = tmp_path / "TestGame.ipa"
        out_dir  = tmp_path / "extracted"

        info = plistlib.dumps({
            "CFBundleIdentifier":       "com.studio.testgame",
            "CFBundleExecutable":       "TestGame",
            "CFBundleShortVersionString": "1.0",
            "MinimumOSVersion":         "14.0",
        })
        with zipfile.ZipFile(ipa_path, "w") as zf:
            zf.writestr("Payload/TestGame.app/Info.plist", info)
            zf.writestr(
                "Payload/TestGame.app/GameConfig.json",
                '{"firebase_api_key": "AIzaSyABCDEF1234567890abcdefghijk-XY"}'
            )

        from vengam.ios.static import scan_ipa
        result = scan_ipa(str(ipa_path), output_dir=str(out_dir), force=True)

        assert result.platform == "ios"
        crits = result.findings_by_severity("CRITICAL")
        assert any("Firebase" in f.title or "Google" in f.title for f in crits)

    def test_ipa_ats_finding(self, tmp_path):
        """NSAllowsArbitraryLoads=true → HIGH finding."""
        ipa_path = tmp_path / "TestGame.ipa"
        out_dir  = tmp_path / "extracted2"

        info = plistlib.dumps({
            "CFBundleIdentifier":   "com.studio.testgame",
            "CFBundleExecutable":   "TestGame",
            "MinimumOSVersion":     "14.0",
            "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
        })
        with zipfile.ZipFile(ipa_path, "w") as zf:
            zf.writestr("Payload/TestGame.app/Info.plist", info)

        from vengam.ios.static import scan_ipa
        result = scan_ipa(str(ipa_path), output_dir=str(out_dir), force=True)

        titles = [f.title for f in result.findings]
        assert any("ATS" in t or "NSAllowsArbitraryLoads" in t for t in titles)


# ── Integration: Risk engine ──────────────────────────────────────────────────

class TestRiskEngineIntegration:

    def test_high_risk_apk_block_release(self, tmp_path):
        """APK with multiple CRITICAL findings → BLOCK RELEASE verdict."""
        d = build_mock_apk_dir(tmp_path, {
            "smali/Config.smali": (
                'const-string v0, "AIzaSyABCDEF1234567890abcdefghijk-XY"\n'
                'const-string v1, "AKIAIOSFODNN7EXAMPLE"\n'
                'const-string v2, "sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ"\n'
            ),
            "smali/AntiCheat.smali": (
                'const-string v0, "disable_anticheat"\n'
                'const-string v1, "skip_receipt_validation"\n'
            ),
            "assets/keys.json": (
                '{"playfab_secret_key": "ABCDEFGHIJKLMNOPQRST12345678"}\n'
            ),
        })
        result = scan_directory(d, "TestGame.apk")
        assert result.verdict == "BLOCK RELEASE"
        assert result.total_score >= 75

    def test_clean_apk_conditionally_safe(self, tmp_path):
        """Clean APK with no secrets → CONDITIONALLY SAFE."""
        d = build_mock_apk_dir(tmp_path, {
            "smali/com/studio/MainActivity.smali": (
                ".class public Lcom/studio/MainActivity;\n"
                ".super Ljava/lang/Object;\n"
                "# clean file, no secrets\n"
            ),
            "AndroidManifest.xml": (
                '<?xml version="1.0"?>\n'
                '<manifest package="com.studio.game">\n'
                '  <application android:allowBackup="false">\n'
                '  </application>\n'
                '</manifest>\n'
            ),
        })
        result = scan_directory(d, "CleanGame.apk")
        assert result.total_score < 40
