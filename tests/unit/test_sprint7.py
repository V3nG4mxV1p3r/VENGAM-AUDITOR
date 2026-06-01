"""
VENGAM Auditor — Sprint 7 Final Unit Tests
Tüm modüllerin son doğrulama testleri.
Run: pytest tests/unit/test_sprint7.py -v
"""
import json
import os
import datetime
import tempfile
from pathlib import Path

import pytest

from vengam.core.models import (
    Finding, FindingLocation, ScanResult,
    AttackSurface, EngineStats, DynamicFinding,
)
from vengam.core.fp_filter import FalsePositiveFilter
from vengam.core.risk_engine import (
    calculate_risk, derive_business_impacts, verdict_explanation,
)
from vengam.patterns.loader import COMPILED_PATTERNS, PATTERN_COUNT
from vengam.utils.entropy import shannon_entropy, is_alphabet_string, classify_high_entropy_string
from vengam.utils.crypto import redact_secret, sha256_string
from vengam.reports import text_report, json_report, sarif_report
from vengam.android.attack_surface import categorise_url


# ── Helpers ───────────────────────────────────────────────────────────────────

def _finding(title="Test", severity="HIGH", score=20, category="General") -> Finding:
    return Finding(
        title=title, severity=severity, confidence="HIGH",
        exploitability="CONFIRMED", secret_type="Test",
        description="Test desc", simulation="Test sim",
        score_value=score, category=category,
        triage_note="Test triage",
        locations=[FindingLocation(
            file="smali/Test.smali", line=1,
            snippet="test snippet", redacted_match="test****match",
        )],
    )


def _scan(findings=None, score=30, verdict="AT RISK — REMEDIATION REQUIRED") -> ScanResult:
    return ScanResult(
        apk_name="TestGame.apk",
        apk_sha256="abc" * 20,
        scan_timestamp=datetime.datetime.utcnow().isoformat() + "Z",
        findings=findings or [_finding()],
        dynamic_findings=[],
        attack_surface=AttackSurface(
            auth={"/auth/login"},
            payment={"/pay/checkout"},
            user_data={"/api/player"},
            internal_api={"/api/v1/game"},
            other=set(),
        ),
        total_score=score,
        verdict=verdict,
        engine_stats=EngineStats(
            files_scanned=100, lines_scanned=50000,
            fp_suppressed=12, patterns_run=42,
            scan_duration_sec=2.5,
        ),
        platform="android",
    )


# ── Pattern registry completeness ─────────────────────────────────────────────

class TestPatternRegistry:

    def test_pattern_count_sufficient(self):
        assert PATTERN_COUNT >= 35, f"Expected 35+ patterns, got {PATTERN_COUNT}"

    def test_all_required_fields_present(self):
        required = {
            "title", "regex", "severity", "confidence",
            "exploitability", "description", "simulation",
            "score_value", "category", "triage_note",
        }
        for pat in COMPILED_PATTERNS:
            missing = required - pat.keys()
            assert not missing, f"Pattern '{pat.get('title')}' missing: {missing}"

    def test_all_severities_valid(self):
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for pat in COMPILED_PATTERNS:
            assert pat["severity"] in valid, \
                f"Invalid severity '{pat['severity']}' in '{pat['title']}'"

    def test_all_categories_valid(self):
        valid = {"General", "GameEngine", "AntiCheat", "Economy", "Config"}
        for pat in COMPILED_PATTERNS:
            assert pat["category"] in valid, \
                f"Invalid category '{pat['category']}' in '{pat['title']}'"

    def test_score_values_reasonable(self):
        for pat in COMPILED_PATTERNS:
            score = pat["score_value"]
            assert 1 <= score <= 50, \
                f"Suspicious score {score} in '{pat['title']}'"

    def test_critical_patterns_exist(self):
        crits = [p for p in COMPILED_PATTERNS if p["severity"] == "CRITICAL"]
        assert len(crits) >= 10, f"Expected 10+ CRITICAL patterns, got {len(crits)}"

    def test_game_engine_patterns_exist(self):
        ge = [p for p in COMPILED_PATTERNS if p["category"] == "GameEngine"]
        assert len(ge) >= 5, f"Expected 5+ GameEngine patterns"

    def test_economy_patterns_exist(self):
        eco = [p for p in COMPILED_PATTERNS if p["category"] == "Economy"]
        assert len(eco) >= 4, f"Expected 4+ Economy patterns"

    def test_no_duplicate_titles(self):
        titles = [p["title"] for p in COMPILED_PATTERNS]
        assert len(titles) == len(set(titles)), "Duplicate pattern titles found"

    def test_regex_all_compile(self):
        import re
        for pat in COMPILED_PATTERNS:
            assert "_re" in pat, f"Pattern '{pat['title']}' has no compiled regex"
            assert hasattr(pat["_re"], "search"), f"_re is not a compiled pattern"


# ── FP Filter edge cases ──────────────────────────────────────────────────────

class TestFPFilterEdgeCases:

    def test_empty_string_not_crash(self):
        is_fp, reason = FalsePositiveFilter.check("", "", "test.smali")
        assert isinstance(is_fp, bool)

    def test_very_long_string_not_crash(self):
        long_str = "a" * 10000
        is_fp, reason = FalsePositiveFilter.check(long_str, long_str, "test.smali")
        assert isinstance(is_fp, bool)

    def test_numeric_string_suppressed(self):
        is_fp, _ = FalsePositiveFilter.check("1.2.3.4", "version=1.2.3.4", "config.xml")
        assert is_fp

    def test_android_resource_ref_suppressed(self):
        for ref in ["@string/app_name", "@color/primary", "@drawable/icon"]:
            is_fp, _ = FalsePositiveFilter.check(ref, f'android:label="{ref}"', "manifest.xml")
            assert is_fp, f"{ref} should be suppressed"

    def test_known_benign_corpus(self):
        corpus = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        is_fp, _ = FalsePositiveFilter.check(corpus, corpus, "Encoder.java")
        assert is_fp

    def test_real_firebase_key_not_suppressed(self):
        key  = "AIzaSyABCDEF1234567890abcdefghijk-XY"
        line = f'String API_KEY = "{key}";'
        is_fp, _ = FalsePositiveFilter.check(key, line, "GameConfig.java")
        assert not is_fp

    def test_real_aws_key_not_suppressed(self):
        key  = "AKIAIOSFODNN7EXAMPLE"
        line = f'aws_access_key_id={key}'
        is_fp, _ = FalsePositiveFilter.check(key, line, "config.properties")
        assert not is_fp

    def test_debug_mode_in_payment_lib_suppressed(self):
        is_fp, _ = FalsePositiveFilter.check(
            "debugMode", "this.debugMode = true;",
            "com/adyen/checkout/DropInActivity.smali",
            pattern_title="Debug / God Mode Flag",
        )
        assert is_fp

    def test_client_validat_in_game_context_not_suppressed(self):
        is_fp, _ = FalsePositiveFilter.check(
            "clientValidation",
            "if (clientValidation(playerGold, MAX_GOLD))",
            "com/studio/game/EconomyManager.smali",
            pattern_title="Client-Side Currency / Score Validation",
        )
        assert not is_fp

    def test_client_validat_outside_game_context_suppressed(self):
        is_fp, _ = FalsePositiveFilter.check(
            "clientValidation",
            "AddressClientValidation.validate(address)",
            "com/adyen/checkout/AddressValidator.smali",
            pattern_title="Client-Side Currency / Score Validation",
        )
        assert is_fp


# ── Entropy utilities ─────────────────────────────────────────────────────────

class TestEntropyUtilities:

    def test_empty_string_zero(self):
        assert shannon_entropy("") == 0.0

    def test_single_char_zero(self):
        assert shannon_entropy("aaaa") < 0.01

    def test_max_entropy_approaches_log2_charset(self):
        import math
        s   = "".join(chr(i) for i in range(128))
        ent = shannon_entropy(s)
        assert ent > 6.5

    def test_firebase_key_high_entropy(self):
        key = "AIzaSyABCDEF1234567890abcdefghijk-XY"
        assert shannon_entropy(key) > 4.0

    def test_alphabet_detection_true(self):
        assert is_alphabet_string(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        )

    def test_alphabet_detection_too_short(self):
        assert not is_alphabet_string("ABCDE")

    def test_alphabet_detection_repetitive(self):
        assert not is_alphabet_string("a" * 62)

    def test_classify_jwt(self):
        jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature_here"
        s_type, _ = classify_high_entropy_string(jwt)
        assert "JWT" in s_type

    def test_classify_hex(self):
        hex_str = "deadbeef" * 8
        s_type, _ = classify_high_entropy_string(hex_str)
        assert "Hex" in s_type or "Crypto" in s_type


# ── Crypto utilities ──────────────────────────────────────────────────────────

class TestCryptoUtilities:

    def test_redact_long_secret(self):
        secret = "AIzaSyABCDEF1234567890abcdefghijk"
        result = redact_secret(secret)
        assert result.startswith("AIza")
        assert result.endswith("hijk")
        assert "****" in result
        assert len(result) == len(secret)

    def test_redact_short_secret(self):
        assert redact_secret("short") == "***REDACTED***"

    def test_redact_exactly_10_chars(self):
        result = redact_secret("1234567890")
        assert result == "***REDACTED***"

    def test_sha256_string_deterministic(self):
        h1 = sha256_string("hello")
        h2 = sha256_string("hello")
        assert h1 == h2
        assert len(h1) == 64

    def test_sha256_different_inputs(self):
        assert sha256_string("hello") != sha256_string("world")


# ── Attack surface mapping ────────────────────────────────────────────────────

class TestAttackSurfaceMapping:

    def test_auth_routes(self):
        for path in ["/auth/login", "/oauth/token", "/sso/callback", "/signin"]:
            assert categorise_url(path, "api.game.com") == "auth"

    def test_payment_routes(self):
        for path in ["/pay/checkout", "/billing/invoice", "/wallet/topup"]:
            assert categorise_url(path, "api.game.com") == "payment"

    def test_user_data_routes(self):
        for path in ["/user/profile", "/player/stats", "/account/settings"]:
            assert categorise_url(path, "api.game.com") == "user_data"

    def test_internal_api_routes(self):
        for path in ["/api/v1/game", "/graphql", "/rpc/service"]:
            assert categorise_url(path, "api.game.com") == "internal_api"

    def test_other_routes(self):
        assert categorise_url("/cdn/assets/image.png", "cdn.game.com") == "other"


# ── Risk engine edge cases ────────────────────────────────────────────────────

class TestRiskEngineEdgeCases:

    def test_score_capped_at_100(self):
        findings = [_finding(score=50) for _ in range(10)]
        score, _ = calculate_risk(findings, AttackSurface())
        assert score == 100

    def test_score_not_negative(self):
        score, _ = calculate_risk([], AttackSurface())
        assert score >= 0

    def test_combo_penalty_firebase_auth(self):
        f_firebase = _finding("Google / Firebase API Key", "CRITICAL", 30)
        surface    = AttackSurface(auth={"/auth/login"})
        score_no_surface, _ = calculate_risk([f_firebase], AttackSurface())
        score_with_surface, _ = calculate_risk([f_firebase], surface)
        assert score_with_surface > score_no_surface

    def test_business_impacts_populated(self):
        f = _finding("Google / Firebase API Key", "CRITICAL", 30, "General")
        surface = AttackSurface(auth={"/auth/login"})
        impacts = derive_business_impacts([f], surface)
        assert len(impacts) > 0
        assert any("Account" in i or "Infrastructure" in i for i in impacts)

    def test_verdict_explanation_block(self):
        reason, action = verdict_explanation("BLOCK RELEASE")
        assert "Critical" in reason or "critical" in reason
        assert "HALT" in action or "Rotate" in action

    def test_verdict_explanation_safe(self):
        reason, action = verdict_explanation("CONDITIONALLY SAFE")
        assert "No critical" in reason or "acceptable" in reason


# ── ScanResult model ──────────────────────────────────────────────────────────

class TestScanResultModel:

    def test_findings_by_severity(self):
        findings = [
            _finding("A", "CRITICAL"), _finding("B", "HIGH"),
            _finding("C", "CRITICAL"), _finding("D", "LOW"),
        ]
        result = _scan(findings=findings)
        assert len(result.findings_by_severity("CRITICAL")) == 2
        assert len(result.findings_by_severity("HIGH"))     == 1
        assert len(result.findings_by_severity("LOW"))      == 1

    def test_findings_by_category(self):
        findings = [
            _finding("A", category="Economy"),
            _finding("B", category="AntiCheat"),
            _finding("C", category="Economy"),
        ]
        result = _scan(findings=findings)
        assert len(result.findings_by_category("Economy"))   == 2
        assert len(result.findings_by_category("AntiCheat")) == 1

    def test_to_dict_finding(self):
        f    = _finding()
        d    = f.to_dict()
        assert "title"        in d
        assert "severity"     in d
        assert "locations"    in d
        assert "triage_note"  in d
        assert isinstance(d["locations"], list)

    def test_finding_location_in_dict(self):
        f   = _finding()
        loc = f.to_dict()["locations"][0]
        assert "file"           in loc
        assert "line"           in loc
        assert "snippet"        in loc
        assert "redacted_match" in loc

    def test_attack_surface_total(self):
        surface = AttackSurface(
            auth={"/a", "/b"}, payment={"/c"},
            user_data=set(), internal_api={"/d", "/e", "/f"},
            other=set(),
        )
        assert surface.total == 6


# ── Report outputs final validation ──────────────────────────────────────────

class TestReportOutputsFinal:

    def test_text_report_complete_sections(self, tmp_path):
        result = _scan()
        out    = str(tmp_path / "report.txt")
        text_report.generate(result, out)
        content = Path(out).read_text()
        for section in [
            "SCAN METADATA", "EXECUTIVE SUMMARY",
            "STATIC FINDINGS", "ATTACK SURFACE",
            "RISK SCORE BREAKDOWN", "REMEDIATION",
            "FINAL VERDICT",
        ]:
            assert section in content, f"Missing section: {section}"

    def test_json_report_schema(self, tmp_path):
        result = _scan()
        out    = str(tmp_path / "report.json")
        json_report.generate(result, out)
        data   = json.loads(Path(out).read_text())
        for key in [
            "schema_version", "tool", "tool_version", "platform",
            "apk_name", "apk_sha256", "scan_timestamp",
            "risk_score", "verdict", "engine_stats",
            "findings", "attack_surface", "business_impacts",
        ]:
            assert key in data, f"Missing JSON key: {key}"

    def test_sarif_github_compatible(self, tmp_path):
        result = _scan()
        out    = str(tmp_path / "report.sarif")
        sarif_report.generate(result, out)
        data   = json.loads(Path(out).read_text())
        assert data["version"] == "2.1.0"
        assert "$schema"       in data
        run = data["runs"][0]
        assert run["tool"]["driver"]["name"] == "VENGAM GameSec Auditor"
        assert "rules"   in run["tool"]["driver"]
        assert "results" in run

    def test_reports_dont_expose_full_secrets(self, tmp_path):
        finding = _finding()
        finding.locations[0].redacted_match = "AIza****ghij"
        result  = _scan(findings=[finding])

        # Text report
        txt_out = str(tmp_path / "r.txt")
        text_report.generate(result, txt_out)
        txt = Path(txt_out).read_text()
        assert "AIzaSyABCDEF1234567890" not in txt

        # JSON report
        json_out = str(tmp_path / "r.json")
        json_report.generate(result, json_out)
        js = Path(json_out).read_text()
        assert "AIzaSyABCDEF1234567890" not in js

    def test_ios_platform_in_reports(self, tmp_path):
        result          = _scan()
        result.platform = "ios"
        result.apk_name = "TestGame.ipa"
        out = str(tmp_path / "ios_report.json")
        json_report.generate(result, out)
        data = json.loads(Path(out).read_text())
        assert data["platform"] == "ios"

    def test_dynamic_findings_in_json(self, tmp_path):
        result = _scan()
        result.dynamic_findings = [
            DynamicFinding(
                hook_name="Hardcoded Crypto Key (Runtime Confirmed)",
                severity="CRITICAL",
                description="SecretKeySpec with hardcoded bytes.",
                evidence=["CCCrypt key: deadbeef12345678"],
                score_value=30,
            )
        ]
        out  = str(tmp_path / "report.json")
        json_report.generate(result, out)
        data = json.loads(Path(out).read_text())
        assert len(data["dynamic_findings"]) == 1
        assert data["dynamic_findings"][0]["severity"] == "CRITICAL"
