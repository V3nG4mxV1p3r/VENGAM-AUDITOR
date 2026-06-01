"""
VENGAM Auditor — Unit Tests
Run: pytest tests/ -v
"""
import pytest
from vengam.core.fp_filter import FalsePositiveFilter
from vengam.core.risk_engine import calculate_risk, _verdict
from vengam.core.models import Finding, AttackSurface
from vengam.utils.entropy import shannon_entropy, is_alphabet_string
from vengam.utils.crypto import redact_secret
from vengam.patterns.loader import COMPILED_PATTERNS, PATTERN_COUNT


# ── FalsePositiveFilter ───────────────────────────────────────────────────────

class TestFalsePositiveFilter:

    def test_safe_package_suppressed(self):
        is_fp, reason = FalsePositiveFilter.check(
            "androidx.core.app", "import androidx.core.app.NotificationManager", "NotificationManager.smali"
        )
        assert is_fp
        assert "androidx" in reason

    def test_base62_alphabet_suppressed(self):
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        is_fp, reason = FalsePositiveFilter.check(alphabet, f'String BASE62 = "{alphabet}";', "Encoder.java")
        assert is_fp
        assert "alphabet" in reason.lower() or "Base62" in reason

    def test_numeric_version_suppressed(self):
        is_fp, _ = FalsePositiveFilter.check("1.2.3.4", "version=1.2.3.4", "config.properties")
        assert is_fp

    def test_android_resource_suppressed(self):
        is_fp, _ = FalsePositiveFilter.check(
            "@string/app_name", 'android:label="@string/app_name"', "AndroidManifest.xml"
        )
        assert is_fp

    def test_agc_twilio_false_positive_suppressed(self):
        is_fp, reason = FalsePositiveFilter.check(
            "ACabc123def456", "agc_resource_id=ACabc123def456", "agc_config.xml",
            pattern_title="Twilio Account SID + Auth Token"
        )
        assert is_fp
        assert "AGC" in reason or "Huawei" in reason

    def test_client_validat_outside_game_context_suppressed(self):
        is_fp, reason = FalsePositiveFilter.check(
            "clientValidation", "AddressClientValidation.validate(address)",
            "com/adyen/checkout/AddressValidator.smali",
            pattern_title="Client-Side Currency / Score Validation"
        )
        assert is_fp

    def test_real_firebase_key_not_suppressed(self):
        is_fp, _ = FalsePositiveFilter.check(
            "AIzaSyABCDEF1234567890abcdefgh-1234567",
            'String API_KEY = "AIzaSyABCDEF1234567890abcdefgh-1234567";',
            "GameConfig.java"
        )
        assert not is_fp

    def test_debug_mode_in_payment_lib_suppressed(self):
        is_fp, reason = FalsePositiveFilter.check(
            "debugMode", "this.debugMode = true;",
            "com/adyen/checkout/DropInActivity.smali",
            pattern_title="Debug / God Mode Flag"
        )
        assert is_fp


# ── Entropy ───────────────────────────────────────────────────────────────────

class TestEntropy:

    def test_low_entropy_string(self):
        assert shannon_entropy("aaaaaaaaaa") < 1.0

    def test_high_entropy_string(self):
        assert shannon_entropy("AIzaSyABCDEF1234567890abcdefghijk") > 4.0

    def test_alphabet_string_detected(self):
        assert is_alphabet_string(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        )

    def test_short_string_not_alphabet(self):
        assert not is_alphabet_string("ABC")

    def test_low_unique_not_alphabet(self):
        assert not is_alphabet_string("a" * 62)


# ── Redaction ─────────────────────────────────────────────────────────────────

class TestRedaction:

    def test_long_secret_redacted(self):
        result = redact_secret("AIzaSyABCDEF1234567890abcdefghijk")
        assert result.startswith("AIza")
        assert "****" in result
        assert result.endswith("hijk")

    def test_short_secret_fully_redacted(self):
        result = redact_secret("short")
        assert result == "***REDACTED***"


# ── Risk Engine ───────────────────────────────────────────────────────────────

class TestRiskEngine:

    def _make_finding(self, severity: str, score: int, title: str = "Test") -> Finding:
        return Finding(
            title=title, severity=severity, confidence="HIGH",
            exploitability="CONFIRMED", secret_type="Test",
            description="Test", simulation="Test", score_value=score,
        )

    def test_no_findings_safe(self):
        score, verdict = calculate_risk([], AttackSurface())
        assert score == 0
        assert verdict == "CONDITIONALLY SAFE"

    def test_critical_finding_block_release(self):
        findings = [self._make_finding("CRITICAL", 80)]
        score, verdict = calculate_risk(findings, AttackSurface())
        assert verdict == "BLOCK RELEASE"
        assert score == 100  # capped at 100

    def test_score_capped_at_100(self):
        findings = [self._make_finding("CRITICAL", 50) for _ in range(5)]
        score, _ = calculate_risk(findings, AttackSurface())
        assert score <= 100

    def test_payment_surface_adds_score(self):
        surface = AttackSurface(payment={"/pay/checkout"})
        score_base, _ = calculate_risk([], AttackSurface())
        score_pay, _  = calculate_risk([], surface)
        assert score_pay > score_base

    def test_verdict_thresholds(self):
        assert _verdict(0)  == "CONDITIONALLY SAFE"
        assert _verdict(40) == "AT RISK — REMEDIATION REQUIRED"
        assert _verdict(75) == "BLOCK RELEASE"


# ── Pattern Registry ──────────────────────────────────────────────────────────

class TestPatterns:

    def test_patterns_loaded(self):
        assert PATTERN_COUNT > 30, "Expected 30+ patterns"

    def test_all_patterns_have_required_fields(self):
        required = {"title", "regex", "severity", "confidence",
                    "exploitability", "description", "simulation", "score_value"}
        for pat in COMPILED_PATTERNS:
            missing = required - pat.keys()
            assert not missing, f"Pattern '{pat.get('title')}' missing: {missing}"

    def test_firebase_key_pattern_matches(self):
        sample = 'String API_KEY = "AIzaSyABCDEF1234567890abcdefghijk-12";'
        matched = [
            p for p in COMPILED_PATTERNS
            if p["title"] == "Google / Firebase API Key" and p["_re"].search(sample)
        ]
        assert matched, "Firebase key pattern should match"

    def test_aws_key_pattern_matches(self):
        sample = "aws_access_key_id=AKIAIOSFODNN7EXAMPLE"
        matched = [
            p for p in COMPILED_PATTERNS
            if p["title"] == "AWS Access Key ID" and p["_re"].search(sample)
        ]
        assert matched, "AWS key pattern should match"

    def test_private_key_pattern_matches(self):
        sample = "-----BEGIN RSA PRIVATE KEY-----"
        matched = [
            p for p in COMPILED_PATTERNS
            if "Private Key" in p["title"] and p["_re"].search(sample)
        ]
        assert matched, "Private key pattern should match"

    def test_pak_encryption_key_pattern_matches(self):
        sample = 'EncryptionKey="AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"'
        matched = [
            p for p in COMPILED_PATTERNS
            if "Unreal" in p["title"] and p["_re"].search(sample)
        ]
        assert matched, "Unreal PAK key pattern should match"
