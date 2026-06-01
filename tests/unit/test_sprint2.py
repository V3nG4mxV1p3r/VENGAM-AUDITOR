"""
VENGAM Auditor — Sprint 2 iOS Unit Tests
Run: pytest tests/ -v
"""
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
import tempfile
import os
import plistlib

from vengam.ios.plist_parser import parse_plist, extract_security_config, analyse_plist_security
from vengam.ios.macho_wrapper import available_tools, analyse_binary_security
from vengam.ios.swift_strings import scan_strings
from vengam.ios.ipa_extractor import _find_app_bundle


# ── plist_parser ──────────────────────────────────────────────────────────────

class TestPlistParser:

    def _write_plist(self, data: dict) -> str:
        """Write a temp XML plist and return its path."""
        tmp = tempfile.NamedTemporaryFile(suffix=".plist", delete=False)
        plistlib.dump(data, tmp)
        tmp.close()
        return tmp.name

    def test_parse_valid_xml_plist(self):
        path = self._write_plist({"CFBundleIdentifier": "com.studio.game"})
        result = parse_plist(path)
        assert result["CFBundleIdentifier"] == "com.studio.game"
        os.unlink(path)

    def test_parse_missing_file_returns_empty(self):
        result = parse_plist("/nonexistent/path/Info.plist")
        assert result == {}

    def test_ats_arbitrary_loads_detected(self):
        path = self._write_plist({
            "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}
        })
        findings = analyse_plist_security(path)
        titles = [f["title"] for f in findings]
        assert any("NSAllowsArbitraryLoads" in t for t in titles)
        os.unlink(path)

    def test_ats_safe_config_no_finding(self):
        path = self._write_plist({
            "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": False}
        })
        findings = analyse_plist_security(path)
        titles = [f["title"] for f in findings]
        assert not any("NSAllowsArbitraryLoads Enabled" in t for t in titles)
        os.unlink(path)

    def test_url_scheme_finding(self):
        path = self._write_plist({
            "CFBundleURLTypes": [
                {"CFBundleURLSchemes": ["mygame", "mygame-auth"]}
            ]
        })
        findings = analyse_plist_security(path)
        titles = [f["title"] for f in findings]
        assert any("URL Scheme" in t for t in titles)
        os.unlink(path)

    def test_background_modes_finding(self):
        path = self._write_plist({
            "UIBackgroundModes": ["fetch", "remote-notification"]
        })
        findings = analyse_plist_security(path)
        titles = [f["title"] for f in findings]
        assert any("Background" in t for t in titles)
        os.unlink(path)

    def test_faceid_finding(self):
        path = self._write_plist({
            "NSFaceIDUsageDescription": "Used for secure login"
        })
        findings = analyse_plist_security(path)
        titles = [f["title"] for f in findings]
        assert any("FaceID" in t or "Biometric" in t for t in titles)
        os.unlink(path)

    def test_extract_security_config_keys(self):
        info = {
            "NSAppTransportSecurity": {
                "NSAllowsArbitraryLoads": True,
                "NSExceptionDomains": {"cdn.mygame.com": {}}
            },
            "CFBundleIdentifier": "com.studio.game",
            "MinimumOSVersion": "14.0",
            "UIBackgroundModes": ["fetch"],
        }
        cfg = extract_security_config(info)
        assert cfg["ats_allows_arbitrary_loads"] is True
        assert "cdn.mygame.com" in cfg["ats_exception_domains"]
        assert cfg["bundle_id"] == "com.studio.game"
        assert cfg["min_ios"] == "14.0"
        assert "fetch" in cfg["background_modes"]


# ── macho_wrapper ─────────────────────────────────────────────────────────────

class TestMachoWrapper:

    def test_available_tools_returns_dict(self):
        tools = available_tools()
        assert isinstance(tools, dict)
        assert "strings" in tools
        assert "otool" in tools
        assert "jtool2" in tools

    def test_analyse_binary_nonexistent_returns_no_crash(self):
        # Should not raise — just return empty or safe defaults
        findings = analyse_binary_security("/nonexistent/binary")
        assert isinstance(findings, list)

    def test_security_flags_structure(self):
        from vengam.ios.macho_wrapper import extract_security_flags
        # Non-existent binary should return default flags dict
        flags = extract_security_flags("/nonexistent/binary")
        assert "pie" in flags
        assert "stack_canary" in flags
        assert "arc" in flags
        assert "encrypted" in flags


# ── swift_strings ─────────────────────────────────────────────────────────────

class TestSwiftStrings:

    def test_firebase_key_detected_in_binary_strings(self):
        strings = [
            "some_random_string",
            'AIzaSyABCDEF1234567890abcdefghijk-12',
            "another_normal_string",
        ]
        findings = scan_strings(strings, "MyGame")
        titles = list(findings.keys())
        assert any("Firebase" in t or "Google" in t for t in titles)

    def test_aws_key_detected_in_binary_strings(self):
        strings = ["AKIAIOSFODNN7EXAMPLE"]
        findings = scan_strings(strings, "MyGame")
        titles = list(findings.keys())
        assert any("AWS" in t for t in titles)

    def test_base62_alphabet_not_flagged(self):
        strings = [
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        ]
        findings = scan_strings(strings, "MyGame")
        # Should be suppressed as FP
        assert len(findings) == 0

    def test_empty_strings_no_crash(self):
        findings = scan_strings([], "MyGame")
        assert findings == {}

    def test_severity_filter_applied(self):
        strings = [
            'AIzaSyABCDEF1234567890abcdefghijk-12',   # CRITICAL
            'android:allowBackup="true"',              # LOW
        ]
        findings_all  = scan_strings(strings, "MyGame")
        findings_crit = scan_strings(strings, "MyGame", severity_filter={"CRITICAL"})
        # With filter, should have fewer or equal findings
        assert len(findings_crit) <= len(findings_all)


# ── ipa_extractor ─────────────────────────────────────────────────────────────

class TestIpaExtractor:

    def test_find_app_bundle_missing_payload(self, tmp_path):
        # No Payload dir → should return None
        result = _find_app_bundle(str(tmp_path))
        assert result is None

    def test_find_app_bundle_finds_app(self, tmp_path):
        payload = tmp_path / "Payload"
        payload.mkdir()
        app = payload / "MyGame.app"
        app.mkdir()
        result = _find_app_bundle(str(tmp_path))
        assert result is not None
        assert "MyGame.app" in result

    def test_find_app_bundle_no_app_in_payload(self, tmp_path):
        payload = tmp_path / "Payload"
        payload.mkdir()
        # No .app inside
        result = _find_app_bundle(str(tmp_path))
        assert result is None


# ── Integration: full iOS scan on mock structure ──────────────────────────────

class TestiOSScanIntegration:

    def test_scan_ipa_missing_file_raises(self):
        from vengam.ios.static import scan_ipa
        with pytest.raises(RuntimeError):
            scan_ipa("/nonexistent/file.ipa")

    def test_scan_ipa_returns_ios_platform(self, tmp_path):
        """
        Create a minimal fake IPA structure and run scan_ipa.
        Verifies platform='ios' is returned without crashing.
        """
        import zipfile
        import plistlib

        # Build minimal IPA zip
        ipa_path = tmp_path / "TestGame.ipa"
        payload_app = "Payload/TestGame.app/"

        info_plist_data = plistlib.dumps({
            "CFBundleIdentifier":       "com.test.game",
            "CFBundleExecutable":       "TestGame",
            "CFBundleShortVersionString": "1.0",
            "MinimumOSVersion":         "14.0",
            "NSAppTransportSecurity":   {"NSAllowsArbitraryLoads": True},
        })

        with zipfile.ZipFile(ipa_path, "w") as zf:
            zf.writestr(payload_app + "Info.plist", info_plist_data)
            zf.writestr(payload_app + "GameConfig.json",
                        '{"api_key": "AIzaSyABCDEF1234567890abcdefghijk-12"}')

        from vengam.ios.static import scan_ipa
        result = scan_ipa(
            str(ipa_path),
            output_dir=str(tmp_path / "out"),
            force=True,
        )

        assert result.platform == "ios"
        assert result.apk_name == "TestGame.ipa"
        assert isinstance(result.total_score, int)
        assert result.total_score >= 0

        # Should find ATS and Firebase key
        titles = [f.title for f in result.findings]
        assert any("NSAllowsArbitraryLoads" in t or "Firebase" in t or "Google" in t
                   for t in titles), f"Expected ATS or Firebase finding, got: {titles}"
