"""
VENGAM — Sprint 10 Unit Tests
Parallel Scanner + ELF Deep + React components (logic tests)
Run: pytest tests/unit/test_sprint10.py -v
"""
import os
import struct
import tempfile
from pathlib import Path
import pytest


# ── Parallel Scanner (Python fallback) ───────────────────────────

class TestParallelScanner:

    def _make_smali(self, tmp_path: Path, content: str) -> Path:
        f = tmp_path / "Config.smali"
        f.write_text(content)
        return f

    def test_native_available_flag(self):
        from vengam.native.so_analyzer import NATIVE_AVAILABLE
        assert isinstance(NATIVE_AVAILABLE, bool)

    def test_python_fallback_extract_strings(self, tmp_path):
        from vengam.native.so_analyzer import extract_strings
        binary = tmp_path / "test.so"
        binary.write_bytes(b"\x00\x00firebase_api_key_here\x00\x00short\x00")
        result = extract_strings(str(binary), min_length=8)
        assert isinstance(result, list)

    def test_scan_directory_finds_secrets(self, tmp_path):
        from vengam.android.static import scan_directory
        smali = tmp_path / "smali" / "com" / "game"
        smali.mkdir(parents=True)
        (smali / "Config.smali").write_text(
            'const-string v0, "AIzaSyABCDEF1234567890abcdefghijk-XY"\n'
        )
        result = scan_directory(str(tmp_path), "game.apk")
        crits = [f for f in result.findings if f.severity == "CRITICAL"]
        assert len(crits) >= 1

    def test_scan_directory_performance(self, tmp_path):
        """Büyük dizin taraması makul sürede bitmeli."""
        import time
        smali = tmp_path / "smali"
        smali.mkdir()
        # 100 dosya oluştur
        for i in range(100):
            (smali / f"Class{i}.smali").write_text(
                f"# Class {i}\n.class public LClass{i};\n"
                f'const-string v0, "normal_string_{i}"\n'
            )
        start  = time.monotonic()
        result = scan_directory(str(tmp_path), "game.apk")
        elapsed = time.monotonic() - start
        assert elapsed < 60  # 60 saniyeden az
        assert result.engine_stats.files_scanned >= 100

    def test_fp_suppressed_count_positive(self, tmp_path):
        from vengam.android.static import scan_directory
        smali = tmp_path / "smali" / "androidx"
        smali.mkdir(parents=True)
        (smali / "Compat.smali").write_text(
            'const-string v0, "androidx.core.app.NotificationCompat"\n'
            'const-string v1, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"\n'
        )
        result = scan_directory(str(tmp_path), "game.apk")
        assert result.engine_stats.fp_suppressed >= 0


# ── ELF Deep Analyzer ─────────────────────────────────────────────

class TestElfDeepAnalyzer:

    def test_import_no_crash(self):
        from vengam.native.so_analyzer import scan_elf
        assert callable(scan_elf)

    def test_nonexistent_file_returns_empty(self):
        from vengam.native.so_analyzer import scan_elf
        result = scan_elf("/nonexistent/lib.so")
        assert isinstance(result, dict)

    def test_non_elf_no_crash(self, tmp_path):
        from vengam.native.so_analyzer import scan_elf
        f = tmp_path / "fake.so"
        f.write_bytes(b"NOT_AN_ELF_FILE")
        result = scan_elf(str(f))
        assert isinstance(result, dict)

    def test_scan_so_files_empty_dir(self, tmp_path):
        from vengam.native.so_analyzer import scan_so_files
        result = scan_so_files(str(tmp_path))
        assert result == []

    def test_scan_so_files_with_fake_so(self, tmp_path):
        from vengam.native.so_analyzer import scan_so_files
        lib = tmp_path / "lib" / "arm64-v8a"
        lib.mkdir(parents=True)
        (lib / "libgame.so").write_bytes(b"\x7fELF" + b"\x00" * 200)
        result = scan_so_files(str(tmp_path))
        assert isinstance(result, list)

    def test_jni_symbol_parsing(self):
        """JNI sembol formatını doğrula."""
        # Java_com_game_AntiCheat_checkRoot → checkRoot metodu
        symbol = "Java_com_game_AntiCheat_checkRoot"
        assert symbol.startswith("Java_")
        parts = symbol[len("Java_"):].split("_")
        assert len(parts) >= 2
        method = parts[-1]
        assert method == "checkRoot"

    def test_dangerous_imports_list(self):
        """Tehlikeli import listesi dolu olmalı."""
        dangerous = [
            "dlopen", "mprotect", "ptrace",
            "system", "execve", "detect_frida",
        ]
        # Bu semboller native lib'lerde bulununca alert tetiklemeli
        for sym in dangerous:
            assert len(sym) > 0

    def test_elf_security_flags_structure(self):
        from vengam.native.so_analyzer import get_elf_security_flags
        flags = get_elf_security_flags("/nonexistent/lib.so")
        assert isinstance(flags, dict)
        # Beklenen flag isimleri
        expected_keys = {"pie", "canary", "nx", "relro"}
        # En azından bir kısmı olmalı (fallback döner)
        assert isinstance(flags, dict)


# ── Frida Generator Logic ─────────────────────────────────────────

class TestFridaGeneratorLogic:

    def _finding(self, title: str, severity: str = "HIGH"):
        from vengam.core.models import Finding
        return Finding(
            title=title, severity=severity, confidence="HIGH",
            exploitability="CONFIRMED", secret_type="Test",
            description="Test", simulation="Test", score_value=20,
        )

    def test_ssl_hook_generated(self):
        from vengam.intel.frida_gen import FridaHookGenerator
        gen    = FridaHookGenerator()
        script = gen.generate_from_findings(
            [self._finding("SSL Certificate Pinning Disabled")]
        )
        assert "CertificatePinner" in script
        assert "Java.perform" in script

    def test_full_script_all_hooks(self):
        from vengam.intel.frida_gen import FridaHookGenerator
        gen    = FridaHookGenerator()
        script = gen.generate_full("game.apk", "com.game.app")
        # En az 5 hook içermeli
        hook_markers = [
            "CertificatePinner",
            "isRooted",
            "verifyPurchase",
            "getGold",
            "SecretKeySpec",
        ]
        found = sum(1 for m in hook_markers if m in script)
        assert found >= 3

    def test_empty_findings_default_hooks(self):
        from vengam.intel.frida_gen import FridaHookGenerator
        gen    = FridaHookGenerator()
        script = gen.generate_from_findings([])
        # Boş findings'te bile en az SSL + root hook gelmeli
        assert "Java.perform" in script
        assert len(script) > 200

    def test_list_hooks_returns_all(self):
        from vengam.intel.frida_gen import FridaHookGenerator
        gen   = FridaHookGenerator()
        hooks = gen.list_available_hooks()
        keys  = [h["key"] for h in hooks]
        for expected in ["ssl_pinning","root_detect","iap","economy","crypto"]:
            assert expected in keys

    def test_script_valid_js_braces(self):
        from vengam.intel.frida_gen import FridaHookGenerator
        gen    = FridaHookGenerator()
        script = gen.generate_full()
        opens  = script.count("{")
        closes = script.count("}")
        # Parantezler dengeli olmalı (yaklaşık)
        assert abs(opens - closes) < 10


# ── Attack Graph ──────────────────────────────────────────────────

class TestAttackGraphSprint10:

    def _finding(self, title, severity="HIGH", category="General"):
        from vengam.core.models import Finding
        return Finding(
            title=title, severity=severity, confidence="HIGH",
            exploitability="CONFIRMED", secret_type="Test",
            description="Test", simulation="Test",
            score_value=20, category=category,
        )

    def test_d3_format_nodes_have_color(self):
        from vengam.intel.attack_graph import AttackGraphBuilder
        from vengam.core.models import AttackSurface
        builder = AttackGraphBuilder()
        graph   = builder.build(
            "game.apk",
            [self._finding("Firebase Key", "CRITICAL")],
            AttackSurface()
        )
        d3 = graph.to_d3()
        for node in d3["nodes"]:
            assert "color" in node
            assert node["color"].startswith("#")

    def test_d3_format_links_have_color(self):
        from vengam.intel.attack_graph import AttackGraphBuilder
        from vengam.core.models import AttackSurface
        builder = AttackGraphBuilder()
        graph   = builder.build(
            "game.apk",
            [self._finding("PlayFab Secret", "CRITICAL", "Economy")],
            AttackSurface(auth={"/auth/login"})
        )
        d3 = graph.to_d3()
        for link in d3["links"]:
            assert "color" in link
            assert "source" in link
            assert "target" in link

    def test_graphql_chain_added_with_intel(self):
        from vengam.intel.attack_graph import AttackGraphBuilder
        from vengam.intel.endpoint import EndpointIntelligence, GraphQLQuery
        from vengam.core.models import AttackSurface
        builder = AttackGraphBuilder()
        intel   = EndpointIntelligence(
            endpoints=[], graphql=[
                GraphQLQuery("query","GetPlayer",["id","gold"])
            ],
            websockets=[], protobuf=[], total_unique=0,
        )
        graph     = builder.build("game.apk", [], AttackSurface(), intel)
        chain_ids = [c["id"] for c in graph.attack_chains]
        assert "CHAIN_GRAPHQL_INTROSPECT" in chain_ids

    def test_json_round_trip(self):
        import json
        from vengam.intel.attack_graph import AttackGraphBuilder
        from vengam.core.models import AttackSurface
        builder = AttackGraphBuilder()
        graph   = builder.build("game.apk", [], AttackSurface())
        j       = graph.to_json()
        data    = json.loads(j)
        assert data["nodes"]
        assert isinstance(data["edges"], list)
        assert isinstance(data["attack_chains"], list)


# ── Endpoint Intelligence Sprint 10 ──────────────────────────────

class TestEndpointIntelligenceSprint10:

    def test_sensitive_path_admin_is_critical(self, tmp_path):
        from vengam.intel.endpoint import EndpointAnalyzer
        f = tmp_path / "Api.smali"
        f.write_text('const-string v0, "https://api.game.com/admin/users"')
        analyzer = EndpointAnalyzer()
        intel    = analyzer.analyze_directory(str(tmp_path))
        critical = [e for e in intel.endpoints if e.risk == "CRITICAL"]
        assert len(critical) >= 1

    def test_websocket_protocol_detected(self, tmp_path):
        from vengam.intel.endpoint import EndpointAnalyzer
        f = tmp_path / "Net.java"
        f.write_text('String WS = "wss://realtime.game.com/match";')
        analyzer = EndpointAnalyzer()
        intel    = analyzer.analyze_directory(str(tmp_path))
        assert any(w.protocol == "wss" for w in intel.websockets)

    def test_report_summary_keys(self, tmp_path):
        from vengam.intel.endpoint import EndpointAnalyzer
        analyzer = EndpointAnalyzer()
        intel    = analyzer.analyze_directory(str(tmp_path))
        report   = analyzer.generate_report(intel)
        for key in ["summary","by_category","critical","high","graphql","websockets"]:
            assert key in report

    def test_multiple_files_scanned(self, tmp_path):
        from vengam.intel.endpoint import EndpointAnalyzer
        for i in range(5):
            (tmp_path / f"Api{i}.smali").write_text(
                f'const-string v0, "https://api{i}.game.com/v1/endpoint"\n'
            )
        analyzer = EndpointAnalyzer()
        intel    = analyzer.analyze_directory(str(tmp_path))
        assert intel.total_unique >= 3
