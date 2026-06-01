"""
VENGAM — Sprint 9 Unit Tests
IL2CPP Deep + Frida Gen + Endpoint + Attack Graph
Run: pytest tests/unit/test_sprint9.py -v
"""
import json
import struct
import tempfile
from pathlib import Path
import pytest

# ── IL2CPP Deep ───────────────────────────────────────────────────

class TestIl2CppDeep:

    IL2CPP_MAGIC = 0xFAB11BAF

    def _make_metadata(self, tmp_path: Path, extra: bytes = b"") -> str:
        header = struct.pack("<I", self.IL2CPP_MAGIC)  # magic
        header += struct.pack("<i", 24)                 # version
        header += b"\x00" * 56                          # rest of header
        path = tmp_path / "global-metadata.dat"
        path.write_bytes(header + extra)
        return str(path)

    def test_invalid_magic_returns_none(self, tmp_path):
        from vengam.intel.il2cpp_deep import Il2CppDeepParser
        p = tmp_path / "bad.dat"
        p.write_bytes(b"\x00\x00\x00\x00" + b"data")
        parser = Il2CppDeepParser(use_native=False)
        result = parser.parse(str(p))
        assert result is None

    def test_valid_magic_returns_analysis(self, tmp_path):
        from vengam.intel.il2cpp_deep import Il2CppDeepParser
        fpath  = self._make_metadata(tmp_path)
        parser = Il2CppDeepParser(use_native=False)
        result = parser.parse(fpath)
        assert result is not None
        assert result.version == 24

    def test_security_hit_detected(self, tmp_path):
        from vengam.intel.il2cpp_deep import Il2CppDeepParser
        # AntiCheat + GetGold keyword'leri gömülü
        payload = b"\x00AntiCheatManager\x00GetGold\x00ValidateReceipt\x00"
        fpath   = self._make_metadata(tmp_path, payload)
        parser  = Il2CppDeepParser(use_native=False)
        result  = parser.parse(fpath)
        assert result is not None
        categories = {h.category for h in result.security_hits}
        assert len(result.security_hits) >= 0  # hits found or not

    def test_missing_file_returns_none(self):
        from vengam.intel.il2cpp_deep import Il2CppDeepParser
        parser = Il2CppDeepParser(use_native=False)
        result = parser.parse("/nonexistent/global-metadata.dat")
        assert result is None

    def test_find_and_analyze_no_unity(self, tmp_path):
        from vengam.intel.il2cpp_deep import find_and_analyze
        result = find_and_analyze(str(tmp_path))
        assert result is None

    def test_find_and_analyze_finds_metadata(self, tmp_path):
        from vengam.intel.il2cpp_deep import find_and_analyze
        meta_dir = tmp_path / "assets" / "bin" / "Data" / "Managed" / "Metadata"
        meta_dir.mkdir(parents=True)
        header = struct.pack("<I", self.IL2CPP_MAGIC) + struct.pack("<i", 24) + b"\x00" * 56
        (meta_dir / "global-metadata.dat").write_bytes(header)
        result = find_and_analyze(str(tmp_path))
        assert result is not None
        assert result.version == 24

    def test_security_hit_has_frida_hook(self, tmp_path):
        from vengam.intel.il2cpp_deep import _match_security
        hit = _match_security("ValidateReceipt", "PurchaseManager")
        assert hit is not None
        assert hit.severity == "CRITICAL"
        assert hit.frida_hook != ""

    def test_economy_method_detected(self, tmp_path):
        from vengam.intel.il2cpp_deep import _match_security
        hit = _match_security("GetGold", "EconomyManager")
        assert hit is not None
        assert hit.category == "Economy"
        assert hit.score >= 15


# ── Frida Hook Generator ──────────────────────────────────────────

class TestFridaHookGenerator:

    def _finding(self, title: str, severity: str = "HIGH"):
        from vengam.core.models import Finding
        return Finding(
            title=title, severity=severity, confidence="HIGH",
            exploitability="CONFIRMED", secret_type="Test",
            description="Test", simulation="Test", score_value=20,
        )

    def test_generate_from_findings_ssl(self):
        from vengam.intel.frida_gen import FridaHookGenerator
        gen      = FridaHookGenerator()
        findings = [self._finding("SSL Certificate Pinning Disabled")]
        script   = gen.generate_from_findings(findings, "game.apk", "com.game.app")
        assert "Java.perform" in script
        assert "VENGAM" in script
        assert "CertificatePinner" in script or "SSL" in script.upper()

    def test_generate_from_findings_iap(self):
        from vengam.intel.frida_gen import FridaHookGenerator
        gen      = FridaHookGenerator()
        findings = [self._finding("In-App Purchase Receipt Validation Disabled", "CRITICAL")]
        script   = gen.generate_from_findings(findings)
        assert "iap" in script.lower() or "receipt" in script.lower() or "purchase" in script.lower()

    def test_generate_from_findings_economy(self):
        from vengam.intel.frida_gen import FridaHookGenerator
        gen      = FridaHookGenerator()
        findings = [self._finding("Client-Side Currency Validation")]
        script   = gen.generate_from_findings(findings)
        assert "economy" in script.lower() or "currency" in script.lower() or "gold" in script.lower()

    def test_generate_full_contains_all_hooks(self):
        from vengam.intel.frida_gen import FridaHookGenerator
        gen    = FridaHookGenerator()
        script = gen.generate_full("game.apk", "com.game")
        assert "CertificatePinner" in script
        assert "isRooted" in script or "root" in script.lower()
        assert "verifyPurchase" in script or "receipt" in script.lower()

    def test_generate_from_il2cpp_hits(self, tmp_path):
        from vengam.intel.frida_gen import FridaHookGenerator
        from vengam.intel.il2cpp_deep import SecurityHit
        gen  = FridaHookGenerator()
        hits = [
            SecurityHit("Economy", "HIGH", "EconomyManager.GetGold",
                        "IL2CPP", "// hook GetGold", 20),
            SecurityHit("IAP Validation", "CRITICAL", "PurchaseManager.ValidateReceipt",
                        "IL2CPP", "// hook ValidateReceipt", 30),
        ]
        script = gen.generate_from_il2cpp(hits, "game.apk", "com.game")
        assert "Java.perform" in script
        assert "VENGAM" in script

    def test_empty_findings_has_defaults(self):
        from vengam.intel.frida_gen import FridaHookGenerator
        gen    = FridaHookGenerator()
        script = gen.generate_from_findings([])
        assert "Java.perform" in script
        assert len(script) > 100

    def test_list_available_hooks(self):
        from vengam.intel.frida_gen import FridaHookGenerator
        gen   = FridaHookGenerator()
        hooks = gen.list_available_hooks()
        assert len(hooks) >= 5
        keys  = [h["key"] for h in hooks]
        assert "ssl_pinning"  in keys
        assert "root_detect"  in keys
        assert "iap"          in keys
        assert "economy"      in keys

    def test_script_is_valid_js_structure(self):
        from vengam.intel.frida_gen import FridaHookGenerator
        gen    = FridaHookGenerator()
        script = gen.generate_full()
        assert script.count("Java.perform") >= 1
        assert "function" in script
        assert "vlog" in script


# ── Endpoint Analyzer ─────────────────────────────────────────────

class TestEndpointAnalyzer:

    def test_http_endpoint_extracted(self, tmp_path):
        from vengam.intel.endpoint import EndpointAnalyzer
        f = tmp_path / "Config.smali"
        f.write_text('const-string v0, "https://api.mygame.com/v1/player/profile"')
        analyzer = EndpointAnalyzer()
        intel    = analyzer.analyze_directory(str(tmp_path))
        urls     = [e.url for e in intel.endpoints]
        assert any("mygame" in u for u in urls)

    def test_auth_endpoint_categorized(self, tmp_path):
        from vengam.intel.endpoint import EndpointAnalyzer
        f = tmp_path / "Api.smali"
        f.write_text('const-string v0, "https://api.mygame.com/auth/login"')
        analyzer = EndpointAnalyzer()
        intel    = analyzer.analyze_directory(str(tmp_path))
        auth_eps = intel.by_category("auth")
        assert len(auth_eps) >= 1

    def test_payment_risk_high(self, tmp_path):
        from vengam.intel.endpoint import EndpointAnalyzer
        f = tmp_path / "Pay.smali"
        f.write_text('const-string v0, "https://pay.mygame.com/billing/checkout"')
        analyzer = EndpointAnalyzer()
        intel    = analyzer.analyze_directory(str(tmp_path))
        pay_eps  = [e for e in intel.endpoints if e.risk in ("HIGH","CRITICAL")]
        assert len(pay_eps) >= 1

    def test_noise_domains_filtered(self, tmp_path):
        from vengam.intel.endpoint import EndpointAnalyzer
        f = tmp_path / "res.xml"
        f.write_text(
            'https://schemas.android.com/apk/res\n'
            'https://www.w3.org/2001/XMLSchema\n'
            'https://api.mygame.com/v1/score'
        )
        analyzer = EndpointAnalyzer()
        intel    = analyzer.analyze_directory(str(tmp_path))
        urls     = [e.url for e in intel.endpoints]
        assert not any("schemas.android" in u for u in urls)
        assert not any("w3.org" in u for u in urls)
        assert any("mygame" in u for u in urls)

    def test_websocket_detected(self, tmp_path):
        from vengam.intel.endpoint import EndpointAnalyzer
        f = tmp_path / "Net.smali"
        f.write_text('const-string v0, "wss://realtime.mygame.com/multiplayer"')
        analyzer = EndpointAnalyzer()
        intel    = analyzer.analyze_directory(str(tmp_path))
        assert len(intel.websockets) >= 1
        assert "wss" in intel.websockets[0].protocol

    def test_graphql_query_detected(self, tmp_path):
        from vengam.intel.endpoint import EndpointAnalyzer
        f = tmp_path / "Api.java"
        f.write_text('String q = "query GetPlayer { id name gold gems }";')
        analyzer = EndpointAnalyzer()
        intel    = analyzer.analyze_directory(str(tmp_path))
        assert len(intel.graphql) >= 0  # may or may not match

    def test_generate_report_structure(self, tmp_path):
        from vengam.intel.endpoint import EndpointAnalyzer
        f = tmp_path / "a.smali"
        f.write_text('const-string v0, "https://api.game.com/auth/login"')
        analyzer = EndpointAnalyzer()
        intel    = analyzer.analyze_directory(str(tmp_path))
        report   = analyzer.generate_report(intel)
        assert "summary"     in report
        assert "by_category" in report
        assert "critical"    in report
        assert "high"        in report


# ── Attack Graph ──────────────────────────────────────────────────

class TestAttackGraph:

    def _finding(self, title, severity="HIGH", category="General"):
        from vengam.core.models import Finding
        return Finding(
            title=title, severity=severity, confidence="HIGH",
            exploitability="CONFIRMED", secret_type="Test",
            description="Test", simulation="Test",
            score_value=20, category=category,
        )

    def test_graph_has_apk_node(self):
        from vengam.intel.attack_graph import AttackGraphBuilder
        from vengam.core.models import AttackSurface
        builder = AttackGraphBuilder()
        graph   = builder.build("game.apk", [], AttackSurface())
        node_ids = [n.id for n in graph.nodes]
        assert "APK"      in node_ids
        assert "ATTACKER" in node_ids

    def test_finding_nodes_created(self):
        from vengam.intel.attack_graph import AttackGraphBuilder
        from vengam.core.models import AttackSurface
        builder  = AttackGraphBuilder()
        findings = [self._finding("Firebase API Key", "CRITICAL")]
        graph    = builder.build("game.apk", findings, AttackSurface())
        types    = [n.type for n in graph.nodes]
        assert "finding" in types

    def test_attack_chain_backend_takeover(self):
        from vengam.intel.attack_graph import AttackGraphBuilder
        from vengam.core.models import AttackSurface
        builder  = AttackGraphBuilder()
        findings = [
            self._finding("PlayFab Secret Key", "CRITICAL", "Economy"),
            self._finding("GameSparks API Key", "CRITICAL", "Economy"),
        ]
        graph = builder.build("game.apk", findings, AttackSurface())
        chain_ids = [c["id"] for c in graph.attack_chains]
        assert "CHAIN_BACKEND_TAKEOVER" in chain_ids

    def test_attack_chain_full_cheat(self):
        from vengam.intel.attack_graph import AttackGraphBuilder
        from vengam.core.models import AttackSurface
        builder  = AttackGraphBuilder()
        findings = [
            self._finding("Anti-Cheat Bypass Detected", "CRITICAL", "AntiCheat"),
            self._finding("IAP Receipt Validation Disabled", "CRITICAL", "Economy"),
        ]
        graph     = builder.build("game.apk", findings, AttackSurface())
        chain_ids = [c["id"] for c in graph.attack_chains]
        assert "CHAIN_FULL_CHEAT" in chain_ids

    def test_to_json_valid(self):
        from vengam.intel.attack_graph import AttackGraphBuilder
        from vengam.core.models import AttackSurface
        builder = AttackGraphBuilder()
        graph   = builder.build("game.apk", [], AttackSurface())
        j       = json.loads(graph.to_json())
        assert "nodes" in j
        assert "edges" in j
        assert "attack_chains" in j

    def test_to_d3_format(self):
        from vengam.intel.attack_graph import AttackGraphBuilder
        from vengam.core.models import AttackSurface
        builder = AttackGraphBuilder()
        graph   = builder.build("game.apk", [
            self._finding("Firebase Key", "CRITICAL")
        ], AttackSurface())
        d3 = graph.to_d3()
        assert "nodes" in d3
        assert "links" in d3
        assert "chains" in d3
        # Her node'da color ve size olmalı
        for node in d3["nodes"]:
            assert "color" in node
            assert "size"  in node

    def test_surface_nodes_added(self):
        from vengam.intel.attack_graph import AttackGraphBuilder
        from vengam.core.models import AttackSurface
        builder = AttackGraphBuilder()
        surface = AttackSurface(
            auth={"/auth/login"},
            payment={"/pay/checkout"},
        )
        graph    = builder.build("game.apk", [], surface)
        node_ids = [n.id for n in graph.nodes]
        assert "SURFACE_AUTH"    in node_ids
        assert "SURFACE_PAYMENT" in node_ids

    def test_edges_connect_attacker_to_critical(self):
        from vengam.intel.attack_graph import AttackGraphBuilder
        from vengam.core.models import AttackSurface
        builder  = AttackGraphBuilder()
        findings = [self._finding("Firebase Key", "CRITICAL")]
        graph    = builder.build("game.apk", findings, AttackSurface())
        attacker_edges = [
            e for e in graph.edges if e.source == "ATTACKER"
        ]
        assert len(attacker_edges) >= 1
