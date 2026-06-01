"""
VENGAM — Sprint 12 Unit Tests
UI v2 entegrasyonu + Intel router + Auth entegrasyonu
Run: pytest tests/unit/test_sprint12.py -v
"""
import json
import pytest
from pathlib import Path


# ── JWT Auth entegrasyon testleri ────────────────────────────────

class TestAuthIntegration:

    def test_full_login_flow(self, tmp_path):
        import os
        os.environ["VENGAM_USERS_FILE"] = str(tmp_path / "users.json")
        from auth import jwt_auth
        import importlib
        importlib.reload(jwt_auth)

        jwt_auth.create_user("alice", "password123", "analyst")
        pair = jwt_auth.authenticate_user("alice", "password123")
        assert pair is not None

        data = jwt_auth.verify_access_token(pair.access_token)
        assert data is not None
        assert data.username == "alice"
        assert data.role     == "analyst"

    def test_admin_role_flow(self, tmp_path):
        import os
        os.environ["VENGAM_USERS_FILE"] = str(tmp_path / "admin_users.json")
        from auth import jwt_auth
        import importlib
        importlib.reload(jwt_auth)

        jwt_auth.create_user("admin", "adminpass", "admin")
        pair = jwt_auth.authenticate_user("admin", "adminpass")
        assert pair is not None

        data = jwt_auth.verify_access_token(pair.access_token)
        assert data.role == "admin"

    def test_logout_invalidates_token(self, tmp_path):
        import os
        os.environ["VENGAM_USERS_FILE"] = str(tmp_path / "logout_users.json")
        from auth import jwt_auth
        import importlib
        importlib.reload(jwt_auth)

        jwt_auth.create_user("bob", "bobpass", "analyst")
        pair = jwt_auth.authenticate_user("bob", "bobpass")
        assert jwt_auth.verify_access_token(pair.access_token) is not None

        jwt_auth.revoke_token(pair.access_token)
        assert jwt_auth.verify_access_token(pair.access_token) is None

    def test_wrong_password_rejected(self, tmp_path):
        import os
        os.environ["VENGAM_USERS_FILE"] = str(tmp_path / "wrong_users.json")
        from auth import jwt_auth
        import importlib
        importlib.reload(jwt_auth)

        jwt_auth.create_user("carol", "correctpass", "analyst")
        pair = jwt_auth.authenticate_user("carol", "wrongpass")
        assert pair is None

    def test_nonexistent_user_rejected(self, tmp_path):
        import os
        os.environ["VENGAM_USERS_FILE"] = str(tmp_path / "nouser.json")
        from auth import jwt_auth
        import importlib
        importlib.reload(jwt_auth)

        pair = jwt_auth.authenticate_user("nobody", "anypass")
        assert pair is None


# ── Intel pipeline testleri ───────────────────────────────────────

class TestIntelPipeline:

    def _finding(self, title, severity="HIGH", category="General"):
        from vengam.core.models import Finding
        return Finding(
            title=title, severity=severity, confidence="HIGH",
            exploitability="CONFIRMED", secret_type="Test",
            description="Test", simulation="Test",
            score_value=20, category=category,
        )

    def test_attack_graph_to_d3_complete(self):
        from vengam.intel.attack_graph import AttackGraphBuilder
        from vengam.core.models import AttackSurface
        builder = AttackGraphBuilder()
        graph   = builder.build(
            "game.apk",
            [
                self._finding("Firebase Key", "CRITICAL"),
                self._finding("Anti-Cheat Bypass", "CRITICAL", "AntiCheat"),
                self._finding("IAP Bypass", "CRITICAL", "Economy"),
            ],
            AttackSurface(auth={"/auth/login"}, payment={"/pay/checkout"}),
        )
        d3 = graph.to_d3()
        assert len(d3["nodes"]) >= 5
        assert len(d3["links"]) >= 4
        assert len(d3["chains"]) >= 1
        for node in d3["nodes"]:
            assert "id"    in node
            assert "color" in node
            assert "size"  in node

    def test_frida_script_from_findings(self):
        from vengam.intel.frida_gen import FridaHookGenerator
        gen      = FridaHookGenerator()
        findings = [
            self._finding("SSL Certificate Pinning Disabled"),
            self._finding("IAP Receipt Validation Disabled", "CRITICAL", "Economy"),
            self._finding("Anti-Cheat Bypass", "CRITICAL", "AntiCheat"),
        ]
        script = gen.generate_from_findings(findings, "game.apk", "com.game.app")
        assert "Java.perform"       in script
        assert "CertificatePinner"  in script
        assert "verifyPurchase"     in script or "receipt" in script.lower()
        assert len(script.splitlines()) > 20

    def test_endpoint_intel_pipeline(self, tmp_path):
        from vengam.intel.endpoint import EndpointAnalyzer
        (tmp_path / "Api.smali").write_text(
            'const-string v0, "https://api.game.com/auth/login"\n'
            'const-string v1, "https://api.game.com/pay/checkout"\n'
            'const-string v2, "wss://rt.game.com/multiplayer"\n'
        )
        analyzer = EndpointAnalyzer()
        intel    = analyzer.analyze_directory(str(tmp_path))
        report   = analyzer.generate_report(intel)
        assert intel.total_unique >= 2
        assert len(intel.websockets) >= 1
        assert "summary" in report
        assert report["summary"]["total_endpoints"] >= 2

    def test_attack_chain_combo_detected(self):
        from vengam.intel.attack_graph import AttackGraphBuilder
        from vengam.core.models import AttackSurface
        builder  = AttackGraphBuilder()
        findings = [
            self._finding("SSL Pinning Disabled", "HIGH"),
            self._finding("JWT Token Exposed", "HIGH"),
        ]
        graph     = builder.build("game.apk", findings, AttackSurface())
        chain_ids = [c["id"] for c in graph.attack_chains]
        assert "CHAIN_MITM_SESSION" in chain_ids

    def test_il2cpp_security_hit_score(self):
        from vengam.intel.il2cpp_deep import _match_security
        hits = [
            _match_security("AdminPanel",      "GameManager"),
            _match_security("DetectFrida",     "SecurityManager"),
            _match_security("ValidateReceipt", "PurchaseHandler"),
        ]
        for hit in hits:
            assert hit is not None
            assert hit.score >= 10
            assert hit.severity in {"CRITICAL","HIGH","MEDIUM"}

    def test_plugin_loader_integration(self, tmp_path):
        from vengam.plugins.loader import PluginLoader
        code = '''
from vengam.plugins.base import ScannerPlugin, PluginMeta
from vengam.core.models import Finding

class IntegrationScanner(ScannerPlugin):
    @property
    def meta(self):
        return PluginMeta(
            id="integration.test_scanner",
            name="Integration Scanner", version="1.0",
            author="Test", description="Integration test",
            plugin_type="scanner",
        )
    def scan(self, d, p="android"):
        return [Finding(
            title="Integration Test Finding",
            severity="HIGH", confidence="HIGH",
            exploitability="CONFIRMED",
            secret_type="Test", description="Test",
            simulation="Test", score_value=20,
        )]
'''
        (tmp_path / "int_scanner.py").write_text(code)
        loader  = PluginLoader()
        count   = loader.load_directory(str(tmp_path))
        assert count >= 1
        results = loader.run_scanners(str(tmp_path))
        assert len(results) >= 1
        assert results[0].success
        assert results[0].findings[0].title == "Integration Test Finding"


# ── Full scan pipeline ────────────────────────────────────────────

class TestFullScanPipeline:

    def test_scan_to_report_pipeline(self, tmp_path):
        """Dizin tarama → rapor üretme tam pipeline."""
        from vengam.android.static import scan_directory
        from vengam.reports import text_report, json_report, sarif_report

        smali = tmp_path / "smali" / "com" / "game"
        smali.mkdir(parents=True)
        (smali / "Config.smali").write_text(
            'const-string v0, "AIzaSyABCDEF1234567890abcdefghijk-XY"\n'
        )

        result   = scan_directory(str(tmp_path), "TestGame.apk")
        out_dir  = tmp_path / "reports"
        out_dir.mkdir()

        txt_path  = str(out_dir / "report.txt")
        json_path = str(out_dir / "report.json")
        sar_path  = str(out_dir / "report.sarif")

        text_report.generate(result,  txt_path)
        json_report.generate(result,  json_path)
        sarif_report.generate(result, sar_path)

        assert (out_dir / "report.txt").exists()
        assert (out_dir / "report.json").exists()
        assert (out_dir / "report.sarif").exists()

        data = json.loads((out_dir / "report.json").read_text())
        assert data["apk_name"] == "TestGame.apk"
        assert "findings"       in data
        assert "engine_stats"   in data

    def test_scan_to_attack_graph_pipeline(self, tmp_path):
        """Tarama → attack graph pipeline."""
        from vengam.android.static import scan_directory
        from vengam.intel.attack_graph import AttackGraphBuilder

        smali = tmp_path / "smali" / "com" / "game"
        smali.mkdir(parents=True)
        (smali / "Economy.smali").write_text(
            'const-string v0, "playfab_secret_key=ABCDEFGHIJKLMNOPQRST12345678"\n'
        )

        result  = scan_directory(str(tmp_path), "TestGame.apk")
        builder = AttackGraphBuilder()
        graph   = builder.build(
            result.apk_name,
            result.findings,
            result.attack_surface,
        )

        assert len(graph.nodes) >= 2
        d3 = graph.to_d3()
        assert "nodes" in d3
        assert "links" in d3

    def test_scan_to_frida_pipeline(self, tmp_path):
        """Tarama → Frida script pipeline."""
        from vengam.android.static import scan_directory
        from vengam.intel.frida_gen import FridaHookGenerator

        smali = tmp_path / "smali" / "com" / "game"
        smali.mkdir(parents=True)
        (smali / "Security.smali").write_text(
            'const-string v0, "ssl_pinning_enabled"\n'
            'invoke-virtual {v0}, Lcom/security/SSLPin;->disable()V\n'
        )

        result = scan_directory(str(tmp_path), "TestGame.apk")
        gen    = FridaHookGenerator()
        script = gen.generate_from_findings(
            result.findings, result.apk_name
        )

        assert "Java.perform" in script
        assert len(script) > 100
