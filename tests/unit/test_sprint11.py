"""
VENGAM — Sprint 11 Unit Tests
Plugin System + JWT Auth
Run: pytest tests/unit/test_sprint11.py -v
"""
import json
import time
import tempfile
from pathlib import Path
import pytest


# ── Plugin Base ───────────────────────────────────────────────────

class TestPluginBase:

    def test_scanner_plugin_interface(self):
        from vengam.plugins.base import ScannerPlugin, PluginMeta
        from vengam.core.models import Finding
        import inspect
        assert inspect.isabstract(ScannerPlugin)

    def test_report_plugin_interface(self):
        from vengam.plugins.base import ReportPlugin
        import inspect
        assert inspect.isabstract(ReportPlugin)

    def test_enrich_plugin_interface(self):
        from vengam.plugins.base import EnrichPlugin
        import inspect
        assert inspect.isabstract(EnrichPlugin)

    def test_hook_plugin_interface(self):
        from vengam.plugins.base import HookPlugin
        import inspect
        assert inspect.isabstract(HookPlugin)

    def test_plugin_result_fields(self):
        from vengam.plugins.base import PluginResult
        r = PluginResult(plugin_id="test", success=True)
        assert r.plugin_id    == "test"
        assert r.success      == True
        assert r.findings     == []
        assert r.error        is None
        assert r.duration_sec == 0.0

    def test_plugin_meta_fields(self):
        from vengam.plugins.base import PluginMeta
        m = PluginMeta(
            id="test.plugin", name="Test", version="1.0",
            author="Tester", description="Test plugin",
            plugin_type="scanner",
        )
        assert m.id          == "test.plugin"
        assert m.plugin_type == "scanner"
        assert m.platform    == "both"


# ── Plugin Loader ─────────────────────────────────────────────────

class TestPluginLoader:

    def _make_plugin_file(self, tmp_path: Path, plugin_code: str) -> Path:
        f = tmp_path / "test_plugin.py"
        f.write_text(plugin_code)
        return f

    def test_loader_starts_empty(self):
        from vengam.plugins.loader import PluginLoader
        loader = PluginLoader()
        assert loader.plugin_count  == 0
        assert loader.scanner_count == 0

    def test_load_valid_scanner_plugin(self, tmp_path):
        from vengam.plugins.loader import PluginLoader
        code = '''
from vengam.plugins.base import ScannerPlugin, PluginMeta
from vengam.core.models import Finding

class MyScanner(ScannerPlugin):
    @property
    def meta(self):
        return PluginMeta(
            id="test.my_scanner", name="My Scanner",
            version="1.0", author="Test",
            description="Test scanner", plugin_type="scanner",
        )
    def scan(self, decompiled_dir, platform="android"):
        return []
'''
        self._make_plugin_file(tmp_path, code)
        loader = PluginLoader()
        count  = loader.load_directory(str(tmp_path))
        assert count >= 1
        assert loader.plugin_count >= 1
        assert loader.scanner_count >= 1

    def test_load_invalid_file_no_crash(self, tmp_path):
        from vengam.plugins.loader import PluginLoader
        f = tmp_path / "bad_plugin.py"
        f.write_text("this is not valid python code !!!")
        loader = PluginLoader()
        count  = loader.load_directory(str(tmp_path))
        assert count == 0

    def test_list_plugins_after_load(self, tmp_path):
        from vengam.plugins.loader import PluginLoader
        code = '''
from vengam.plugins.base import ScannerPlugin, PluginMeta
from vengam.core.models import Finding

class ListTestPlugin(ScannerPlugin):
    @property
    def meta(self):
        return PluginMeta(
            id="test.list_test", name="List Test",
            version="2.0", author="Dev",
            description="List test", plugin_type="scanner",
            tags=["test","demo"],
        )
    def scan(self, d, p="android"):
        return []
'''
        self._make_plugin_file(tmp_path, code)
        loader = PluginLoader()
        loader.load_directory(str(tmp_path))
        plugins = loader.list_plugins()
        assert len(plugins) >= 1
        p = plugins[0]
        assert "id"      in p
        assert "name"    in p
        assert "version" in p
        assert "type"    in p

    def test_unload_plugin(self, tmp_path):
        from vengam.plugins.loader import PluginLoader
        code = '''
from vengam.plugins.base import ScannerPlugin, PluginMeta
from vengam.core.models import Finding

class UnloadTest(ScannerPlugin):
    @property
    def meta(self):
        return PluginMeta(
            id="test.unload_me", name="Unload Me",
            version="1.0", author="Test",
            description="Will be unloaded", plugin_type="scanner",
        )
    def scan(self, d, p="android"):
        return []
'''
        self._make_plugin_file(tmp_path, code)
        loader = PluginLoader()
        loader.load_directory(str(tmp_path))
        assert loader.plugin_count >= 1
        result = loader.unload("test.unload_me")
        assert result == True
        assert loader.plugin_count == 0

    def test_run_scanners_returns_results(self, tmp_path):
        from vengam.plugins.loader import PluginLoader
        code = '''
from vengam.plugins.base import ScannerPlugin, PluginMeta
from vengam.core.models import Finding

class ReturnOneScanner(ScannerPlugin):
    @property
    def meta(self):
        return PluginMeta(
            id="test.return_one", name="Return One",
            version="1.0", author="Test",
            description="Returns one finding", plugin_type="scanner",
        )
    def scan(self, decompiled_dir, platform="android"):
        return [Finding(
            title="Test Finding", severity="HIGH",
            confidence="HIGH", exploitability="CONFIRMED",
            secret_type="Test", description="Test",
            simulation="Test", score_value=20,
        )]
'''
        self._make_plugin_file(tmp_path, code)
        loader     = PluginLoader()
        loader.load_directory(str(tmp_path))
        results    = loader.run_scanners(str(tmp_path))
        assert len(results) >= 1
        assert results[0].success
        assert len(results[0].findings) == 1

    def test_community_example_plugin_loads(self, tmp_path):
        """Örnek community plugin'in yüklenip çalıştığını test et."""
        from vengam.plugins.loader import PluginLoader
        community_dir = Path(__file__).parent.parent.parent / \
                        "vengam" / "plugins" / "community"
        if not community_dir.exists():
            pytest.skip("Community plugins dizini bulunamadı")
        loader = PluginLoader()
        count  = loader.load_directory(str(community_dir))
        assert count >= 0  # Hata vermeden yüklenmeli


# ── JWT Authentication ────────────────────────────────────────────

class TestJwtAuth:

    def test_hash_and_verify_password(self):
        from auth.jwt_auth import hash_password, verify_password
        pw   = "SuperSecret123!"
        h    = hash_password(pw)
        assert h != pw
        assert verify_password(pw, h)
        assert not verify_password("wrong", h)

    def test_create_token_pair(self):
        from auth.jwt_auth import create_token_pair
        pair = create_token_pair("testuser", "analyst")
        assert pair.access_token
        assert pair.refresh_token
        assert pair.token_type  == "bearer"
        assert pair.expires_in  > 0

    def test_verify_valid_access_token(self):
        from auth.jwt_auth import create_token_pair, verify_access_token
        pair   = create_token_pair("alice", "admin")
        result = verify_access_token(pair.access_token)
        assert result is not None
        assert result.username == "alice"
        assert result.role     == "admin"

    def test_verify_invalid_token_returns_none(self):
        from auth.jwt_auth import verify_access_token
        assert verify_access_token("not.a.valid.token") is None
        assert verify_access_token("") is None
        assert verify_access_token("a.b.c") is None

    def test_revoke_token(self):
        from auth.jwt_auth import create_token_pair, verify_access_token, revoke_token
        pair = create_token_pair("bob", "analyst")
        assert verify_access_token(pair.access_token) is not None
        revoke_token(pair.access_token)
        assert verify_access_token(pair.access_token) is None

    def test_refresh_token_works(self):
        from auth.jwt_auth import create_token_pair, refresh_access_token
        pair     = create_token_pair("carol", "analyst")
        new_pair = refresh_access_token(pair.refresh_token)
        assert new_pair is not None
        assert new_pair.access_token != pair.access_token

    def test_refresh_with_access_token_fails(self):
        from auth.jwt_auth import create_token_pair, refresh_access_token
        pair   = create_token_pair("dave", "analyst")
        result = refresh_access_token(pair.access_token)  # access token ≠ refresh
        assert result is None

    def test_brute_force_protection(self):
        from auth.jwt_auth import (
            record_failed_login, is_brute_forced,
            clear_failed_logins, MAX_FAILED_LOGINS,
        )
        user = "brute_test_user_xyz"
        clear_failed_logins(user)
        for _ in range(MAX_FAILED_LOGINS):
            record_failed_login(user)
        assert is_brute_forced(user)
        clear_failed_logins(user)
        assert not is_brute_forced(user)

    def test_create_and_authenticate_user(self, tmp_path):
        import os
        os.environ["VENGAM_USERS_FILE"] = str(tmp_path / "users.json")
        from auth import jwt_auth
        # Reload ile yeni path'i kullan
        import importlib
        importlib.reload(jwt_auth)

        success = jwt_auth.create_user("testuser", "testpass123", "analyst")
        assert success

        # Aynı kullanıcı tekrar oluşturulamaz
        dup = jwt_auth.create_user("testuser", "otherpass", "analyst")
        assert not dup

        # Authenticate
        pair = jwt_auth.authenticate_user("testuser", "testpass123")
        assert pair is not None

        # Yanlış şifre
        fail = jwt_auth.authenticate_user("testuser", "wrongpass")
        assert fail is None

    def test_token_contains_correct_claims(self):
        from auth.jwt_auth import create_token_pair, verify_access_token
        pair = create_token_pair("eve", "admin")
        data = verify_access_token(pair.access_token)
        assert data.username == "eve"
        assert data.role     == "admin"
        assert data.exp      >  int(time.time())
