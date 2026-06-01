"""
VENGAM — Sprint 13 Unit Tests
Enterprise: Multi-Tenant + Audit Log
Run: pytest tests/unit/test_sprint13.py -v
"""
import json
import os
import tempfile
from pathlib import Path
import pytest


# ── Multi-Tenant ──────────────────────────────────────────────────

class TestMultiTenant:

    def _setup(self, tmp_path: Path):
        os.environ["VENGAM_ORGS_FILE"] = str(tmp_path / "orgs.json")
        from vengam.enterprise import multi_tenant
        import importlib
        importlib.reload(multi_tenant)
        return multi_tenant

    def test_create_organization(self, tmp_path):
        mt  = self._setup(tmp_path)
        org = mt.create_organization("Studio Alpha", "studio-alpha", "pro")
        assert org.id
        assert org.name    == "Studio Alpha"
        assert org.slug    == "studio-alpha"
        assert org.plan    == "pro"
        assert org.api_key != ""

    def test_duplicate_slug_raises(self, tmp_path):
        mt = self._setup(tmp_path)
        mt.create_organization("Studio A", "same-slug", "pro")
        with pytest.raises(ValueError):
            mt.create_organization("Studio B", "same-slug", "pro")

    def test_get_organization_by_id(self, tmp_path):
        mt  = self._setup(tmp_path)
        org = mt.create_organization("Game Dev", "game-dev", "enterprise")
        got = mt.get_organization(org.id)
        assert got is not None
        assert got.name == "Game Dev"
        assert got.is_enterprise

    def test_get_organization_by_slug(self, tmp_path):
        mt  = self._setup(tmp_path)
        org = mt.create_organization("Mobile Studio", "mobile-studio", "pro")
        got = mt.get_org_by_slug("mobile-studio")
        assert got is not None
        assert got.id == org.id

    def test_get_nonexistent_org_returns_none(self, tmp_path):
        mt  = self._setup(tmp_path)
        got = mt.get_organization("nonexistent-id")
        assert got is None

    def test_add_member_to_org(self, tmp_path):
        mt  = self._setup(tmp_path)
        org = mt.create_organization("Team X", "team-x", "pro")
        result = mt.add_member(org.id, "alice")
        assert result == True
        assert mt.is_member(org.id, "alice")

    def test_is_not_member(self, tmp_path):
        mt  = self._setup(tmp_path)
        org = mt.create_organization("Team Y", "team-y", "pro")
        assert not mt.is_member(org.id, "nobody")

    def test_add_member_nonexistent_org(self, tmp_path):
        mt     = self._setup(tmp_path)
        result = mt.add_member("fake-id", "alice")
        assert result == False

    def test_validate_api_key(self, tmp_path):
        mt  = self._setup(tmp_path)
        org = mt.create_organization("Key Test", "key-test", "pro")
        got = mt.validate_api_key(org.api_key)
        assert got is not None
        assert got.id == org.id

    def test_validate_invalid_api_key(self, tmp_path):
        mt  = self._setup(tmp_path)
        got = mt.validate_api_key("invalid-key-xyz")
        assert got is None

    def test_list_organizations(self, tmp_path):
        mt = self._setup(tmp_path)
        mt.create_organization("Org 1", "org-1", "free")
        mt.create_organization("Org 2", "org-2", "pro")
        mt.create_organization("Org 3", "org-3", "enterprise")
        orgs = mt.list_organizations()
        assert len(orgs) == 3

    def test_organization_plans(self, tmp_path):
        mt  = self._setup(tmp_path)
        org = mt.create_organization("Free Studio", "free-studio", "free")
        assert not org.is_enterprise
        org2 = mt.create_organization("Enterprise Co", "ent-co", "enterprise")
        assert org2.is_enterprise

    def test_duplicate_member_not_added_twice(self, tmp_path):
        mt  = self._setup(tmp_path)
        org = mt.create_organization("Team Z", "team-z", "pro")
        mt.add_member(org.id, "bob")
        mt.add_member(org.id, "bob")  # İkinci kez ekle
        got = mt.get_organization(org.id)
        assert got.members.count("bob") == 1


# ── Audit Log ─────────────────────────────────────────────────────

class TestAuditLog:

    def _setup(self, tmp_path: Path):
        os.environ["VENGAM_AUDIT_LOG"] = str(tmp_path / "audit.jsonl")
        from vengam.enterprise import audit_log
        import importlib
        importlib.reload(audit_log)
        return audit_log

    def test_write_and_read_entry(self, tmp_path):
        al = self._setup(tmp_path)
        al.write_audit("alice", "LOGIN", resource="session-1", success=True)
        entries = al.read_audit(actor="alice")
        assert len(entries) >= 1
        assert entries[0]["actor"]  == "alice"
        assert entries[0]["action"] == "LOGIN"

    def test_write_multiple_entries(self, tmp_path):
        al = self._setup(tmp_path)
        al.write_audit("alice", "SCAN_STARTED",  resource="scan-1")
        al.write_audit("alice", "SCAN_COMPLETE", resource="scan-1")
        al.write_audit("bob",   "LOGIN",         resource="")
        entries = al.read_audit()
        assert len(entries) >= 3

    def test_filter_by_actor(self, tmp_path):
        al = self._setup(tmp_path)
        al.write_audit("alice", "LOGIN")
        al.write_audit("bob",   "LOGIN")
        al.write_audit("alice", "SCAN_STARTED")
        alice_entries = al.read_audit(actor="alice")
        assert all(e["actor"] == "alice" for e in alice_entries)
        assert len(alice_entries) == 2

    def test_filter_by_action(self, tmp_path):
        al = self._setup(tmp_path)
        al.write_audit("alice", "LOGIN")
        al.write_audit("alice", "SCAN_STARTED")
        al.write_audit("bob",   "LOGIN")
        logins = al.read_audit(action="LOGIN")
        assert all(e["action"] == "LOGIN" for e in logins)
        assert len(logins) == 2

    def test_failed_login_recorded(self, tmp_path):
        al = self._setup(tmp_path)
        al.write_audit("hacker", "LOGIN_FAILED",
                       success=False, detail="Wrong password")
        entries = al.read_audit(actor="hacker")
        assert len(entries) == 1
        assert not entries[0]["success"]
        assert "Wrong password" in entries[0]["detail"]

    def test_empty_log_returns_empty_list(self, tmp_path):
        al      = self._setup(tmp_path)
        entries = al.read_audit()
        assert entries == []

    def test_limit_works(self, tmp_path):
        al = self._setup(tmp_path)
        for i in range(20):
            al.write_audit("alice", "SCAN_STARTED", resource=f"scan-{i}")
        entries = al.read_audit(limit=5)
        assert len(entries) == 5

    def test_scan_audit_trail(self, tmp_path):
        al = self._setup(tmp_path)
        al.write_audit("alice", "SCAN_STARTED",  resource="scan-abc")
        al.write_audit("alice", "SCAN_COMPLETE", resource="scan-abc")
        al.write_audit("bob",   "REPORT_EXPORT", resource="scan-abc")
        trail = al.get_scan_audit_trail("scan-abc")
        assert len(trail) == 3

    def test_entry_has_timestamp(self, tmp_path):
        al = self._setup(tmp_path)
        al.write_audit("alice", "LOGIN")
        entries = al.read_audit(actor="alice")
        assert "ts" in entries[0]
        assert entries[0]["ts"]  # Boş olmamalı

    def test_org_filter(self, tmp_path):
        al = self._setup(tmp_path)
        al.write_audit("alice", "SCAN_STARTED", org_id="org-1")
        al.write_audit("bob",   "SCAN_STARTED", org_id="org-2")
        org1_entries = al.read_audit(org_id="org-1")
        assert all(e["org_id"] == "org-1" for e in org1_entries)


# ── Enterprise entegrasyon ────────────────────────────────────────

class TestEnterpriseIntegration:

    def test_full_org_workflow(self, tmp_path):
        """Organizasyon oluştur → üye ekle → audit log yaz."""
        os.environ["VENGAM_ORGS_FILE"]  = str(tmp_path / "orgs.json")
        os.environ["VENGAM_AUDIT_LOG"]  = str(tmp_path / "audit.jsonl")

        from vengam.enterprise import multi_tenant, audit_log
        import importlib
        importlib.reload(multi_tenant)
        importlib.reload(audit_log)

        # 1. Org oluştur
        org = multi_tenant.create_organization("TestCo", "testco", "enterprise")
        audit_log.write_audit("admin", "CONFIG_CHANGE",
                              resource=org.id, org_id=org.id,
                              detail="Created org TestCo")

        # 2. Üye ekle
        multi_tenant.add_member(org.id, "developer1")
        audit_log.write_audit("admin", "CONFIG_CHANGE",
                              resource=org.id, org_id=org.id,
                              detail="Added developer1")

        # 3. Scan simüle et
        audit_log.write_audit("developer1", "SCAN_STARTED",
                              resource="scan-xyz", org_id=org.id)
        audit_log.write_audit("developer1", "SCAN_COMPLETE",
                              resource="scan-xyz", org_id=org.id)

        # 4. Doğrula
        assert multi_tenant.is_member(org.id, "developer1")
        entries = audit_log.read_audit(org_id=org.id)
        assert len(entries) == 4

    def test_api_key_authentication_flow(self, tmp_path):
        """API key ile organizasyon doğrulama."""
        os.environ["VENGAM_ORGS_FILE"] = str(tmp_path / "api_orgs.json")

        from vengam.enterprise import multi_tenant
        import importlib
        importlib.reload(multi_tenant)

        org = multi_tenant.create_organization("APIOrg", "api-org", "pro")

        # Doğru key
        validated = multi_tenant.validate_api_key(org.api_key)
        assert validated is not None
        assert validated.id == org.id

        # Yanlış key
        assert multi_tenant.validate_api_key("wrong-key") is None

    def test_multiple_orgs_isolation(self, tmp_path):
        """İki organizasyon birbirinin üyelerini göremez."""
        os.environ["VENGAM_ORGS_FILE"] = str(tmp_path / "iso_orgs.json")

        from vengam.enterprise import multi_tenant
        import importlib
        importlib.reload(multi_tenant)

        org1 = multi_tenant.create_organization("Org One", "org-one", "pro")
        org2 = multi_tenant.create_organization("Org Two", "org-two", "pro")

        multi_tenant.add_member(org1.id, "alice")
        multi_tenant.add_member(org2.id, "bob")

        assert     multi_tenant.is_member(org1.id, "alice")
        assert not multi_tenant.is_member(org1.id, "bob")
        assert     multi_tenant.is_member(org2.id, "bob")
        assert not multi_tenant.is_member(org2.id, "alice")
