"""
VENGAM — Enterprise: Multi-Tenant Support
Her organizasyon kendi izole scan ortamına sahip olur.
Kullanıcılar sadece kendi organizasyonlarının scan'larını görebilir.
"""
from __future__ import annotations
import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from vengam.utils.logger import log

ORGS_FILE = Path(os.environ.get("VENGAM_ORGS_FILE", "data/organizations.json"))


@dataclass
class Organization:
    id:           str
    name:         str
    slug:         str           # URL-safe kısa isim
    created_at:   str
    plan:         str = "pro"   # free | pro | enterprise
    max_users:    int = 10
    max_scans_pm: int = 100     # Aylık maksimum scan
    api_key:      str = ""
    members:      list[str] = field(default_factory=list)  # username listesi
    settings:     dict = field(default_factory=dict)

    @property
    def is_enterprise(self) -> bool:
        return self.plan == "enterprise"


def _load_orgs() -> dict[str, dict]:
    if not ORGS_FILE.exists():
        return {}
    try:
        return json.loads(ORGS_FILE.read_text())
    except Exception:
        return {}

def _save_orgs(orgs: dict) -> None:
    ORGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    ORGS_FILE.write_text(json.dumps(orgs, indent=2))


def create_organization(name: str, slug: str, plan: str = "pro") -> Organization:
    orgs = _load_orgs()
    if any(o.get("slug") == slug for o in orgs.values()):
        raise ValueError(f"Slug '{slug}' zaten kullanımda")

    import secrets
    org = Organization(
        id=str(uuid.uuid4()),
        name=name, slug=slug,
        created_at=datetime.now(timezone.utc).isoformat(),
        plan=plan,
        api_key=secrets.token_urlsafe(32),
    )
    orgs[org.id] = {
        "id": org.id, "name": org.name, "slug": org.slug,
        "created_at": org.created_at, "plan": org.plan,
        "max_users": org.max_users, "max_scans_pm": org.max_scans_pm,
        "api_key": org.api_key, "members": [], "settings": {},
    }
    _save_orgs(orgs)
    log.info(f"Organizasyon oluşturuldu: {name} ({slug})")
    return org


def get_organization(org_id: str) -> Organization | None:
    orgs = _load_orgs()
    data = orgs.get(org_id)
    if not data:
        return None
    return Organization(**{k: v for k, v in data.items()
                          if k in Organization.__dataclass_fields__})


def get_org_by_slug(slug: str) -> Organization | None:
    orgs = _load_orgs()
    for data in orgs.values():
        if data.get("slug") == slug:
            return Organization(**{k: v for k, v in data.items()
                                   if k in Organization.__dataclass_fields__})
    return None


def add_member(org_id: str, username: str) -> bool:
    orgs = _load_orgs()
    if org_id not in orgs:
        return False
    if username not in orgs[org_id]["members"]:
        orgs[org_id]["members"].append(username)
        _save_orgs(orgs)
    return True


def is_member(org_id: str, username: str) -> bool:
    orgs = _load_orgs()
    org  = orgs.get(org_id, {})
    return username in org.get("members", [])


def validate_api_key(api_key: str) -> Organization | None:
    """API key ile organizasyon doğrula."""
    orgs = _load_orgs()
    for data in orgs.values():
        if data.get("api_key") == api_key:
            return Organization(**{k: v for k, v in data.items()
                                   if k in Organization.__dataclass_fields__})
    return None


def list_organizations() -> list[Organization]:
    orgs = _load_orgs()
    return [
        Organization(**{k: v for k, v in data.items()
                        if k in Organization.__dataclass_fields__})
        for data in orgs.values()
    ]
