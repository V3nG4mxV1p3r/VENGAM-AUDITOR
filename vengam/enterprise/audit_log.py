"""
VENGAM — Enterprise: Audit Log
Tüm kritik aksiyonları kaydeder.
GDPR / SOC2 uyumluluk için gerekli.
"""
from __future__ import annotations
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from vengam.utils.logger import log

AUDIT_LOG_FILE = Path(os.environ.get("VENGAM_AUDIT_LOG", "data/audit.jsonl"))


@dataclass
class AuditEntry:
    timestamp:  str
    actor:      str       # username
    action:     str       # LOGIN | SCAN | DELETE | EXPORT | CONFIG_CHANGE
    resource:   str       # scan_id, user_id, etc.
    org_id:     str = ""
    ip_address: str = ""
    success:    bool = True
    detail:     str = ""


AUDIT_ACTIONS = {
    "LOGIN":         "Kullanıcı girişi",
    "LOGOUT":        "Kullanıcı çıkışı",
    "LOGIN_FAILED":  "Başarısız giriş denemesi",
    "SCAN_STARTED":  "Tarama başlatıldı",
    "SCAN_COMPLETE": "Tarama tamamlandı",
    "REPORT_EXPORT": "Rapor dışa aktarıldı",
    "SCAN_DELETED":  "Tarama silindi",
    "USER_CREATED":  "Kullanıcı oluşturuldu",
    "USER_DELETED":  "Kullanıcı silindi",
    "CONFIG_CHANGE": "Yapılandırma değiştirildi",
    "API_KEY_USED":  "API anahtarı kullanıldı",
}


def write_audit(
    actor:      str,
    action:     str,
    resource:   str = "",
    org_id:     str = "",
    ip_address: str = "",
    success:    bool = True,
    detail:     str = "",
) -> None:
    entry = AuditEntry(
        timestamp  = datetime.now(timezone.utc).isoformat(),
        actor      = actor,
        action     = action,
        resource   = resource,
        org_id     = org_id,
        ip_address = ip_address,
        success    = success,
        detail     = detail,
    )
    try:
        AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "ts":       entry.timestamp,
                "actor":    entry.actor,
                "action":   entry.action,
                "resource": entry.resource,
                "org_id":   entry.org_id,
                "ip":       entry.ip_address,
                "success":  entry.success,
                "detail":   entry.detail,
            }) + "\n")
    except Exception as e:
        log.warning(f"Audit log yazma hatası: {e}")


def read_audit(
    actor:    str | None = None,
    action:   str | None = None,
    org_id:   str | None = None,
    limit:    int = 100,
) -> list[dict]:
    if not AUDIT_LOG_FILE.exists():
        return []
    entries = []
    try:
        lines = AUDIT_LOG_FILE.read_text(encoding="utf-8").splitlines()
        for line in reversed(lines):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except Exception:
                continue
            if actor  and entry.get("actor")  != actor:  continue
            if action and entry.get("action") != action: continue
            if org_id and entry.get("org_id") != org_id: continue
            entries.append(entry)
            if len(entries) >= limit:
                break
    except Exception as e:
        log.warning(f"Audit log okuma hatası: {e}")
    return entries


def get_scan_audit_trail(scan_id: str) -> list[dict]:
    """Belirli bir scan'ın audit trail'ini döner."""
    return read_audit(resource=scan_id, limit=50)
