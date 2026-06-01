"""
VENGAM — Örnek Community Scanner Plugin
Bu dosyayı kopyalayarak kendi plugin'inizi yazabilirsiniz.

Kurulum:
  1. Bu dosyayı vengam/plugins/community/ klasörüne koyun
  2. VENGAM otomatik keşfeder ve yükler
"""
from __future__ import annotations
import re
from pathlib import Path
from vengam.plugins.base import ScannerPlugin, PluginMeta
from vengam.core.models import Finding, FindingLocation


class HardcodedAdminPasswordScanner(ScannerPlugin):
    """
    Admin şifrelerini ve backdoor hesaplarını tespit eder.
    """

    @property
    def meta(self) -> PluginMeta:
        return PluginMeta(
            id="community.hardcoded_admin",
            name="Hardcoded Admin Password Scanner",
            version="1.0.0",
            author="VENGAM Community",
            description="Admin/backdoor şifrelerini tespit eder",
            plugin_type="scanner",
            platform="android",
            tags=["credentials", "admin", "backdoor"],
        )

    # Tespit pattern'leri
    PATTERNS = [
        (re.compile(
            r'(?i)(admin|administrator|root|superuser)[_\s]*(password|pass|pwd|secret)\s*[=:]\s*["\'][^"\']{4,}["\']',
            re.IGNORECASE
        ), "CRITICAL", 35),
        (re.compile(
            r'(?i)(backdoor|master[_\s]?key|skeleton[_\s]?key|god[_\s]?mode[_\s]?password)',
            re.IGNORECASE
        ), "CRITICAL", 40),
        (re.compile(
            r'(?i)(default[_\s]?password|hardcoded[_\s]?password)\s*[=:]\s*["\'][^"\']{4,}["\']',
            re.IGNORECASE
        ), "HIGH", 25),
    ]

    # FP'leri önlemek için dışla
    EXCLUDE_PATHS = [
        "androidx", "com/google", "test", "sample",
        "BuildConfig", "R.smali",
    ]

    SCAN_EXTS = {".smali", ".java", ".kt", ".xml", ".json", ".properties"}

    def scan(self, decompiled_dir: str, platform: str = "android") -> list[Finding]:
        findings = []
        seen_titles: set[str] = set()
        base = Path(decompiled_dir)

        for filepath in base.rglob("*"):
            if not filepath.is_file():
                continue
            if filepath.suffix.lower() not in self.SCAN_EXTS:
                continue

            rel = str(filepath.relative_to(base)).replace("\\", "/").lower()
            if any(ex in rel for ex in self.EXCLUDE_PATHS):
                continue

            try:
                lines = filepath.read_text(
                    encoding="utf-8", errors="ignore"
                ).splitlines()
            except OSError:
                continue

            for line_no, line in enumerate(lines, 1):
                for pattern, severity, score in self.PATTERNS:
                    m = pattern.search(line)
                    if not m:
                        continue

                    matched = m.group(0)[:60]
                    title   = "Hardcoded Admin Credential"

                    if title in seen_titles:
                        # Mevcut bulguya lokasyon ekle
                        for f in findings:
                            if f.title == title:
                                if len(f.locations) < 5:
                                    f.locations.append(FindingLocation(
                                        file=str(filepath.relative_to(base)),
                                        line=line_no,
                                        snippet=line.strip()[:100],
                                        redacted_match=matched[:20]+"***",
                                    ))
                                break
                    else:
                        seen_titles.add(title)
                        findings.append(Finding(
                            title=title,
                            severity=severity,
                            confidence="HIGH",
                            exploitability="CONFIRMED",
                            secret_type="Admin Credential",
                            description=(
                                "Admin veya backdoor şifresi kaynak kodda "
                                "hardcoded olarak tespit edildi."
                            ),
                            simulation=(
                                "Saldırgan admin şifresini kullanarak "
                                "tüm sistemde yetkisiz erişim sağlar."
                            ),
                            score_value=score,
                            category="General",
                            triage_note=(
                                "Tüm admin şifreleri koddan kaldırılmalı. "
                                "Güvenli bir secrets manager kullanın."
                            ),
                            cwe_id="CWE-798",
                            owasp_ref="M9: Insecure Data Storage",
                            locations=[FindingLocation(
                                file=str(filepath.relative_to(base)),
                                line=line_no,
                                snippet=line.strip()[:100],
                                redacted_match=matched[:20]+"***",
                            )],
                        ))
                    break  # Satır başına bir pattern yeterli

        return findings
