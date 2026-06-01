"""
VENGAM Auditor — iOS Swift / ObjC String Pattern Scanner
Runs all VENGAM patterns against strings extracted from a Mach-O binary.
"""
from __future__ import annotations
import re
from vengam.core.fp_filter import FalsePositiveFilter
from vengam.core.models import FindingLocation
from vengam.patterns.loader import COMPILED_PATTERNS
from vengam.utils.crypto import redact_secret
from vengam.utils.entropy import shannon_entropy, is_alphabet_string, classify_high_entropy_string
from vengam.utils.logger import log
from vengam.config import MAX_LOCATIONS_PER_FINDING

_CTX_RE = re.compile(
    r"\b(key|secret|token|auth|pass|bearer|api|aws|cred|password|jwt|credential|encrypt)\b",
    re.IGNORECASE,
)


def scan_strings(
    strings: list[str],
    binary_name: str,
    severity_filter: set[str] | None = None,
    category_filter: set[str] | None = None,
) -> dict[str, dict]:
    """
    Run all VENGAM patterns against a list of extracted binary strings.
    Returns findings_map: {title → raw_finding_dict with locations list}.
    """
    fp_filter    = FalsePositiveFilter()
    findings_map: dict[str, dict] = {}
    fp_count     = 0

    for line_no, raw_string in enumerate(strings, 1):
        s = raw_string.strip()
        if not s:
            continue

        # ── Pattern matching ──────────────────────────────────────
        for pat in COMPILED_PATTERNS:
            m = pat["_re"].search(s)
            if not m:
                continue

            is_fp, reason = fp_filter.check(
                s, s, binary_name,
                pattern_title=pat["title"],
            )
            if is_fp:
                fp_count += 1
                continue

            sev = pat["severity"]
            cat = pat.get("category", "General")
            if severity_filter and sev not in severity_filter:
                continue
            if category_filter and cat not in category_filter:
                continue

            title = pat["title"]
            if title not in findings_map:
                findings_map[title] = {**pat, "locations": []}

            if len(findings_map[title]["locations"]) < MAX_LOCATIONS_PER_FINDING:
                raw_match = (
                    m.group(m.lastindex) if m.lastindex else m.group(0)
                ) or m.group(0)
                findings_map[title]["locations"].append(
                    FindingLocation(
                        file=f"[binary] {binary_name}",
                        line=line_no,
                        snippet=s[:120],
                        redacted_match=redact_secret(raw_match) if len(raw_match) > 6 else "***",
                    )
                )

        # ── Entropy detection ─────────────────────────────────────
        if is_alphabet_string(s):
            fp_count += 1
            continue

        is_fp, _ = fp_filter.check(s, s, binary_name)
        if is_fp:
            fp_count += 1
            continue

        ent     = shannon_entropy(s)
        has_ctx = bool(_CTX_RE.search(s))

        if ent >= 5.0 and has_ctx:
            s_type, s_sim = classify_high_entropy_string(s)
            title  = f"Exposed {s_type}"
            sev, conf, exp, score = "CRITICAL", "HIGH", "LIKELY", 25
        elif ent >= 5.2:
            title  = "Unclassified High-Entropy Asset (Binary)"
            s_type = "Obfuscated Data"
            s_sim  = "Attacker reverse-engineers binary string to determine if it acts as seed or endpoint."
            sev, conf, exp, score = "MEDIUM", "LOW", "THEORETICAL", 5
        else:
            continue

        if severity_filter and sev not in severity_filter:
            continue

        if title not in findings_map:
            findings_map[title] = {
                "title": title, "severity": sev, "confidence": conf,
                "exploitability": exp, "secret_type": s_type,
                "description": "High Shannon entropy string extracted from iOS binary.",
                "simulation": s_sim, "score_value": score,
                "cwe_id": "CWE-798", "owasp_ref": "M9: Insecure Data Storage",
                "category": "General",
                "triage_note": "Verify this is not a Base64 alphabet, UUID, or SDK constant.",
                "locations": [],
            }
        if len(findings_map[title]["locations"]) < MAX_LOCATIONS_PER_FINDING:
            findings_map[title]["locations"].append(
                FindingLocation(
                    file=f"[binary] {binary_name}",
                    line=line_no,
                    snippet=s[:120],
                    redacted_match=redact_secret(s),
                )
            )

    log.info(
        f"Binary string scan: {len(strings)} strings | "
        f"{len(findings_map)} pattern findings | "
        f"{fp_count} FP suppressed"
    )
    return findings_map
