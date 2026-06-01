"""
VENGAM Auditor — Android Static Analysis Engine
Walks decompiled APK directory, runs patterns + entropy detection.
"""
from __future__ import annotations
import datetime
import re
import time
from pathlib import Path
from urllib.parse import urlparse

from vengam.config import (
    SCANNABLE_EXTENSIONS,
    IGNORE_FILE_FRAGMENTS,
    MAX_LOCATIONS_PER_FINDING,
    SNIPPET_MAX_LEN,
)
from vengam.core.models import (
    AttackSurface, EngineStats, Finding, FindingLocation, ScanResult,
)
from vengam.core.fp_filter import FalsePositiveFilter
from vengam.core.risk_engine import calculate_risk
from vengam.patterns.loader import COMPILED_PATTERNS, PATTERN_COUNT
from vengam.utils.crypto import sha256_file, redact_secret
from vengam.utils.entropy import shannon_entropy, is_alphabet_string, classify_high_entropy_string
from vengam.utils.logger import log
from vengam.android.attack_surface import categorise_url, NOISE_DOMAINS, NOISE_EXTENSIONS

# Regex helpers
_URL_RE    = re.compile(r"https?://[a-zA-Z0-9\-\.]+[a-zA-Z0-9_/\-\.=?&]*")
_STRING_RE = re.compile(r"['\"]([^'\"\s]{20,256})['\"]")
_CTX_RE    = re.compile(
    r"\b(key|secret|token|auth|pass|bearer|api|aws|cred|password|jwt|credential|encrypt)\b"
)


def _is_noise_file(filename: str) -> bool:
    return any(frag in filename for frag in IGNORE_FILE_FRAGMENTS)


def scan_directory(
    decompiled_dir: str,
    apk_path: str,
    severity_filter: set[str] | None = None,
    category_filter: set[str] | None = None,
) -> ScanResult:
    """
    Walk a decompiled APK directory and return a ScanResult.

    Parameters
    ----------
    decompiled_dir   : path returned by decompile_apk()
    apk_path         : original .apk path (for SHA-256 and name)
    severity_filter  : if set, only include findings with matching severity
    category_filter  : if set, only include findings with matching category
    """
    log.info("=== PHASE 2: STATIC ANALYSIS ===")
    log.info(f"Patterns loaded: {PATTERN_COUNT}")

    fp_filter     = FalsePositiveFilter()
    findings_map: dict[str, Finding] = {}
    surface       = AttackSurface()
    stats         = EngineStats()
    t0            = time.monotonic()

    for root, _dirs, files in Path(decompiled_dir).walk():
        for fname in files:
            if _is_noise_file(fname):
                continue
            if Path(fname).suffix not in SCANNABLE_EXTENSIONS:
                continue

            filepath = root / fname
            relative = str(filepath.relative_to(decompiled_dir))
            stats.files_scanned += 1

            try:
                lines = filepath.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue

            for line_no, line in enumerate(lines, 1):
                stats.lines_scanned += 1
                stripped = line.strip()

                # ── URL extraction ───────────────────────────────
                for url in _URL_RE.findall(line):
                    parsed = urlparse(url)
                    netloc = parsed.netloc.lower()
                    path   = parsed.path.lower()
                    if any(nd in netloc for nd in NOISE_DOMAINS):
                        continue
                    if any(path.endswith(ext) for ext in NOISE_EXTENSIONS):
                        continue
                    cat = categorise_url(path, netloc)
                    getattr(surface, cat).add(path or netloc)

                # ── Pattern matching ─────────────────────────────
                for pat in COMPILED_PATTERNS:
                    m = pat["_re"].search(line)
                    if not m:
                        continue

                    is_fp, reason = fp_filter.check(
                        stripped, line, fname,
                        pattern_title=pat["title"],
                    )
                    if is_fp:
                        stats.fp_suppressed += 1
                        log.debug(f"FP [{reason}]: {relative}:{line_no}")
                        continue

                    sev = pat["severity"]
                    cat = pat.get("category", "General")
                    if severity_filter and sev not in severity_filter:
                        continue
                    if category_filter and cat not in category_filter:
                        continue

                    title = pat["title"]
                    if title not in findings_map:
                        findings_map[title] = Finding(
                            title=title, severity=sev,
                            confidence=pat["confidence"],
                            exploitability=pat["exploitability"],
                            secret_type=pat["secret_type"],
                            description=pat["description"],
                            simulation=pat["simulation"],
                            score_value=pat["score_value"],
                            cvss_vector=pat.get("cvss_vector", ""),
                            cwe_id=pat.get("cwe_id", ""),
                            owasp_ref=pat.get("owasp_ref", ""),
                            category=cat,
                            triage_note=pat.get("triage_note", ""),
                        )

                    if len(findings_map[title].locations) < MAX_LOCATIONS_PER_FINDING:
                        raw_match = (
                            m.group(m.lastindex) if m.lastindex else m.group(0)
                        ) or m.group(0)
                        findings_map[title].locations.append(
                            FindingLocation(
                                file=relative, line=line_no,
                                snippet=stripped[:SNIPPET_MAX_LEN].replace("\n", " "),
                                redacted_match=redact_secret(raw_match) if len(raw_match) > 6 else "***",
                            )
                        )

                # ── Entropy-based detection ──────────────────────
                for raw in _STRING_RE.findall(line):
                    if raw.startswith("L") and "/" in raw and ";" in raw:
                        continue
                    if is_alphabet_string(raw):
                        stats.fp_suppressed += 1
                        continue

                    is_fp, _ = fp_filter.check(raw, line, fname)
                    if is_fp:
                        stats.fp_suppressed += 1
                        continue

                    ent      = shannon_entropy(raw)
                    has_ctx  = bool(_CTX_RE.search(line.lower()))

                    if ent >= 5.0 and has_ctx:
                        s_type, s_sim = classify_high_entropy_string(raw)
                        title = f"Exposed {s_type}"
                        sev, conf, exp, score = "CRITICAL", "HIGH", "LIKELY", 25
                    elif ent >= 5.2:
                        title  = "Unclassified High-Entropy Asset"
                        s_type = "Obfuscated Data"
                        s_sim  = "Attacker reverse-engineers data to determine if it acts as seed or endpoint."
                        sev, conf, exp, score = "MEDIUM", "LOW", "THEORETICAL", 5
                    else:
                        continue

                    if severity_filter and sev not in severity_filter:
                        continue

                    if title not in findings_map:
                        findings_map[title] = Finding(
                            title=title, severity=sev, confidence=conf,
                            exploitability=exp, secret_type=s_type,
                            description="High Shannon entropy string detected near security-sensitive keyword.",
                            simulation=s_sim, score_value=score,
                            cwe_id="CWE-798", owasp_ref="M9: Insecure Data Storage",
                            triage_note="Verify this is not a Base64 alphabet, resource ID, or SDK constant.",
                        )
                    if len(findings_map[title].locations) < MAX_LOCATIONS_PER_FINDING:
                        findings_map[title].locations.append(
                            FindingLocation(
                                file=relative, line=line_no,
                                snippet=stripped[:SNIPPET_MAX_LEN].replace("\n", " "),
                                redacted_match=redact_secret(raw),
                            )
                        )

    stats.scan_duration_sec = round(time.monotonic() - t0, 2)
    stats.patterns_run = PATTERN_COUNT

    log.info(
        f"Scan done: {stats.files_scanned} files | "
        f"{stats.lines_scanned:,} lines | "
        f"{len(findings_map)} findings | "
        f"{stats.fp_suppressed} FP suppressed | "
        f"{stats.scan_duration_sec}s"
    )

    from vengam.config import SEVERITY_ORDER
    sorted_findings = sorted(
        findings_map.values(),
        key=lambda f: SEVERITY_ORDER.get(f.severity, 0),
        reverse=True,
    )

    total_score, verdict = calculate_risk(sorted_findings, surface)

    return ScanResult(
        apk_name=Path(apk_path).name,
        apk_sha256=sha256_file(apk_path),
        scan_timestamp=datetime.datetime.now(datetime.timezone.utc)
            .isoformat().replace("+00:00", "Z"),
        findings=sorted_findings,
        dynamic_findings=[],
        attack_surface=surface,
        total_score=total_score,
        verdict=verdict,
        engine_stats=stats,
        platform="android",
    )
