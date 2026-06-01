"""
VENGAM Auditor — iOS Static Analysis Orchestrator
Combines IPA extraction + plist analysis + Mach-O analysis + string scanning.
"""
from __future__ import annotations
import datetime
import os
import time
from pathlib import Path

from vengam.core.models import (
    AttackSurface, EngineStats, Finding, FindingLocation, ScanResult,
)
from vengam.core.fp_filter import FalsePositiveFilter
from vengam.core.risk_engine import calculate_risk
from vengam.config import (
    SCANNABLE_EXTENSIONS, IGNORE_FILE_FRAGMENTS,
    MAX_LOCATIONS_PER_FINDING, SNIPPET_MAX_LEN, SEVERITY_ORDER,
)
from vengam.ios.ipa_extractor import extract_ipa, get_ipa_structure
from vengam.ios.plist_parser import analyse_plist_security
from vengam.ios.macho_wrapper import extract_strings, analyse_binary_security
from vengam.ios.swift_strings import scan_strings
from vengam.android.attack_surface import categorise_url, NOISE_DOMAINS, NOISE_EXTENSIONS
from vengam.patterns.loader import COMPILED_PATTERNS, PATTERN_COUNT
from vengam.utils.crypto import sha256_file, redact_secret
from vengam.utils.entropy import shannon_entropy, is_alphabet_string, classify_high_entropy_string
from vengam.utils.logger import log

import re
from urllib.parse import urlparse

_URL_RE    = re.compile(r"https?://[a-zA-Z0-9\-\.]+[a-zA-Z0-9_/\-\.=?&]*")
_STRING_RE = re.compile(r"['\"]([^'\"\s]{20,256})['\"]")
_CTX_RE    = re.compile(
    r"\b(key|secret|token|auth|pass|bearer|api|aws|cred|password|jwt|credential|encrypt)\b"
)

# iOS-specific scannable extensions (in addition to base set)
IOS_SCANNABLE_EXTENSIONS = SCANNABLE_EXTENSIONS | frozenset({
    ".swift", ".m", ".mm", ".h", ".strings", ".stringsdict",
})

IOS_IGNORE_FRAGMENTS = IGNORE_FILE_FRAGMENTS | frozenset({
    "LaunchScreen", "Assets.xcassets", "Base.lproj",
    "en.lproj", "zh-Hans.lproj",
})


def _is_noise_file(filename: str) -> bool:
    return any(frag in filename for frag in IOS_IGNORE_FRAGMENTS)


def _raw_finding_to_finding(raw: dict) -> Finding:
    """Convert a raw pattern dict (with locations) to a Finding dataclass."""
    return Finding(
        title=raw["title"],
        severity=raw["severity"],
        confidence=raw.get("confidence", "MEDIUM"),
        exploitability=raw.get("exploitability", "THEORETICAL"),
        secret_type=raw.get("secret_type", "Unknown"),
        description=raw.get("description", ""),
        simulation=raw.get("simulation", ""),
        score_value=raw.get("score_value", 5),
        cvss_vector=raw.get("cvss_vector", ""),
        cwe_id=raw.get("cwe_id", ""),
        owasp_ref=raw.get("owasp_ref", ""),
        category=raw.get("category", "General"),
        triage_note=raw.get("triage_note", ""),
        locations=raw.get("locations", []),
    )


def scan_ipa(
    ipa_path: str,
    output_dir: str | None = None,
    force: bool = False,
    severity_filter: set[str] | None = None,
    category_filter: set[str] | None = None,
) -> ScanResult:
    """
    Full iOS IPA security scan.
    Returns a ScanResult with platform='ios'.
    """
    log.info("=== PHASE 1: IPA EXTRACTION ===")

    ipa_path = ipa_path.strip("\"'")
    stem     = Path(ipa_path).stem
    out_dir  = output_dir or os.path.join(os.getcwd(), stem + "_vengam_ios_out")

    app_bundle = extract_ipa(ipa_path, out_dir, force=force)
    if not app_bundle:
        raise RuntimeError(f"Failed to extract IPA: {ipa_path}")

    structure = get_ipa_structure(app_bundle)

    log.info("=== PHASE 2: iOS STATIC ANALYSIS ===")
    log.info(f"Patterns loaded: {PATTERN_COUNT}")

    fp_filter     = FalsePositiveFilter()
    findings_map: dict[str, Finding] = {}
    surface       = AttackSurface()
    stats         = EngineStats()
    t0            = time.monotonic()

    # ── Phase 2a: plist security analysis ────────────────────────
    log.info("--- plist analysis ---")
    if structure["info_plist"]:
        raw_plist_findings = analyse_plist_security(structure["info_plist"])
        for raw in raw_plist_findings:
            if severity_filter and raw["severity"] not in severity_filter:
                continue
            if category_filter and raw.get("category", "General") not in category_filter:
                continue
            title = raw["title"]
            loc   = FindingLocation(
                file="Info.plist",
                line=1,
                snippet=raw.get("evidence", "")[:SNIPPET_MAX_LEN],
            )
            if title not in findings_map:
                findings_map[title] = _raw_finding_to_finding({**raw, "locations": [loc]})
            else:
                if len(findings_map[title].locations) < MAX_LOCATIONS_PER_FINDING:
                    findings_map[title].locations.append(loc)

    # ── Phase 2b: Mach-O binary security flags ───────────────────
    log.info("--- Mach-O binary analysis ---")
    if structure["binary"]:
        binary_sec = analyse_binary_security(structure["binary"])
        for raw in binary_sec:
            if severity_filter and raw["severity"] not in severity_filter:
                continue
            title = raw["title"]
            loc   = FindingLocation(
                file=f"[binary] {Path(structure['binary']).name}",
                line=1,
                snippet=raw.get("evidence", "")[:SNIPPET_MAX_LEN],
            )
            if title not in findings_map:
                findings_map[title] = _raw_finding_to_finding({**raw, "locations": [loc]})

        # ── Phase 2c: Binary string pattern scan ─────────────────
        log.info("--- Binary string scan ---")
        bin_strings = extract_strings(structure["binary"], min_length=8)
        stats.files_scanned += 1

        bin_findings = scan_strings(
            bin_strings,
            Path(structure["binary"]).name,
            severity_filter=severity_filter,
            category_filter=category_filter,
        )
        for title, raw in bin_findings.items():
            if title not in findings_map:
                findings_map[title] = _raw_finding_to_finding(raw)
            else:
                for loc in raw.get("locations", []):
                    if len(findings_map[title].locations) < MAX_LOCATIONS_PER_FINDING:
                        findings_map[title].locations.append(loc)

    # ── Phase 2d: Text file scan (same as Android) ────────────────
    log.info("--- Text file scan ---")
    for root, _dirs, files in Path(app_bundle).walk():
        for fname in files:
            if _is_noise_file(fname):
                continue
            if Path(fname).suffix not in IOS_SCANNABLE_EXTENSIONS:
                continue

            filepath = root / fname
            relative = str(filepath.relative_to(app_bundle))
            stats.files_scanned += 1

            try:
                lines = filepath.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue

            for line_no, line in enumerate(lines, 1):
                stats.lines_scanned += 1
                stripped = line.strip()

                # URL extraction
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

                # Pattern matching
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
                                snippet=stripped[:SNIPPET_MAX_LEN],
                                redacted_match=redact_secret(raw_match) if len(raw_match) > 6 else "***",
                            )
                        )

                # Entropy detection
                for raw_s in _STRING_RE.findall(line):
                    if is_alphabet_string(raw_s):
                        stats.fp_suppressed += 1
                        continue
                    is_fp, _ = fp_filter.check(raw_s, line, fname)
                    if is_fp:
                        stats.fp_suppressed += 1
                        continue

                    ent     = shannon_entropy(raw_s)
                    has_ctx = bool(_CTX_RE.search(line.lower()))

                    if ent >= 5.0 and has_ctx:
                        s_type, s_sim = classify_high_entropy_string(raw_s)
                        e_title = f"Exposed {s_type}"
                        sev, conf, exp, score = "CRITICAL", "HIGH", "LIKELY", 25
                    elif ent >= 5.2:
                        e_title = "Unclassified High-Entropy Asset"
                        s_type  = "Obfuscated Data"
                        s_sim   = "Attacker reverse-engineers data to determine if it is a seed or endpoint."
                        sev, conf, exp, score = "MEDIUM", "LOW", "THEORETICAL", 5
                    else:
                        continue

                    if severity_filter and sev not in severity_filter:
                        continue

                    if e_title not in findings_map:
                        findings_map[e_title] = Finding(
                            title=e_title, severity=sev, confidence=conf,
                            exploitability=exp, secret_type=s_type,
                            description="High Shannon entropy string detected near security-sensitive keyword.",
                            simulation=s_sim, score_value=score,
                            cwe_id="CWE-798", owasp_ref="M9: Insecure Data Storage",
                            triage_note="Verify this is not a Base64 alphabet, UUID, or SDK constant.",
                        )
                    if len(findings_map[e_title].locations) < MAX_LOCATIONS_PER_FINDING:
                        findings_map[e_title].locations.append(
                            FindingLocation(
                                file=relative, line=line_no,
                                snippet=stripped[:SNIPPET_MAX_LEN],
                                redacted_match=redact_secret(raw_s),
                            )
                        )

    stats.scan_duration_sec = round(time.monotonic() - t0, 2)
    stats.patterns_run      = PATTERN_COUNT

    log.info(
        f"iOS scan done: {stats.files_scanned} files | "
        f"{stats.lines_scanned:,} lines | "
        f"{len(findings_map)} findings | "
        f"{stats.fp_suppressed} FP suppressed | "
        f"{stats.scan_duration_sec}s"
    )

    sorted_findings = sorted(
        findings_map.values(),
        key=lambda f: SEVERITY_ORDER.get(f.severity, 0),
        reverse=True,
    )

    total_score, verdict = calculate_risk(sorted_findings, surface)

    return ScanResult(
        apk_name=Path(ipa_path).name,
        apk_sha256=sha256_file(ipa_path),
        scan_timestamp=datetime.datetime.now(datetime.timezone.utc)
            .isoformat().replace("+00:00", "Z"),
        findings=sorted_findings,
        dynamic_findings=[],
        attack_surface=surface,
        total_score=total_score,
        verdict=verdict,
        engine_stats=stats,
        platform="ios",
    )
