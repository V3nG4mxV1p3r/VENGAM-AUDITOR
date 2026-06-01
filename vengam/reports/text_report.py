"""
VENGAM Auditor — Text Report Generator
"""
from __future__ import annotations
from collections import defaultdict
from vengam.core.models import ScanResult
from vengam.core.risk_engine import verdict_explanation, derive_business_impacts
from vengam.config import TOOL_NAME, TOOL_VERSION
from vengam.utils.logger import log

W    = 72
DIV  = "─" * W
HDIV = "═" * W

SEV_BADGE = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH":     "🟠 HIGH",
    "MEDIUM":   "🟡 MEDIUM",
    "LOW":      "🔵 LOW",
    "INFO":     "⚪ INFO",
}


def generate(result: ScanResult, out_path: str) -> None:
    with open(out_path, "w", encoding="utf-8") as rf:

        def w(line: str = "") -> None:
            rf.write(line + "\n")

        def chunk(text: str, width: int = 68, indent: str = "        ") -> None:
            for i in range(0, len(text), width):
                w(indent + text[i:i + width])

        # ── Header ───────────────────────────────────────────────
        w(HDIV)
        w(f"  {TOOL_NAME}  ·  Enterprise Security Report  ·  v{TOOL_VERSION}")
        w(HDIV)
        w()

        # 1. Metadata
        w("1. SCAN METADATA")
        w(DIV)
        s = result.engine_stats
        w(f"  Target           : {result.apk_name}")
        w(f"  Platform         : {result.platform.upper()}")
        w(f"  SHA-256          : {result.apk_sha256}")
        w(f"  Scan Timestamp   : {result.scan_timestamp}")
        w(f"  Engine Version   : {result.tool_version}")
        w(f"  Files Scanned    : {s.files_scanned}")
        w(f"  Lines Scanned    : {s.lines_scanned:,}")
        w(f"  Patterns Run     : {s.patterns_run}")
        w(f"  FP Suppressed    : {s.fp_suppressed}")
        w(f"  Scan Duration    : {s.scan_duration_sec}s")
        w()

        # 2. Executive Summary
        w("2. EXECUTIVE SUMMARY")
        w(DIV)
        w(f"  Overall Risk Score   : {result.total_score} / 100")
        w(f"  Release Readiness    : {result.verdict}")
        crit = len(result.findings_by_severity("CRITICAL"))
        high = len(result.findings_by_severity("HIGH"))
        med  = len(result.findings_by_severity("MEDIUM"))
        w(f"  Critical / High / Medium : {crit} / {high} / {med}")
        by_cat = defaultdict(int)
        for f in result.findings:
            by_cat[f.category] += 1
        w("  By Category      : " + " | ".join(f"{k}: {v}" for k, v in by_cat.items()))
        w(f"  Attack Surface   : {result.attack_surface.total} actionable routes")
        w(f"  Dynamic Findings : {len(result.dynamic_findings)}")
        w()
        w("  KEY BUSINESS RISKS:")
        for imp in derive_business_impacts(result.findings, result.attack_surface):
            w(f"    •  {imp}")
        w()

        # 3. Static Findings
        w("3. STATIC FINDINGS  (sorted by severity)")
        w(DIV)
        if not result.findings:
            w("  No significant findings detected.")
        for idx, f in enumerate(result.findings, 1):
            w()
            w(f"  [{idx:02d}] {SEV_BADGE.get(f.severity, f.severity)}  [{f.category}]  —  {f.title}")
            w(f"        Type           : {f.secret_type}")
            w(f"        Confidence     : {f.confidence}")
            w(f"        Exploitability : {f.exploitability}")
            if f.cvss_vector: w(f"        CVSS Vector    : {f.cvss_vector}")
            if f.cwe_id:      w(f"        CWE            : {f.cwe_id}")
            if f.owasp_ref:   w(f"        OWASP Mobile   : {f.owasp_ref}")
            w(f"        Score Impact   : +{f.score_value} pts")
            w()
            w("        DESCRIPTION")
            chunk(f.description)
            w()
            w("        ATTACK SIMULATION")
            chunk(f.simulation)
            if f.triage_note:
                w()
                w("        TRIAGE GUIDANCE")
                chunk(f.triage_note, indent="        ▶ ")
            w()
            w(f"        LOCATIONS  ({len(f.locations)} shown, max 5)")
            for loc in f.locations:
                w(f"          → {loc.file}  :  line {loc.line}")
                if loc.snippet:
                    w(f"            {loc.snippet[:90]}")
                if loc.redacted_match:
                    w(f"            Matched: {loc.redacted_match}")
            w()
            w("  " + "·" * (W - 2))

        # 4. Dynamic Findings
        if result.dynamic_findings:
            w()
            w("4. DYNAMIC FINDINGS  (Frida Runtime Analysis)")
            w(DIV)
            for idx, df in enumerate(result.dynamic_findings, 1):
                w()
                w(f"  [{idx:02d}] {SEV_BADGE.get(df.severity, df.severity)}  —  {df.hook_name}")
                w(f"        {df.description}")
                if df.evidence:
                    w(f"        Evidence ({len(df.evidence)} events):")
                    for ev in df.evidence[:5]:
                        w(f"          → {ev[:100]}")
                w()

        # 5. Attack Surface
        w()
        w("5. ATTACK SURFACE MAPPING")
        w(DIV)
        surf = result.attack_surface
        for label, routes in [
            ("[AUTH]",         surf.auth),
            ("[PAYMENT]",      surf.payment),
            ("[USER DATA]",    surf.user_data),
            ("[INTERNAL API]", surf.internal_api),
            ("[OTHER]",        surf.other),
        ]:
            if not routes:
                continue
            w(f"\n  {label}  —  {len(routes)} routes")
            for r in sorted(routes)[:8]:
                w(f"    + {r}")
            if len(routes) > 8:
                w(f"    … and {len(routes) - 8} more.")

        # 6. Risk Score Breakdown
        w()
        w("6. RISK SCORE BREAKDOWN")
        w(DIV)
        w("  Base: 0")
        for f in result.findings:
            w(f"  (+{f.score_value:02d})  [{f.severity:8}]  {f.title}")
        if surf.payment:               w("  (+15)  [SURFACE ]  Payment routes exposed")
        if surf.auth:                  w("  (+10)  [SURFACE ]  Auth routes exposed")
        if len(surf.internal_api) > 5: w("  (+10)  [SURFACE ]  Broad API exposure (>5 routes)")
        w("  [Combo bonuses applied for correlated findings]")
        w(DIV)
        w(f"  TOTAL  :  {result.total_score} / 100")

        # 7. Recommendations
        w()
        w("7. REMEDIATION RECOMMENDATIONS")
        w(DIV)
        recs = [
            ("Secrets Management",   "Remove ALL hardcoded credentials. Use Android Keystore for crypto. Fetch secrets post-auth from a dedicated secrets manager (Vault, AWS SM)."),
            ("Token Architecture",   "OAuth 2.0 / OIDC with short-lived JWTs (≤15 min). Enforce RS256/ES256 server-side."),
            ("API Defence",          "Rate-limit at WAF/gateway. Enforce Play Integrity API. Use mTLS for service-to-service."),
            ("Game Economy",         "ALL economy operations validated server-side. Signed score/purchase submissions. Server-authoritative currency ledger."),
            ("Anti-Cheat Hardening", "Remove debug flags before release. Enforce App Attestation. Consider LLVM-obfuscator for critical game logic."),
            ("Asset Protection",     "Unreal PAK encryption keys must NEVER be in the client binary."),
            ("Code Obfuscation",     "Aggressive R8/ProGuard. Commercial protectors (DexGuard, iXGuard) for crypto/anti-cheat classes."),
            ("CI/CD Integration",    "Integrate VENGAM as a blocking pipeline gate. Exit code 2 (BLOCK RELEASE) must fail the pipeline."),
            ("Network Security",     "Disable cleartext traffic. Enable certificate pinning. Do not trust user CA stores in production."),
            ("Manifest Hardening",   "Set allowBackup=false. Add permissions to all exported components."),
        ]
        for i, (title, detail) in enumerate(recs, 1):
            w()
            w(f"  {i}. {title.upper()}")
            chunk(detail, indent="     ")

        # 8. Verdict
        w()
        w(HDIV)
        w(f"  FINAL VERDICT  :  {result.verdict}")
        w(f"  RISK SCORE     :  {result.total_score} / 100")
        w(HDIV)
        reason, action = verdict_explanation(result.verdict)
        w(f"  REASON : {reason}")
        w(f"  ACTION : {action}")
        w(HDIV)

    log.info(f"Text report → {out_path}")
