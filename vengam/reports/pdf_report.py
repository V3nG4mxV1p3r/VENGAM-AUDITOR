"""
VENGAM Auditor — PDF Report Generator
Requires: pip install weasyprint
"""
from __future__ import annotations
import html as html_lib
from collections import defaultdict
from vengam.core.models import ScanResult
from vengam.core.risk_engine import verdict_explanation, derive_business_impacts
from vengam.config import TOOL_NAME, TOOL_VERSION
from vengam.utils.logger import log

SEV_COLOR = {
    "CRITICAL": "#ff3b5c",
    "HIGH":     "#ff8c00",
    "MEDIUM":   "#ffd700",
    "LOW":      "#4facfe",
    "INFO":     "#6b7280",
}

SEV_BG = {
    "CRITICAL": "rgba(255,59,92,0.12)",
    "HIGH":     "rgba(255,140,0,0.12)",
    "MEDIUM":   "rgba(255,215,0,0.10)",
    "LOW":      "rgba(79,172,254,0.10)",
    "INFO":     "rgba(107,114,128,0.10)",
}

CAT_COLOR = {
    "GameEngine": "#4facfe",
    "AntiCheat":  "#ff3b5c",
    "Economy":    "#ffd700",
    "Config":     "#a78bfa",
    "General":    "#6b7280",
}


def _e(s: str) -> str:
    """HTML-escape a string."""
    return html_lib.escape(str(s))


def _verdict_class(verdict: str) -> str:
    if verdict == "BLOCK RELEASE":
        return "verdict-block"
    if "AT RISK" in verdict:
        return "verdict-risk"
    return "verdict-safe"


def _build_html(result: ScanResult) -> str:
    reason, action = verdict_explanation(result.verdict)
    impacts        = derive_business_impacts(result.findings, result.attack_surface)
    by_cat         = defaultdict(int)
    for f in result.findings:
        by_cat[f.category] += 1

    crit = len(result.findings_by_severity("CRITICAL"))
    high = len(result.findings_by_severity("HIGH"))
    med  = len(result.findings_by_severity("MEDIUM"))
    low  = len(result.findings_by_severity("LOW"))

    # ── CSS ──────────────────────────────────────────────────────
    css = """
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&family=JetBrains+Mono:wght@400;700&display=swap');

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
        font-family: 'Inter', sans-serif;
        background: #ffffff;
        color: #1a1d2e;
        font-size: 11pt;
        line-height: 1.6;
    }

    /* Cover page */
    .cover {
        background: linear-gradient(135deg, #0a0b0f 0%, #13151c 60%, #1a1d2e 100%);
        color: #e8eaf0;
        padding: 80px 60px;
        min-height: 100vh;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        page-break-after: always;
    }
    .cover-logo {
        font-size: 42pt;
        font-weight: 800;
        letter-spacing: -1px;
        margin-bottom: 4px;
    }
    .cover-logo span { color: #ff3b5c; }
    .cover-subtitle { font-size: 14pt; color: #6b7280; margin-bottom: 60px; }
    .cover-title {
        font-size: 28pt;
        font-weight: 800;
        line-height: 1.2;
        margin-bottom: 12px;
    }
    .cover-meta { font-family: 'JetBrains Mono', monospace; font-size: 9pt; color: #6b7280; line-height: 2; }
    .cover-score-row { display: flex; gap: 40px; margin-top: 60px; }
    .cover-score-card {
        background: rgba(255,255,255,0.05);
        border: 1px solid rgba(255,255,255,0.1);
        border-radius: 12px;
        padding: 24px 32px;
        text-align: center;
    }
    .cover-score-value { font-size: 36pt; font-weight: 800; }
    .cover-score-label { font-size: 9pt; color: #6b7280; margin-top: 4px; text-transform: uppercase; letter-spacing: 1px; }

    /* Page layout */
    .page {
        padding: 48px 56px;
        page-break-after: always;
    }
    .page:last-child { page-break-after: auto; }

    /* Section headers */
    .section-title {
        font-size: 8pt;
        font-weight: 700;
        letter-spacing: 3px;
        text-transform: uppercase;
        color: #6b7280;
        margin-bottom: 16px;
        padding-bottom: 10px;
        border-bottom: 2px solid #f0f1f5;
    }

    /* Verdict banner */
    .verdict-banner {
        border-radius: 10px;
        padding: 20px 24px;
        margin-bottom: 28px;
        display: flex;
        align-items: center;
        gap: 16px;
    }
    .verdict-block { background: rgba(255,59,92,0.08); border: 1px solid rgba(255,59,92,0.25); }
    .verdict-risk  { background: rgba(255,140,0,0.08); border: 1px solid rgba(255,140,0,0.25); }
    .verdict-safe  { background: rgba(0,200,120,0.08); border: 1px solid rgba(0,200,120,0.25); }

    .verdict-pill {
        padding: 8px 20px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 11pt;
        white-space: nowrap;
    }
    .verdict-block .verdict-pill { background: rgba(255,59,92,0.15); color: #cc1f3a; }
    .verdict-risk  .verdict-pill { background: rgba(255,140,0,0.15);  color: #cc6e00; }
    .verdict-safe  .verdict-pill { background: rgba(0,200,120,0.15);  color: #007a50; }
    .verdict-detail { font-size: 10pt; color: #6b7280; }

    /* Metric cards */
    .metric-row { display: flex; gap: 16px; margin-bottom: 28px; }
    .metric-card {
        flex: 1;
        background: #f8f9fc;
        border: 1px solid #e8eaf0;
        border-radius: 10px;
        padding: 18px 22px;
    }
    .metric-value { font-size: 30pt; font-weight: 800; line-height: 1; }
    .metric-label { font-size: 9pt; color: #6b7280; margin-top: 5px; text-transform: uppercase; letter-spacing: 1px; }

    /* Finding card */
    .finding-card {
        border: 1px solid #e8eaf0;
        border-radius: 10px;
        margin-bottom: 16px;
        overflow: hidden;
        page-break-inside: avoid;
    }
    .finding-header {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 14px 18px;
        background: #f8f9fc;
    }
    .sev-dot {
        width: 9px; height: 9px;
        border-radius: 50%;
        flex-shrink: 0;
    }
    .finding-title { font-weight: 700; font-size: 11pt; flex: 1; }
    .cat-badge {
        font-family: 'JetBrains Mono', monospace;
        font-size: 8pt;
        padding: 2px 8px;
        border-radius: 4px;
        background: #e8eaf0;
        color: #6b7280;
    }
    .score-chip {
        font-family: 'JetBrains Mono', monospace;
        font-size: 9pt;
        color: #6b7280;
        background: #e8eaf0;
        padding: 2px 8px;
        border-radius: 4px;
    }
    .finding-body { padding: 14px 18px; }
    .finding-body p { font-size: 10pt; color: #4b5563; line-height: 1.7; margin-bottom: 10px; }

    .sim-box {
        background: #fff5f5;
        border-left: 3px solid #ff3b5c;
        padding: 10px 14px;
        border-radius: 0 6px 6px 0;
        font-size: 10pt;
        color: #6b7280;
        margin-bottom: 10px;
    }
    .triage-box {
        background: #f0f7ff;
        border-left: 3px solid #4facfe;
        padding: 10px 14px;
        border-radius: 0 6px 6px 0;
        font-size: 10pt;
        color: #2563eb;
        margin-bottom: 10px;
    }

    .meta-row { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; }
    .meta-pill {
        font-family: 'JetBrains Mono', monospace;
        font-size: 8pt;
        padding: 3px 8px;
        background: #f0f1f5;
        border-radius: 4px;
        color: #6b7280;
    }
    .meta-pill b { color: #1a1d2e; }

    .loc-item {
        font-family: 'JetBrains Mono', monospace;
        font-size: 9pt;
        color: #6b7280;
        padding: 5px 8px;
        background: #f8f9fc;
        border-radius: 4px;
        margin-top: 4px;
        display: flex;
        gap: 10px;
    }
    .loc-line  { color: #4facfe; flex-shrink: 0; }
    .loc-match { color: #ff8c00; margin-left: auto; }

    /* Impact list */
    .impact-list { list-style: none; }
    .impact-list li {
        padding: 8px 12px;
        background: #f8f9fc;
        border-left: 3px solid #ff3b5c;
        border-radius: 0 6px 6px 0;
        margin-bottom: 8px;
        font-size: 10pt;
        color: #4b5563;
    }

    /* Surface table */
    .surface-table { width: 100%; border-collapse: collapse; font-size: 10pt; }
    .surface-table th {
        text-align: left;
        padding: 10px 14px;
        background: #f0f1f5;
        font-weight: 700;
        font-size: 9pt;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: #6b7280;
    }
    .surface-table td {
        padding: 9px 14px;
        border-bottom: 1px solid #f0f1f5;
        font-family: 'JetBrains Mono', monospace;
        font-size: 9pt;
        color: #4b5563;
    }
    .surface-table tr:last-child td { border-bottom: none; }

    /* Score breakdown */
    .score-row {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 8px 0;
        border-bottom: 1px solid #f0f1f5;
        font-size: 10pt;
    }
    .score-pts { font-family: 'JetBrains Mono', monospace; font-size: 9pt; color: #6b7280; min-width: 48px; }
    .score-sev { font-size: 9pt; font-weight: 700; min-width: 70px; }

    /* Rec cards */
    .rec-card {
        background: #f8f9fc;
        border: 1px solid #e8eaf0;
        border-radius: 8px;
        padding: 14px 18px;
        margin-bottom: 12px;
        page-break-inside: avoid;
    }
    .rec-title { font-weight: 700; font-size: 10pt; margin-bottom: 6px; }
    .rec-body  { font-size: 10pt; color: #4b5563; line-height: 1.6; }

    /* Footer */
    @page {
        margin: 0;
        @bottom-center {
            content: "VENGAM GameSec Auditor v""" + TOOL_VERSION + """ — Confidential";
            font-size: 8pt;
            color: #9ca3af;
        }
        @bottom-right {
            content: counter(page);
            font-size: 8pt;
            color: #9ca3af;
        }
    }
    """

    # ── Build findings HTML ───────────────────────────────────────
    def findings_html(findings) -> str:
        parts = []
        for idx, f in enumerate(findings, 1):
            dot_color   = SEV_COLOR.get(f.severity, "#6b7280")
            cat_color   = CAT_COLOR.get(f.category, "#6b7280")
            sev_bg      = SEV_BG.get(f.severity, "rgba(107,114,128,0.1)")

            locs_html = ""
            for loc in f.locations[:5]:
                match_html = (
                    f'<span class="loc-match">{_e(loc.redacted_match)}</span>'
                    if loc.redacted_match else ""
                )
                locs_html += f"""
                <div class="loc-item">
                    <span class="loc-line">:{loc.line}</span>
                    <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{_e(loc.file)}</span>
                    {match_html}
                </div>"""

            triage_html = ""
            if f.triage_note:
                triage_html = f'<div class="triage-box">▶ {_e(f.triage_note)}</div>'

            cvss_html = f'<div class="meta-pill">CVSS <b>{_e(f.cvss_vector)}</b></div>' if f.cvss_vector else ""
            cwe_html  = f'<div class="meta-pill">CWE <b>{_e(f.cwe_id)}</b></div>'       if f.cwe_id      else ""
            owasp_html= f'<div class="meta-pill">OWASP <b>{_e(f.owasp_ref)}</b></div>'  if f.owasp_ref   else ""

            parts.append(f"""
            <div class="finding-card">
                <div class="finding-header">
                    <div class="sev-dot" style="background:{dot_color}"></div>
                    <span class="finding-title">{idx:02d}. {_e(f.title)}</span>
                    <span class="cat-badge" style="color:{cat_color}">{_e(f.category)}</span>
                    <span class="score-chip">+{f.score_value}pts</span>
                </div>
                <div class="finding-body">
                    <div class="meta-row">
                        <div class="meta-pill">Severity <b>{_e(f.severity)}</b></div>
                        <div class="meta-pill">Confidence <b>{_e(f.confidence)}</b></div>
                        <div class="meta-pill">Exploitability <b>{_e(f.exploitability)}</b></div>
                        {cwe_html}{owasp_html}{cvss_html}
                    </div>
                    <p>{_e(f.description)}</p>
                    <div class="sim-box">⚔️ {_e(f.simulation)}</div>
                    {triage_html}
                    {locs_html}
                </div>
            </div>""")
        return "\n".join(parts)

    # ── Attack surface rows ───────────────────────────────────────
    def surface_rows() -> str:
        surf = result.attack_surface
        rows = []
        for cat, routes in [
            ("Auth",         surf.auth),
            ("Payment",      surf.payment),
            ("User Data",    surf.user_data),
            ("Internal API", surf.internal_api),
            ("Other",        surf.other),
        ]:
            if not routes:
                continue
            sample = ", ".join(list(routes)[:3])
            if len(routes) > 3:
                sample += f" … +{len(routes)-3} more"
            rows.append(f"""
            <tr>
                <td><b>{_e(cat)}</b></td>
                <td style="text-align:center;font-weight:700">{len(routes)}</td>
                <td>{_e(sample)}</td>
            </tr>""")
        return "\n".join(rows)

    # ── Recommendations ───────────────────────────────────────────
    recs = [
        ("Secrets Management",   "Remove ALL hardcoded credentials. Use Android Keystore for crypto. Fetch secrets post-auth from a dedicated secrets manager."),
        ("Token Architecture",   "OAuth 2.0 / OIDC with short-lived JWTs (≤15 min). Enforce RS256/ES256 server-side."),
        ("API Defence",          "Rate-limit at WAF/gateway. Enforce Play Integrity API. Use mTLS for service-to-service calls."),
        ("Game Economy",         "ALL economy operations validated server-side. Signed score/purchase submissions. Server-authoritative currency ledger."),
        ("Anti-Cheat Hardening", "Remove debug flags before release. Enforce App Attestation. Consider LLVM-obfuscator for critical game logic."),
        ("Asset Protection",     "Unreal PAK encryption keys must NEVER be in the client binary. Use server-side key provisioning."),
        ("Code Obfuscation",     "Aggressive R8/ProGuard with dictionary obfuscation. Commercial protectors (DexGuard, iXGuard) for crypto/anti-cheat."),
        ("Network Security",     "Disable cleartext traffic. Enable certificate pinning. Do not trust user CA stores in production builds."),
        ("Manifest Hardening",   "Set allowBackup=false. Add permissions to all exported components."),
        ("CI/CD Integration",    "Integrate VENGAM as a blocking pipeline gate. Exit code 2 (BLOCK RELEASE) must fail the pipeline automatically."),
    ]
    recs_html = "\n".join(
        f'<div class="rec-card"><div class="rec-title">{i}. {_e(t)}</div><div class="rec-body">{_e(d)}</div></div>'
        for i, (t, d) in enumerate(recs, 1)
    )

    # ── Score breakdown ───────────────────────────────────────────
    score_rows = "\n".join(
        f'<div class="score-row">'
        f'<span class="score-pts">+{f.score_value:02d}</span>'
        f'<span class="score-sev" style="color:{SEV_COLOR.get(f.severity,"#6b7280")}">{_e(f.severity)}</span>'
        f'<span>{_e(f.title)}</span>'
        f'</div>'
        for f in result.findings
    )

    impacts_html = "\n".join(f"<li>{_e(imp)}</li>" for imp in impacts)
    by_cat_str   = " | ".join(f"{k}: {v}" for k, v in by_cat.items())

    # ── Full HTML document ────────────────────────────────────────
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<style>{css}</style>
</head>
<body>

<!-- ═══════════════════ COVER PAGE ═══════════════════ -->
<div class="cover">
    <div>
        <div class="cover-logo">VENG<span>AM</span></div>
        <div class="cover-subtitle">GameSec Auditor &nbsp;·&nbsp; v{_e(TOOL_VERSION)}</div>
        <div class="cover-title">Mobile Security<br>Audit Report</div>
        <div class="cover-meta">
            Target    : {_e(result.apk_name)}<br>
            Platform  : {_e(result.platform.upper())}<br>
            SHA-256   : {_e(result.apk_sha256)}<br>
            Timestamp : {_e(result.scan_timestamp)}<br>
            Engine    : {_e(result.tool_version)}
        </div>
    </div>
    <div class="cover-score-row">
        <div class="cover-score-card">
            <div class="cover-score-value" style="color:{SEV_COLOR.get('CRITICAL','#ff3b5c') if result.total_score >= 75 else ('#ff8c00' if result.total_score >= 40 else '#00f593')}">{result.total_score}</div>
            <div class="cover-score-label">Risk Score / 100</div>
        </div>
        <div class="cover-score-card">
            <div class="cover-score-value" style="color:#ff3b5c">{crit}</div>
            <div class="cover-score-label">Critical</div>
        </div>
        <div class="cover-score-card">
            <div class="cover-score-value" style="color:#ff8c00">{high}</div>
            <div class="cover-score-label">High</div>
        </div>
        <div class="cover-score-card">
            <div class="cover-score-value" style="color:#e8eaf0">{len(result.findings)}</div>
            <div class="cover-score-label">Total Findings</div>
        </div>
    </div>
</div>

<!-- ═══════════════════ EXECUTIVE SUMMARY ═══════════════════ -->
<div class="page">
    <div class="section-title">Executive Summary</div>

    <div class="verdict-banner {_verdict_class(result.verdict)}">
        <span class="verdict-pill">{_e(result.verdict)}</span>
        <span class="verdict-detail">{_e(reason)}</span>
    </div>

    <div class="metric-row">
        <div class="metric-card">
            <div class="metric-value" style="color:{SEV_COLOR.get('CRITICAL','#ff3b5c') if result.total_score>=75 else ('#ff8c00' if result.total_score>=40 else '#00c878')}">{result.total_score}/100</div>
            <div class="metric-label">Risk Score</div>
        </div>
        <div class="metric-card">
            <div class="metric-value" style="color:#ff3b5c">{crit}</div>
            <div class="metric-label">Critical</div>
        </div>
        <div class="metric-card">
            <div class="metric-value" style="color:#ff8c00">{high}</div>
            <div class="metric-label">High</div>
        </div>
        <div class="metric-card">
            <div class="metric-value" style="color:#ffd700">{med}</div>
            <div class="metric-label">Medium</div>
        </div>
        <div class="metric-card">
            <div class="metric-value" style="color:#4facfe">{low}</div>
            <div class="metric-label">Low</div>
        </div>
    </div>

    <p style="font-size:10pt;color:#4b5563;margin-bottom:16px">
        <b>Categories:</b> {_e(by_cat_str)} &nbsp;·&nbsp;
        <b>Attack Surface:</b> {result.attack_surface.total} routes &nbsp;·&nbsp;
        <b>Files Scanned:</b> {result.engine_stats.files_scanned} &nbsp;·&nbsp;
        <b>FP Suppressed:</b> {result.engine_stats.fp_suppressed}
    </p>

    <div class="section-title" style="margin-top:24px">Key Business Risks</div>
    <ul class="impact-list">{impacts_html}</ul>

    <div class="section-title" style="margin-top:28px">Recommended Action</div>
    <p style="font-size:10pt;color:#4b5563">{_e(action)}</p>
</div>

<!-- ═══════════════════ FINDINGS ═══════════════════ -->
<div class="page">
    <div class="section-title">Security Findings ({len(result.findings)} total)</div>
    {findings_html(result.findings)}
</div>

<!-- ═══════════════════ ATTACK SURFACE ═══════════════════ -->
<div class="page">
    <div class="section-title">Attack Surface Mapping</div>
    <table class="surface-table">
        <thead>
            <tr>
                <th>Category</th>
                <th style="text-align:center">Count</th>
                <th>Sample Routes</th>
            </tr>
        </thead>
        <tbody>{surface_rows()}</tbody>
    </table>

    <div class="section-title" style="margin-top:32px">Risk Score Breakdown</div>
    {score_rows}
    <div style="margin-top:12px;font-size:10pt;font-weight:700;color:#1a1d2e">
        TOTAL: {result.total_score} / 100
    </div>
</div>

<!-- ═══════════════════ RECOMMENDATIONS ═══════════════════ -->
<div class="page">
    <div class="section-title">Remediation Recommendations</div>
    {recs_html}
</div>

</body>
</html>"""


def generate(result: ScanResult, out_path: str) -> None:
    try:
        from weasyprint import HTML, CSS
    except ImportError:
        log.error("WeasyPrint not installed. Run: pip install weasyprint")
        raise

    html_content = _build_html(result)

    HTML(string=html_content).write_pdf(out_path)
    log.info(f"PDF report → {out_path}")
