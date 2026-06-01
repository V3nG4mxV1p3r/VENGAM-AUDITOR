"""
VENGAM Auditor — Diff / Version Comparison Report
Compares two APK/IPA scans and reports:
  - NEW findings (appeared in new version)
  - FIXED findings (resolved in new version)
  - WORSENED findings (severity increased)
  - IMPROVED findings (severity decreased)
  - UNCHANGED findings
"""
from __future__ import annotations
import datetime
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from vengam.core.models import Finding, ScanResult
from vengam.config import TOOL_NAME, TOOL_VERSION, SEVERITY_ORDER
from vengam.utils.logger import log


# ── Diff models ───────────────────────────────────────────────────────────────

@dataclass
class FindingDiff:
    status:      str         # NEW | FIXED | WORSENED | IMPROVED | UNCHANGED
    title:       str
    category:    str
    old_severity: str | None
    new_severity: str | None
    score_delta:  int        # positive = worse, negative = better
    finding:     Finding | None   # the Finding object (new version preferred)


@dataclass
class DiffResult:
    old_apk:       str
    new_apk:       str
    old_sha256:    str
    new_sha256:    str
    old_score:     int
    new_score:     int
    old_verdict:   str
    new_verdict:   str
    timestamp:     str
    diffs:         list[FindingDiff]

    @property
    def score_delta(self) -> int:
        return self.new_score - self.old_score

    @property
    def new_findings(self)      -> list[FindingDiff]:
        return [d for d in self.diffs if d.status == "NEW"]

    @property
    def fixed_findings(self)    -> list[FindingDiff]:
        return [d for d in self.diffs if d.status == "FIXED"]

    @property
    def worsened_findings(self) -> list[FindingDiff]:
        return [d for d in self.diffs if d.status == "WORSENED"]

    @property
    def improved_findings(self) -> list[FindingDiff]:
        return [d for d in self.diffs if d.status == "IMPROVED"]

    @property
    def unchanged_findings(self)-> list[FindingDiff]:
        return [d for d in self.diffs if d.status == "UNCHANGED"]


# ── Core diff engine ──────────────────────────────────────────────────────────

def diff_scans(old: ScanResult, new: ScanResult) -> DiffResult:
    """
    Compare two ScanResult objects and produce a DiffResult.
    Findings are matched by title (canonical key).
    """
    old_map = {f.title: f for f in old.findings}
    new_map = {f.title: f for f in new.findings}

    all_titles = set(old_map) | set(new_map)
    diffs: list[FindingDiff] = []

    for title in sorted(all_titles):
        old_f = old_map.get(title)
        new_f = new_map.get(title)

        if old_f is None and new_f is not None:
            # NEW — appeared in new version
            diffs.append(FindingDiff(
                status="NEW",
                title=title,
                category=new_f.category,
                old_severity=None,
                new_severity=new_f.severity,
                score_delta=new_f.score_value,
                finding=new_f,
            ))

        elif old_f is not None and new_f is None:
            # FIXED — resolved in new version
            diffs.append(FindingDiff(
                status="FIXED",
                title=title,
                category=old_f.category,
                old_severity=old_f.severity,
                new_severity=None,
                score_delta=-old_f.score_value,
                finding=old_f,
            ))

        elif old_f is not None and new_f is not None:
            old_rank = SEVERITY_ORDER.get(old_f.severity, 0)
            new_rank = SEVERITY_ORDER.get(new_f.severity, 0)
            delta    = new_f.score_value - old_f.score_value

            if new_rank > old_rank:
                status = "WORSENED"
            elif new_rank < old_rank:
                status = "IMPROVED"
            else:
                status = "UNCHANGED"

            diffs.append(FindingDiff(
                status=status,
                title=title,
                category=new_f.category,
                old_severity=old_f.severity,
                new_severity=new_f.severity,
                score_delta=delta,
                finding=new_f,
            ))

    # Sort: NEW/WORSENED first, then FIXED/IMPROVED, then UNCHANGED
    order = {"NEW": 0, "WORSENED": 1, "IMPROVED": 2, "FIXED": 3, "UNCHANGED": 4}
    diffs.sort(key=lambda d: (order.get(d.status, 9),
                               -SEVERITY_ORDER.get(d.new_severity or d.old_severity or "INFO", 0)))

    return DiffResult(
        old_apk=old.apk_name,
        new_apk=new.apk_name,
        old_sha256=old.apk_sha256,
        new_sha256=new.apk_sha256,
        old_score=old.total_score,
        new_score=new.total_score,
        old_verdict=old.verdict,
        new_verdict=new.verdict,
        timestamp=datetime.datetime.now(datetime.timezone.utc)
            .isoformat().replace("+00:00", "Z"),
        diffs=diffs,
    )


# ── Text diff report ──────────────────────────────────────────────────────────

def generate_text_diff(diff: DiffResult, out_path: str) -> None:
    W    = 72
    DIV  = "─" * W
    HDIV = "═" * W

    STATUS_ICON = {
        "NEW":       "🔴 NEW",
        "FIXED":     "✅ FIXED",
        "WORSENED":  "⬆️  WORSENED",
        "IMPROVED":  "⬇️  IMPROVED",
        "UNCHANGED": "⚪ UNCHANGED",
    }

    with open(out_path, "w", encoding="utf-8") as f:
        def w(line: str = "") -> None:
            f.write(line + "\n")

        w(HDIV)
        w(f"  {TOOL_NAME}  ·  Version Comparison Report  ·  v{TOOL_VERSION}")
        w(HDIV)
        w()

        # Header
        w("COMPARISON OVERVIEW")
        w(DIV)
        delta_sign = "+" if diff.score_delta >= 0 else ""
        w(f"  Old Version  : {diff.old_apk}")
        w(f"  New Version  : {diff.new_apk}")
        w(f"  Timestamp    : {diff.timestamp}")
        w()
        w(f"  {'':20}  {'OLD':>10}  {'NEW':>10}  {'DELTA':>10}")
        w(f"  {'Risk Score':20}  {diff.old_score:>10}  {diff.new_score:>10}  {delta_sign}{diff.score_delta:>9}")
        w(f"  {'Verdict':20}  {diff.old_verdict[:10]:>10}  {diff.new_verdict[:10]:>10}")
        w()
        w(f"  NEW findings      : {len(diff.new_findings)}")
        w(f"  FIXED findings    : {len(diff.fixed_findings)}")
        w(f"  WORSENED          : {len(diff.worsened_findings)}")
        w(f"  IMPROVED          : {len(diff.improved_findings)}")
        w(f"  UNCHANGED         : {len(diff.unchanged_findings)}")
        w()

        # Risk direction
        if diff.score_delta > 10:
            w("  ⚠️  SECURITY REGRESSION — new version is significantly less secure.")
        elif diff.score_delta < -10:
            w("  ✅  SECURITY IMPROVEMENT — new version is significantly more secure.")
        else:
            w("  ℹ️  Security posture largely unchanged between versions.")
        w()

        # Detail by status
        for status in ["NEW", "WORSENED", "IMPROVED", "FIXED", "UNCHANGED"]:
            group = [d for d in diff.diffs if d.status == status]
            if not group:
                continue
            w()
            w(f"{STATUS_ICON[status]}  FINDINGS  ({len(group)})")
            w(DIV)
            for d in group:
                sev_str = ""
                if d.old_severity and d.new_severity:
                    sev_str = f"  [{d.old_severity} → {d.new_severity}]"
                elif d.new_severity:
                    sev_str = f"  [{d.new_severity}]"
                elif d.old_severity:
                    sev_str = f"  [{d.old_severity}]"

                delta_str = f"  (Δ{'+' if d.score_delta>=0 else ''}{d.score_delta}pts)" if d.score_delta else ""
                w(f"  • {d.title}{sev_str}{delta_str}")
                if d.finding and d.finding.triage_note and status in ("NEW", "WORSENED"):
                    w(f"    ▶ {d.finding.triage_note[:80]}")

        w()
        w(HDIV)
        w(f"  DIFF SUMMARY  :  {len(diff.new_findings)} new | {len(diff.fixed_findings)} fixed | "
          f"{len(diff.worsened_findings)} worsened | score Δ{delta_sign}{diff.score_delta}")
        w(HDIV)

    log.info(f"Diff text report → {out_path}")


# ── JSON diff report ──────────────────────────────────────────────────────────

def generate_json_diff(diff: DiffResult, out_path: str) -> None:
    payload = {
        "schema_version": "vengam-diff-v7",
        "tool":           TOOL_NAME,
        "tool_version":   TOOL_VERSION,
        "timestamp":      diff.timestamp,
        "old_apk":        diff.old_apk,
        "new_apk":        diff.new_apk,
        "old_sha256":     diff.old_sha256,
        "new_sha256":     diff.new_sha256,
        "old_score":      diff.old_score,
        "new_score":      diff.new_score,
        "score_delta":    diff.score_delta,
        "old_verdict":    diff.old_verdict,
        "new_verdict":    diff.new_verdict,
        "summary": {
            "new":       len(diff.new_findings),
            "fixed":     len(diff.fixed_findings),
            "worsened":  len(diff.worsened_findings),
            "improved":  len(diff.improved_findings),
            "unchanged": len(diff.unchanged_findings),
        },
        "diffs": [
            {
                "status":       d.status,
                "title":        d.title,
                "category":     d.category,
                "old_severity": d.old_severity,
                "new_severity": d.new_severity,
                "score_delta":  d.score_delta,
            }
            for d in diff.diffs
        ],
    }
    with open(out_path, "w", encoding="utf-8") as jf:
        json.dump(payload, jf, indent=2, ensure_ascii=False)
    log.info(f"Diff JSON report → {out_path}")


# ── High-level entry point ────────────────────────────────────────────────────

def generate_diff(
    old_apk: str,
    new_apk: str,
    output_dir: str = ".",
    force: bool = False,
) -> DiffResult:
    """
    Full diff workflow:
    1. Decompile + scan old APK
    2. Decompile + scan new APK
    3. Diff the two results
    4. Write text + JSON reports
    Returns the DiffResult.
    """
    from vengam.core.decompiler import check_apktool, decompile_apk
    from vengam.android.static import scan_directory

    if not check_apktool():
        raise RuntimeError("apktool not available")

    os.makedirs(output_dir, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        # Scan old
        old_stem  = Path(old_apk).stem
        old_decomp= os.path.join(tmp, old_stem + "_old")
        log.info(f"Scanning OLD: {old_apk}")
        if not decompile_apk(old_apk, old_decomp, force=True):
            raise RuntimeError(f"Decompilation failed: {old_apk}")
        old_result = scan_directory(old_decomp, old_apk)

        # Scan new
        new_stem  = Path(new_apk).stem
        new_decomp= os.path.join(tmp, new_stem + "_new")
        log.info(f"Scanning NEW: {new_apk}")
        if not decompile_apk(new_apk, new_decomp, force=True):
            raise RuntimeError(f"Decompilation failed: {new_apk}")
        new_result = scan_directory(new_decomp, new_apk)

    diff = diff_scans(old_result, new_result)

    base = os.path.join(output_dir, f"diff_{old_stem}_vs_{new_stem}")
    generate_text_diff(diff, base + ".txt")
    generate_json_diff(diff, base + ".json")

    log.info(
        f"Diff complete: {len(diff.new_findings)} new | "
        f"{len(diff.fixed_findings)} fixed | "
        f"score {old_result.total_score} → {new_result.total_score}"
    )
    return diff
