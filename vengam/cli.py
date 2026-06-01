"""
VENGAM Auditor — CLI Entry Point
"""
from __future__ import annotations
import argparse
import os
import sys
from pathlib import Path

from vengam.config import TOOL_NAME, TOOL_VERSION
from vengam.utils.logger import get_logger

BANNER = r"""
╔══════════════════════════════════════════════════════════════════╗
║      ██╗   ██╗███████╗███╗   ██╗ ██████╗  █████╗ ███╗   ███╗     ║
║      ██║   ██║██╔════╝████╗  ██║██╔════╝ ██╔══██╗████╗ ████║     ║
║      ██║   ██║█████╗  ██╔██╗ ██║██║  ███╗███████║██╔████╔██║     ║
║      ╚██╗ ██╔╝██╔══╝  ██║╚██╗██║██║   ██║██╔══██║██║╚██╔╝██║     ║
║       ╚████╔╝ ███████╗██║ ╚████║╚██████╔╝██║  ██║██║ ╚═╝ ██║     ║
║        ╚═══╝  ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝     ║
║                                                                  ║
║       GameSec Auditor  ·  v7.0  Professional Edition             ║
║       Android · iOS · Static · Dynamic (Frida)                   ║
╚══════════════════════════════════════════════════════════════════╝
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vengam",
        description=f"{TOOL_NAME} v{TOOL_VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples
────────
  Android static scan:
    vengam -t MyGame.apk
    vengam -t MyGame.apk --severity-filter CRITICAL,HIGH
    vengam -t MyGame.apk --category-filter Economy,AntiCheat

  Pre-decompiled directory:
    vengam --dir MyGame_out/

  Frida dynamic analysis (combined):
    vengam -t MyGame.apk --frida --pkg com.studio.game --timeout 90

  iOS IPA scan (Sprint 2):
    vengam --ios -t MyGame.ipa

  Web dashboard:
    vengam --web --port 5000

  Diff scan (Sprint 5):
    vengam --diff old.apk new.apk
        """,
    )

    # ── Scan modes ────────────────────────────────────────────────
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--web",   action="store_true", help="Start web dashboard (Sprint 4)")
    mode.add_argument("--frida", action="store_true", help="Enable Frida dynamic analysis")
    mode.add_argument("--ios",   action="store_true", help="iOS IPA scan mode (Sprint 2)")
    mode.add_argument("--diff",  nargs=2, metavar=("OLD", "NEW"),
                      help="Diff scan: compare two APKs (Sprint 5)")

    # ── Input ─────────────────────────────────────────────────────
    src = p.add_mutually_exclusive_group()
    src.add_argument("-t", "--target", metavar="APK",
                     help="Path to .apk or .ipa file")
    src.add_argument("--dir", metavar="DIR",
                     help="Path to pre-decompiled directory")

    # ── Options ───────────────────────────────────────────────────
    p.add_argument("--pkg",     metavar="PACKAGE",
                   help="App package name for Frida attach")
    p.add_argument("--timeout", type=int, default=60,
                   help="Frida observation timeout in seconds (default: 60)")
    p.add_argument("-o", "--output", metavar="DIR", default=".",
                   help="Report output directory (default: current dir)")
    p.add_argument("--force",   action="store_true",
                   help="Force re-decompilation even if output dir exists")
    p.add_argument("--format",
                   choices=["all", "text", "json", "sarif", "pdf"],
                   default="all",
                   help="Report format (default: all)")
    p.add_argument("--severity-filter", metavar="LEVELS",
                   help="Comma-separated severity filter  e.g. CRITICAL,HIGH")
    p.add_argument("--category-filter", metavar="CATS",
                   help="Comma-separated category filter  e.g. Economy,AntiCheat")
    p.add_argument("--host",  default="0.0.0.0",
                   help="Web server host (default: 0.0.0.0)")
    p.add_argument("--port",  type=int, default=5000,
                   help="Web server port (default: 5000)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Enable debug logging")

    return p


def main() -> int:
    if len(sys.argv) == 1:
        print(BANNER)
        build_parser().print_help()
        return 0

    parser = build_parser()
    args   = parser.parse_args()
    log    = get_logger(verbose=args.verbose)

    print(BANNER)

    # ── Parse filters ─────────────────────────────────────────────
    severity_filter: set[str] | None = None
    category_filter: set[str] | None = None

    if args.severity_filter:
        severity_filter = {s.strip().upper() for s in args.severity_filter.split(",")}
        log.info(f"Severity filter: {severity_filter}")

    if args.category_filter:
        category_filter = {s.strip() for s in args.category_filter.split(",")}
        log.info(f"Category filter: {category_filter}")

    # ── Web mode ──────────────────────────────────────────────────
    if args.web:
        try:
            from vengam.web.server import start
            start(host=args.host, port=args.port)
        except ImportError:
            log.error("Web server not available yet (Sprint 4). Install: pip install fastapi uvicorn")
        return 0

    # ── iOS mode ──────────────────────────────────────────────────
    if args.ios:
        try:
            from vengam.ios.static import scan_ipa
            if not args.target:
                log.error("Provide -t MyGame.ipa for iOS scan.")
                return 1
            result = scan_ipa(
                args.target,
                severity_filter=severity_filter,
                category_filter=category_filter,
            )
            return _write_reports(result, args, log)
        except ImportError:
            log.error("iOS module not available yet (Sprint 2).")
            return 1

    # ── Diff mode ─────────────────────────────────────────────────
    if args.diff:
        try:
            from vengam.reports.diff_report import generate_diff
            old_apk, new_apk = args.diff
            generate_diff(old_apk, new_apk, args.output)
        except ImportError:
            log.error("Diff report not available yet (Sprint 5).")
        return 0

    # ── Frida-only mode (no APK) ───────────────────────────────────
    if args.frida and not args.target and not args.dir:
        if not args.pkg:
            log.error("--pkg is required for Frida-only mode. e.g. --pkg com.studio.game")
            return 1
        from vengam.dynamic.frida_runner import run as frida_run
        findings = frida_run(args.pkg, args.timeout)
        for df in findings:
            print(f"  [{df.severity}]  {df.hook_name}")
            for ev in df.evidence:
                print(f"    → {ev}")
        return 0

    # ── Resolve decompiled directory ──────────────────────────────
    apk_path = ""

    if args.target:
        apk_path = args.target.strip("\"'")
        stem     = Path(os.path.basename(apk_path)).stem
        decomp   = os.path.join(os.getcwd(), stem + "_vengam_out")

        from vengam.core.decompiler import check_apktool, decompile_apk
        if not check_apktool():
            return 1

        if not os.path.exists(decomp) or args.force:
            if not decompile_apk(apk_path, decomp, force=args.force):
                return 1
        else:
            log.info(f"Reusing existing decompilation: {decomp}")

        decompiled_dir = decomp

    elif args.dir:
        decompiled_dir = args.dir
        apk_path       = decompiled_dir
        if not os.path.isdir(decompiled_dir):
            log.error(f"Directory not found: {decompiled_dir}")
            return 1
    else:
        log.error("Provide -t <apk> or --dir <directory>")
        parser.print_help()
        return 1

    # ── Static scan ───────────────────────────────────────────────
    from vengam.android.static import scan_directory
    result = scan_directory(
        decompiled_dir, apk_path,
        severity_filter=severity_filter,
        category_filter=category_filter,
    )

    # ── Optional Frida combined ───────────────────────────────────
    if args.frida:
        if not args.pkg:
            log.warning("--pkg not set — skipping Frida dynamic analysis.")
        else:
            from vengam.dynamic.frida_runner import run as frida_run
            result.dynamic_findings = frida_run(args.pkg, args.timeout)
            dyn_score = sum(df.score_value for df in result.dynamic_findings)
            from vengam.core.risk_engine import _verdict
            result.total_score = min(100, result.total_score + dyn_score)
            result.verdict     = _verdict(result.total_score)

    return _write_reports(result, args, log)


def _write_reports(result, args, log) -> int:
    from vengam.reports import text_report, json_report, sarif_report
    from vengam.config import SCORE_BLOCK_RELEASE, SCORE_AT_RISK

    out_dir = args.output
    os.makedirs(out_dir, exist_ok=True)
    stem = Path(result.apk_name).stem or "report"
    fmt  = args.format

    if fmt in ("all", "text"):
        text_report.generate(
            result, os.path.join(out_dir, f"{stem}_vengam_report.txt")
        )
    if fmt in ("all", "json"):
        json_report.generate(
            result, os.path.join(out_dir, f"{stem}_vengam_report.json")
        )
    if fmt in ("all", "sarif"):
        sarif_report.generate(
            result, os.path.join(out_dir, f"{stem}_vengam_report.sarif")
        )
    if fmt == "pdf":
        try:
            from vengam.reports import pdf_report
            pdf_report.generate(
                result, os.path.join(out_dir, f"{stem}_vengam_report.pdf")
            )
        except ImportError:
            log.error("PDF report not available yet (Sprint 5). Install: pip install weasyprint")

    # ── Summary ───────────────────────────────────────────────────
    print()
    print("═" * 64)
    print(f"  SCAN COMPLETE  —  {result.apk_name}")
    print(f"  Platform         : {result.platform.upper()}")
    print(f"  Risk Score       : {result.total_score} / 100")
    print(f"  Verdict          : {result.verdict}")
    print(f"  Static Findings  : {len(result.findings)}")
    print(f"  Dynamic Findings : {len(result.dynamic_findings)}")
    print(f"  FP Suppressed    : {result.engine_stats.fp_suppressed}")
    print(f"  Scan Duration    : {result.engine_stats.scan_duration_sec}s")
    print(f"  Reports saved to : {out_dir}/")
    print("═" * 64)

    # Exit codes:
    # 0 = CONDITIONALLY SAFE
    # 1 = AT RISK (general)
    # 2 = BLOCK RELEASE (critical)
    # 3 = HIGH-only scenario (no critical, but score >= AT_RISK)
    if result.verdict == "BLOCK RELEASE":
        return 2
    crits = len(result.findings_by_severity("CRITICAL"))
    highs = len(result.findings_by_severity("HIGH"))
    if crits == 0 and highs > 0 and result.total_score >= SCORE_AT_RISK:
        return 3
    if result.total_score >= SCORE_AT_RISK:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
