"""
VENGAM — Scan Router FINAL v2
Decompile artık VENGAM/_workspace/ altında yapılır.
Tarama bitince otomatik silinir, depolama şişmez.
"""
from __future__ import annotations
import json
import os
import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, UploadFile, Depends
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Security
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from db.database import ScanRecord, get_db
from vengam.core.decompiler import check_apktool, decompile_apk
from vengam.core.workspace import scan_workspace
from vengam.android.static import scan_directory
from vengam.reports import text_report, json_report, sarif_report
from vengam.utils.logger import log

router          = APIRouter()
bearer          = HTTPBearer(auto_error=False)
REPORTS_DIR     = os.environ.get("VENGAM_REPORTS_DIR", "vengam_reports")
ALLOWED_EXTS    = {".apk", ".ipa"}
ALLOWED_MAGIC   = {b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"}
MAX_SIZE        = 500 * 1024 * 1024
os.makedirs(REPORTS_DIR, exist_ok=True)


def _validate(filename: str, data: bytes) -> None:
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTS:
        raise HTTPException(400, "Sadece .apk ve .ipa dosyaları kabul edilir.")
    if len(data) > MAX_SIZE:
        raise HTTPException(400, "Dosya çok büyük (max 500MB).")
    if len(data) >= 4 and not any(data[:4].startswith(m) for m in ALLOWED_MAGIC):
        raise HTTPException(400, "Geçersiz dosya formatı.")


def _parse_filters(severity, category):
    sev = {s.strip().upper() for s in severity.split(",")} if severity else None
    cat = {c.strip()         for c in category.split(",")} if category else None
    return sev, cat


async def _optional_auth(
    credentials: HTTPAuthorizationCredentials = Security(bearer),
):
    if not credentials:
        return None
    try:
        from auth.jwt_auth import verify_access_token
        return verify_access_token(credentials.credentials)
    except Exception:
        return None


@router.post("/android")
async def scan_android(
    file:            UploadFile = File(...),
    severity_filter: str | None = Form(None),
    category_filter: str | None = Form(None),
    db:              AsyncSession = Depends(get_db),
    _user=Depends(_optional_auth),
):
    scan_id      = str(uuid.uuid4())
    sev_f, cat_f = _parse_filters(severity_filter, category_filter)
    data         = await file.read()
    _validate(file.filename, data)

    # _workspace/android_XXXXXXXX/ altında çalış — bitince otomatik silinir
    with scan_workspace("android") as ws:
        apk_path   = ws / file.filename
        decomp_dir = ws / "decompiled"

        apk_path.write_bytes(data)

        if not check_apktool():
            raise HTTPException(500, "apktool bulunamadı.")
        if not decompile_apk(str(apk_path), str(decomp_dir), force=True):
            raise HTTPException(500, "Decompilation başarısız.")

        result = scan_directory(
            str(decomp_dir), str(apk_path),
            severity_filter=sev_f,
            category_filter=cat_f,
        )

        _run_rule_engine(result, str(decomp_dir))
        _run_plugins(result, str(decomp_dir), "android")
        _run_endpoint_intel(result, str(decomp_dir))
        il2cpp_data = _run_il2cpp(str(decomp_dir))

        return await _save_and_respond(scan_id, result, db, il2cpp_data)
    # with bloğu çıkışında ws otomatik silinir ✓


@router.post("/ios")
async def scan_ios(
    file:            UploadFile = File(...),
    severity_filter: str | None = Form(None),
    category_filter: str | None = Form(None),
    db:              AsyncSession = Depends(get_db),
    _user=Depends(_optional_auth),
):
    scan_id      = str(uuid.uuid4())
    sev_f, cat_f = _parse_filters(severity_filter, category_filter)
    data         = await file.read()
    _validate(file.filename, data)

    with scan_workspace("ios") as ws:
        ipa_path = ws / file.filename
        out_dir  = ws / "extracted"
        ipa_path.write_bytes(data)

        try:
            from vengam.ios.static import scan_ipa
            result = scan_ipa(
                str(ipa_path), output_dir=str(out_dir), force=True,
                severity_filter=sev_f, category_filter=cat_f,
            )
        except Exception as exc:
            raise HTTPException(500, f"iOS scan hatası: {exc}")

        _run_plugins(result, str(out_dir), "ios")
        il2cpp_data = _run_il2cpp(str(out_dir))
        return await _save_and_respond(scan_id, result, db, il2cpp_data)


@router.get("/{scan_id}")
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    stmt   = select(ScanRecord).where(ScanRecord.id == scan_id)
    record = (await db.execute(stmt)).scalar_one_or_none()
    if not record:
        raise HTTPException(404, "Tarama bulunamadı.")
    return {
        "id":             record.id,
        "apk_name":       record.apk_name,
        "platform":       record.platform,
        "scan_timestamp": str(record.scan_timestamp),
        "total_score":    record.total_score,
        "verdict":        record.verdict,
        "findings":       json.loads(record.findings_json or "[]"),
    }


# ── Pipeline yardımcıları ─────────────────────────────────────────

def _run_rule_engine(result, decomp_dir: str) -> None:
    try:
        from vengam.core.rule_engine import get_rule_engine
        from vengam.core.models import Finding, FindingLocation
        engine = get_rule_engine()
        if engine.rule_count == 0:
            return
        base      = Path(decomp_dir)
        SCAN_EXTS = {".smali", ".java", ".kt", ".xml", ".json", ".properties"}
        rule_findings: dict[str, Finding] = {}

        for filepath in base.rglob("*"):
            if not filepath.is_file():
                continue
            if filepath.suffix.lower() not in SCAN_EXTS:
                continue
            try:
                lines = filepath.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            rel = str(filepath.relative_to(base))
            for line_no, line in enumerate(lines, 1):
                for m in engine.match_line(line, rel, line_no):
                    rid = m.rule.id
                    if rid not in rule_findings:
                        rule_findings[rid] = Finding(
                            title=m.rule.title, severity=m.rule.severity,
                            confidence=m.rule.confidence,
                            exploitability="LIKELY",
                            secret_type=m.rule.category,
                            description=m.rule.description,
                            simulation=m.rule.simulation,
                            score_value=m.rule.score_value,
                            category=m.rule.category,
                            triage_note=m.rule.triage_note,
                            cwe_id=m.rule.cwe_id,
                            owasp_ref=m.rule.owasp_ref,
                        )
                    if len(rule_findings[rid].locations) < 5:
                        rule_findings[rid].locations.append(
                            FindingLocation(
                                file=rel, line=line_no,
                                snippet=line.strip()[:100],
                                redacted_match=m.matched_text[:40],
                            )
                        )
        existing = {f.title for f in result.findings}
        for f in rule_findings.values():
            if f.title not in existing:
                result.findings.append(f)
    except Exception as e:
        log.warning(f"Rule engine atlandı: {e}")


def _run_plugins(result, decomp_dir: str, platform: str) -> None:
    try:
        from vengam.plugins.loader import get_plugin_loader
        loader = get_plugin_loader()
        if loader.scanner_count == 0:
            return
        existing = {f.title for f in result.findings}
        for pr in loader.run_scanners(decomp_dir, platform):
            if pr.success:
                for f in pr.findings:
                    if f.title not in existing:
                        result.findings.append(f)
                        existing.add(f.title)
    except Exception as e:
        log.warning(f"Plugin atlandı: {e}")


def _run_endpoint_intel(result, decomp_dir: str) -> None:
    try:
        from vengam.intel.endpoint import EndpointAnalyzer
        intel = EndpointAnalyzer().analyze_directory(decomp_dir)
        for ep in intel.endpoints:
            cat = ep.category
            if cat == "auth":          result.attack_surface.auth.add(ep.url)
            elif cat == "payment":     result.attack_surface.payment.add(ep.url)
            elif cat == "user_data":   result.attack_surface.user_data.add(ep.url)
            elif cat in ("api","graphql"): result.attack_surface.internal_api.add(ep.url)
            else:                      result.attack_surface.other.add(ep.url)
        for ws in intel.websockets:
            result.attack_surface.other.add(ws.url)
    except Exception as e:
        log.warning(f"Endpoint intel atlandı: {e}")


def _run_il2cpp(decomp_dir: str) -> dict | None:
    try:
        from vengam.intel.il2cpp_deep import find_and_analyze
        analysis = find_and_analyze(decomp_dir)
        if not analysis:
            return None
        return {
            "version":       analysis.version,
            "class_count":   analysis.class_count,
            "method_count":  analysis.method_count,
            "string_count":  analysis.string_count,
            "security_hits": [
                {"category": h.category, "severity": h.severity,
                 "name": h.name, "context": h.context,
                 "frida_hook": h.frida_hook, "score": h.score}
                for h in analysis.security_hits
            ],
            "classes": [
                {"name": c.name, "namespace": c.namespace,
                 "methods": [{"name": m.name, "class_name": m.class_name}
                              for m in c.methods[:20]]}
                for c in analysis.classes[:100]
            ],
            "raw_strings": analysis.raw_strings[:200],
        }
    except Exception as e:
        log.warning(f"IL2CPP atlandı: {e}")
        return None


async def _save_and_respond(scan_id, result, db, il2cpp_data=None) -> JSONResponse:
    stem     = Path(result.apk_name).stem
    scan_dir = os.path.join(REPORTS_DIR, scan_id)
    os.makedirs(scan_dir, exist_ok=True)

    txt_path  = os.path.join(scan_dir, f"{stem}_report.txt")
    json_path = os.path.join(scan_dir, f"{stem}_report.json")
    sar_path  = os.path.join(scan_dir, f"{stem}_report.sarif")

    text_report.generate(result,  txt_path)
    json_report.generate(result,  json_path)
    sarif_report.generate(result, sar_path)

    if il2cpp_data:
        try:
            d = json.loads(Path(json_path).read_text())
            d["il2cpp_analysis"] = il2cpp_data
            Path(json_path).write_text(json.dumps(d, ensure_ascii=False, indent=2))
        except Exception:
            pass

    pdf_path = None
    try:
        from vengam.reports import pdf_report
        pdf_path = os.path.join(scan_dir, f"{stem}_report.pdf")
        pdf_report.generate(result, pdf_path)
    except Exception:
        pdf_path = None

    record = ScanRecord(
        id=scan_id, apk_name=result.apk_name, platform=result.platform,
        apk_sha256=result.apk_sha256, total_score=result.total_score,
        verdict=result.verdict,
        findings_json=json.dumps([f.to_dict() for f in result.findings], ensure_ascii=False),
        report_txt=txt_path, report_json=json_path,
        report_sarif=sar_path, report_pdf=pdf_path,
        duration_sec=result.engine_stats.scan_duration_sec,
    )
    db.add(record)
    await db.commit()

    report_links = {
        "txt":   f"/api/reports/{scan_id}/txt",
        "json":  f"/api/reports/{scan_id}/json",
        "sarif": f"/api/reports/{scan_id}/sarif",
    }
    if pdf_path:
        report_links["pdf"] = f"/api/reports/{scan_id}/pdf"

    return JSONResponse({
        "scan_id":       scan_id,
        "apk_name":      result.apk_name,
        "platform":      result.platform,
        "risk_score":    result.total_score,
        "verdict":       result.verdict,
        "findings":      [f.to_dict() for f in result.findings],
        "attack_surface": {
            "auth":         list(result.attack_surface.auth),
            "payment":      list(result.attack_surface.payment),
            "user_data":    list(result.attack_surface.user_data),
            "internal_api": list(result.attack_surface.internal_api),
            "other":        list(result.attack_surface.other),
        },
        "engine_stats":  result.engine_stats.to_dict(),
        "report_links":  report_links,
        "il2cpp_available": il2cpp_data is not None,
    })
