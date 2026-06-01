"""
VENGAM — Intel Router
GET /api/intel/attack-graph/{scan_id}
GET /api/intel/frida/{scan_id}
GET /api/intel/il2cpp/{scan_id}
GET /api/plugins
"""
from __future__ import annotations
import json
import os
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from db.database import ScanRecord, get_db
from auth.jwt_auth import verify_access_token, TokenData
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Security

router = APIRouter()
bearer = HTTPBearer(auto_error=False)

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(bearer),
) -> TokenData:
    if not credentials:
        raise HTTPException(401, "Authentication required")
    data = verify_access_token(credentials.credentials)
    if not data:
        raise HTTPException(401, "Invalid or expired token")
    return data


@router.get("/attack-graph/{scan_id}")
async def get_attack_graph(
    scan_id: str,
    db:      AsyncSession = Depends(get_db),
    _user:   TokenData    = Depends(get_current_user),
):
    stmt   = select(ScanRecord).where(ScanRecord.id == scan_id)
    record = (await db.execute(stmt)).scalar_one_or_none()
    if not record:
        raise HTTPException(404, "Scan not found")

    try:
        from vengam.intel.attack_graph import AttackGraphBuilder
        from vengam.intel.endpoint import EndpointAnalyzer
        from vengam.core.models import AttackSurface, Finding
        findings_raw = json.loads(record.findings_json or "[]")
        findings = []
        for fr in findings_raw:
            try:
                f = Finding(
                    title=fr.get("title",""), severity=fr.get("severity","LOW"),
                    confidence=fr.get("confidence","LOW"),
                    exploitability=fr.get("exploitability","THEORETICAL"),
                    secret_type=fr.get("secret_type",""),
                    description=fr.get("description",""),
                    simulation=fr.get("simulation",""),
                    score_value=fr.get("score_value",5),
                    category=fr.get("category","General"),
                    triage_note=fr.get("triage_note",""),
                )
                findings.append(f)
            except Exception:
                continue

        surface = AttackSurface()
        builder = AttackGraphBuilder()
        graph   = builder.build(record.apk_name, findings, surface)
        return JSONResponse(graph.to_d3())

    except Exception as exc:
        raise HTTPException(500, f"Attack graph error: {exc}")


@router.get("/frida/{scan_id}")
async def get_frida_script(
    scan_id: str,
    mode:    str = "auto",
    db:      AsyncSession = Depends(get_db),
    _user:   TokenData    = Depends(get_current_user),
):
    stmt   = select(ScanRecord).where(ScanRecord.id == scan_id)
    record = (await db.execute(stmt)).scalar_one_or_none()
    if not record:
        raise HTTPException(404, "Scan not found")

    try:
        from vengam.intel.frida_gen import FridaHookGenerator
        from vengam.core.models import Finding
        findings_raw = json.loads(record.findings_json or "[]")
        findings = [
            Finding(
                title=fr.get("title",""), severity=fr.get("severity","LOW"),
                confidence="LOW", exploitability="THEORETICAL",
                secret_type="", description="", simulation="",
                score_value=5, category=fr.get("category","General"),
            )
            for fr in findings_raw
        ]
        gen = FridaHookGenerator()
        if mode == "full":
            script = gen.generate_full(record.apk_name)
        else:
            script = gen.generate_from_findings(findings, record.apk_name)

        return JSONResponse({"scan_id": scan_id, "mode": mode, "script": script})

    except Exception as exc:
        raise HTTPException(500, f"Frida gen error: {exc}")


@router.get("/il2cpp/{scan_id}")
async def get_il2cpp(
    scan_id: str,
    db:      AsyncSession = Depends(get_db),
    _user:   TokenData    = Depends(get_current_user),
):
    stmt   = select(ScanRecord).where(ScanRecord.id == scan_id)
    record = (await db.execute(stmt)).scalar_one_or_none()
    if not record:
        raise HTTPException(404, "Scan not found")

    reports_dir = os.environ.get("VENGAM_REPORTS_DIR", "vengam_reports")
    scan_dir    = Path(reports_dir) / scan_id
    json_path   = scan_dir / f"{Path(record.apk_name).stem}_report.json"

    if not json_path.exists():
        return JSONResponse(None)

    try:
        data = json.loads(json_path.read_text())
        il2cpp = data.get("il2cpp_analysis")
        return JSONResponse(il2cpp)
    except Exception:
        return JSONResponse(None)


@router.get("/plugins")
async def list_plugins(
    _user: TokenData = Depends(get_current_user),
):
    try:
        from vengam.plugins.loader import get_plugin_loader
        loader  = get_plugin_loader()
        plugins = loader.list_plugins()
        return JSONResponse(plugins)
    except Exception:
        return JSONResponse([])
