"""
VENGAM — History Router
GET  /api/history          → list all scans
GET  /api/history/{id}     → single scan detail
DELETE /api/history/{id}   → delete scan record
"""
from __future__ import annotations
import json
import os
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from db.database import ScanRecord, get_db

router = APIRouter()


@router.get("")
async def list_scans(
    limit:    int = 20,
    offset:   int = 0,
    platform: str | None = None,
    db:       AsyncSession = Depends(get_db),
):
    stmt = select(ScanRecord).order_by(ScanRecord.scan_timestamp.desc())
    if platform:
        stmt = stmt.where(ScanRecord.platform == platform)
    stmt    = stmt.limit(limit).offset(offset)
    records = (await db.execute(stmt)).scalars().all()

    return {
        "total":  len(records),
        "offset": offset,
        "scans": [
            {
                "id":             r.id,
                "apk_name":       r.apk_name,
                "platform":       r.platform,
                "scan_timestamp": str(r.scan_timestamp),
                "total_score":    r.total_score,
                "verdict":        r.verdict,
                "duration_sec":   r.duration_sec,
            }
            for r in records
        ],
    }


@router.get("/{scan_id}")
async def get_scan_detail(scan_id: str, db: AsyncSession = Depends(get_db)):
    stmt   = select(ScanRecord).where(ScanRecord.id == scan_id)
    record = (await db.execute(stmt)).scalar_one_or_none()
    if not record:
        raise HTTPException(404, "Scan not found")
    return {
        "id":             record.id,
        "apk_name":       record.apk_name,
        "platform":       record.platform,
        "apk_sha256":     record.apk_sha256,
        "scan_timestamp": str(record.scan_timestamp),
        "total_score":    record.total_score,
        "verdict":        record.verdict,
        "duration_sec":   record.duration_sec,
        "findings":       json.loads(record.findings_json or "[]"),
        "report_links": {
            "txt":   f"/api/reports/{record.id}/txt",
            "json":  f"/api/reports/{record.id}/json",
            "sarif": f"/api/reports/{record.id}/sarif",
        },
    }


@router.delete("/{scan_id}")
async def delete_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    stmt   = select(ScanRecord).where(ScanRecord.id == scan_id)
    record = (await db.execute(stmt)).scalar_one_or_none()
    if not record:
        raise HTTPException(404, "Scan not found")

    # Remove report files from disk
    for attr in ("report_txt", "report_json", "report_sarif"):
        path = getattr(record, attr, None)
        if path and os.path.exists(path):
            os.remove(path)

    await db.execute(delete(ScanRecord).where(ScanRecord.id == scan_id))
    await db.commit()
    return {"deleted": scan_id}
