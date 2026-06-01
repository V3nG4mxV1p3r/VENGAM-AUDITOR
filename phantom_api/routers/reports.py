"""
VENGAM — Reports Router v2
PDF desteği eklendi, scan_id bazlı erişim
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from db.database import ScanRecord, get_db

router = APIRouter()

FORMAT_MAP = {
    "txt":   ("report_txt",   "text/plain",                ".txt"),
    "json":  ("report_json",  "application/json",          ".json"),
    "sarif": ("report_sarif", "application/json",          ".sarif"),
    "pdf":   ("report_pdf",   "application/pdf",           ".pdf"),   # ← YENİ
}


@router.get("/{scan_id}/{fmt}")
async def download_report(
    scan_id: str,
    fmt:     str,
    db:      AsyncSession = Depends(get_db),
):
    if fmt not in FORMAT_MAP:
        raise HTTPException(400, f"Bilinmeyen format '{fmt}'. Kullanılabilir: txt, json, sarif, pdf")

    stmt   = select(ScanRecord).where(ScanRecord.id == scan_id)
    record = (await db.execute(stmt)).scalar_one_or_none()
    if not record:
        raise HTTPException(404, "Tarama bulunamadı.")

    attr, media_type, ext = FORMAT_MAP[fmt]
    path = getattr(record, attr, None)

    if not path:
        if fmt == "pdf":
            raise HTTPException(404, "PDF rapor mevcut değil. WeasyPrint kurulu değil olabilir: pip install weasyprint")
        raise HTTPException(404, f"{fmt} raporu bu tarama için mevcut değil.")

    import os
    if not os.path.exists(path):
        raise HTTPException(404, f"Rapor dosyası bulunamadı: {path}")

    return FileResponse(
        path=path,
        media_type=media_type,
        filename=f"{record.apk_name}_{scan_id[:8]}_report{ext}",
    )
