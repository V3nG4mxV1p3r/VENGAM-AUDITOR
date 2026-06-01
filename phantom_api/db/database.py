"""
VENGAM — Database (SQLite via SQLAlchemy async)
Güncelleme: report_pdf alanı eklendi
"""
from __future__ import annotations
import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import Column, String, Integer, Float, Text, DateTime
import datetime

DB_PATH     = os.environ.get("VENGAM_DB", "vengam_scans.db")
DATABASE_URL= f"sqlite+aiosqlite:///{DB_PATH}"

engine            = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base              = declarative_base()


class ScanRecord(Base):
    __tablename__ = "scans"

    id             = Column(String,  primary_key=True)
    apk_name       = Column(String,  nullable=False)
    platform       = Column(String,  default="android")
    apk_sha256     = Column(String)
    scan_timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    total_score    = Column(Integer,  default=0)
    verdict        = Column(String)
    findings_json  = Column(Text)
    report_txt     = Column(String)
    report_json    = Column(String)
    report_sarif   = Column(String)
    report_pdf     = Column(String)   # ← YENİ
    duration_sec   = Column(Float,    default=0.0)


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
