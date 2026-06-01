"""
VENGAM Auditor — FastAPI Backend (FINAL)
Tüm router'lar bağlı:
  /api/scan          → APK/IPA tarama
  /api/reports       → Rapor indirme
  /api/history       → Scan geçmişi
  /api/auth          → JWT kimlik doğrulama
  /api/intel         → Attack graph, Frida, IL2CPP
  /api/enterprise    → Multi-tenant, audit log
  /ui                → Web dashboard
"""
from __future__ import annotations
import os
import time
from collections import defaultdict
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from db.database import init_db
from routers import scan, reports, history
from routers import auth as auth_router
from routers import intel as intel_router
from routers import enterprise as enterprise_router

# ── App ───────────────────────────────────────────────────────────
app = FastAPI(
    title="VENGAM Auditor API",
    version="7.0.0",
    description="Mobile Game Security Analysis Engine",
)

# ── CORS ──────────────────────────────────────────────────────────
ALLOWED_ORIGINS = os.environ.get(
    "VENGAM_CORS_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000,"
    "http://localhost:8000,http://127.0.0.1:8000"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
    allow_credentials=False,
)


# ── Security Headers ──────────────────────────────────────────────
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"]        = "DENY"
        response.headers["X-XSS-Protection"]       = "1; mode=block"
        response.headers["Referrer-Policy"]        = "strict-origin-when-cross-origin"
        return response

app.add_middleware(SecurityHeadersMiddleware)


# ── Rate Limiting ─────────────────────────────────────────────────
RATE_LIMITS = {
    "/api/scan":       (3,  60),
    "/api/history":    (30, 60),
    "/api/reports":    (20, 60),
    "/api/auth/login": (10, 60),
}
_rate_store: dict[str, list[float]] = defaultdict(list)


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path      = request.url.path
        client_ip = request.client.host if request.client else "unknown"
        for prefix, (limit, window) in RATE_LIMITS.items():
            if path.startswith(prefix) and request.method in ("POST", "DELETE"):
                key  = f"{client_ip}:{prefix}"
                now  = time.time()
                hits = [t for t in _rate_store[key] if now - t < window]
                hits.append(now)
                _rate_store[key] = hits
                if len(hits) > limit:
                    return JSONResponse(
                        {"detail": f"Rate limit: max {limit} requests/{window}s"},
                        status_code=429,
                        headers={"Retry-After": str(window)},
                    )
                break
        return await call_next(request)

app.add_middleware(RateLimitMiddleware)


# ── Routers ───────────────────────────────────────────────────────
app.include_router(scan.router,            prefix="/api/scan",       tags=["Scan"])
app.include_router(reports.router,         prefix="/api/reports",    tags=["Reports"])
app.include_router(history.router,         prefix="/api/history",    tags=["History"])
app.include_router(auth_router.router,     prefix="/api/auth",       tags=["Auth"])
app.include_router(intel_router.router,    prefix="/api/intel",      tags=["Intel"])
app.include_router(enterprise_router.router, prefix="/api/enterprise", tags=["Enterprise"])


# ── Static UI ─────────────────────────────────────────────────────
_ROOT   = Path(__file__).parent.parent
UI_DIR  = _ROOT / "vengam_ui"
WEB_DIR = _ROOT / "phantom-web" / "dist"   # Build sonrası

# Önce build edilmiş React UI'yi dene, yoksa legacy HTML'i kullan
_static_dir = WEB_DIR if WEB_DIR.exists() else UI_DIR

if _static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")

    @app.get("/ui", response_class=HTMLResponse, include_in_schema=False)
    async def serve_ui():
        # React build varsa index.html, yoksa dashboard.html
        for fname in ["index.html", "dashboard.html"]:
            html_path = _static_dir / fname
            if html_path.exists():
                return HTMLResponse(
                    content=html_path.read_text(encoding="utf-8")
                )
        raise HTTPException(404, "UI dosyası bulunamadı")

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def root():
        return HTMLResponse(
            '<meta http-equiv="refresh" content="0;url=/ui">',
            status_code=302,
        )
else:
    @app.get("/", include_in_schema=False)
    async def root_no_ui():
        return {"message": "VENGAM Auditor API v7.0.0", "docs": "/docs"}


# ── Health & Info ─────────────────────────────────────────────────
@app.get("/api/health", tags=["System"])
async def health():
    return {"status": "ok", "version": "7.0.0"}


@app.get("/api/info", tags=["System"])
async def info():
    try:
        from vengam.patterns.loader import PATTERN_COUNT
        pattern_count = PATTERN_COUNT
    except Exception:
        pattern_count = 0
    try:
        from vengam.plugins.loader import get_plugin_loader
        plugin_count = get_plugin_loader().plugin_count
    except Exception:
        plugin_count = 0
    return {
        "tool":          "VENGAM Auditor",
        "version":       "7.0.0",
        "pattern_count": pattern_count,
        "plugin_count":  plugin_count,
        "platforms":     ["android", "ios"],
        "report_formats":["txt", "json", "sarif", "pdf"],
        "features": [
            "static_analysis", "dynamic_frida", "il2cpp_deep",
            "attack_graph", "endpoint_intel", "plugin_system",
            "jwt_auth", "multi_tenant", "audit_log",
            "diff_scan", "pdf_report", "sarif_report",
        ],
    }


# ── Startup ───────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    await init_db()
    # İlk kullanıcıyı oluştur (yoksa)
    try:
        from auth.jwt_auth import ensure_default_user
        ensure_default_user()
    except Exception:
        pass
    # Plugin'leri yükle
    try:
        from vengam.plugins.loader import get_plugin_loader
        get_plugin_loader()
    except Exception:
        pass


# ── Error Handlers ────────────────────────────────────────────────
@app.exception_handler(429)
async def rate_limited(request, exc):
    return JSONResponse(
        {"detail": "Rate limit aşıldı. Lütfen bekleyin."},
        status_code=429,
        headers={"Retry-After": "60"},
    )

@app.exception_handler(413)
async def too_large(request, exc):
    return JSONResponse(
        {"detail": "Dosya çok büyük (max 500MB)."},
        status_code=413,
    )
