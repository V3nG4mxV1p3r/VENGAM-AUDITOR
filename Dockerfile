# ═══════════════════════════════════════════════════════
# VENGAM Auditor — Dockerfile
# Multi-stage build: builder + runtime
# ═══════════════════════════════════════════════════════

# ── Stage 1: Builder ─────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# System deps for WeasyPrint + apktool
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jre-headless \
    wget \
    curl \
    git \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libcairo2 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    libxml2 \
    libxslt1.1 \
    && rm -rf /var/lib/apt/lists/*

# Download apktool
RUN wget -q https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar \
    -O /usr/local/lib/apktool.jar

# Python deps
COPY pyproject.toml .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir \
       fastapi \
       uvicorn[standard] \
       python-multipart \
       sqlalchemy \
       aiosqlite \
       weasyprint \
       rich \
       && pip install --no-cache-dir -e . 2>/dev/null || true

# ── Stage 2: Runtime ─────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="VENGAM Auditor" \
      org.opencontainers.image.version="7.0.0" \
      org.opencontainers.image.description="Mobile Security Analysis Engine"

# Runtime system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jre-headless \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libcairo2 \
    libgdk-pixbuf2.0-0 \
    libxml2 \
    libxslt1.1 \
    binutils \
    && rm -rf /var/lib/apt/lists/*

# Copy apktool from builder
COPY --from=builder /usr/local/lib/apktool.jar /usr/local/lib/apktool.jar

# Copy Python packages
COPY --from=builder /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY --from=builder /usr/local/bin /usr/local/bin

WORKDIR /app

# Copy source
COPY vengam/        ./vengam/
COPY phantom-api/   ./phantom-api/
COPY frida-scripts/ ./frida-scripts/

# Create dirs
RUN mkdir -p /app/vengam_reports /app/data

# Environment
ENV VENGAM_APKTOOL=/usr/local/lib/apktool.jar \
    VENGAM_REPORTS_DIR=/app/vengam_reports \
    VENGAM_DB=/app/data/vengam_scans.db \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "phantom-api.main:app", "--host", "0.0.0.0", "--port", "8000"]
