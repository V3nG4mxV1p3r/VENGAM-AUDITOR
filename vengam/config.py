"""
VENGAM Auditor — Global Configuration
"""
from __future__ import annotations
import os
from pathlib import Path

# ── Tool identity ─────────────────────────────────────────────────────────────
TOOL_NAME    = "VENGAM Auditor"
TOOL_VERSION = "7.0.0"
SCHEMA_VER   = "vengam-v7"

# ── Severity / ordering ───────────────────────────────────────────────────────
SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
    "INFO":     0,
}

ALL_SEVERITIES = list(SEVERITY_ORDER.keys())

# ── apktool path (override via VENGAM_APKTOOL env var) ───────────────────────
APKTOOL_PATH: str = os.environ.get(
    "VENGAM_APKTOOL",
    r"C:\apktool\apktool.jar",   # Windows default — change for Linux/Mac
)

# ── File scanning ─────────────────────────────────────────────────────────────
SCANNABLE_EXTENSIONS: frozenset[str] = frozenset({
    ".xml", ".smali", ".txt", ".json", ".properties",
    ".gradle", ".kt", ".java", ".yaml", ".yml",
    ".config", ".env", ".ini", ".plist",
})

NOISE_DOMAINS: frozenset[str] = frozenset({
    "w3.org", "schemas.android.com", "example.com", "localhost",
    "127.0.0.1", "google.com", "android.com", "goo.gl",
    "play.google.com", "schema.org", "xmlpull.org",
    "ns.adobe.com", "purl.org",
})

NOISE_EXTENSIONS: frozenset[str] = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
    ".ico", ".js", ".css", ".woff", ".ttf", ".otf",
    ".mp3", ".ogg", ".wav", ".mp4", ".avi", ".zip", ".so",
})

IGNORE_FILE_FRAGMENTS: frozenset[str] = frozenset({
    "EmojiCompat", "ComponentActivity", "MapBuilder",
    "WebViewMediaIntegrity", "BuildConfig", "R.smali",
    "Manifest.smali", "BR.smali", "DataBinderMapper",
})

# ── Risk thresholds ───────────────────────────────────────────────────────────
SCORE_BLOCK_RELEASE      = 75   # exit code 2
SCORE_AT_RISK            = 40   # exit code 3 (HIGH-only) or 1
SCORE_CONDITIONALLY_SAFE = 0

# ── Report defaults ───────────────────────────────────────────────────────────
MAX_LOCATIONS_PER_FINDING = 5
SNIPPET_MAX_LEN           = 120

# ── Paths ─────────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.parent
FRIDA_SCRIPTS_DIR = PROJECT_ROOT / "frida-scripts"
