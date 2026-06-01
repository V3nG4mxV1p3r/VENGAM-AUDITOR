"""
VENGAM — Cryptographic helpers & secret redaction
"""
from __future__ import annotations
import hashlib


def redact_secret(s: str) -> str:
    """Return first4****last4 representation — never expose full secret in reports."""
    if len(s) <= 10:
        return "***REDACTED***"
    return s[:4] + "*" * (len(s) - 8) + s[-4:]


def sha256_file(path: str) -> str:
    """Return hex SHA-256 of a file, or 'N/A' on error."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return "N/A"


def sha256_string(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()
