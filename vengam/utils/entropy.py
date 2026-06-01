"""
VENGAM — Shannon entropy & string classification utilities
"""
from __future__ import annotations
import base64
import math
import re
from collections import Counter


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy (bits per character)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def is_alphabet_string(s: str) -> bool:
    """
    True if the string looks like a Base62/64 character alphabet definition
    (e.g. 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789').
    These are benign constants, not secrets.
    """
    if len(s) < 60 or len(s) > 70:
        return False
    return len(set(s)) >= 55


def classify_high_entropy_string(s: str) -> tuple[str, str]:
    """
    Returns (secret_type, simulation_text) based on string characteristics.
    Used when entropy threshold is exceeded but no pattern matched.
    """
    if re.match(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$", s):
        return (
            "JWT",
            "Attacker replays token against auth endpoints; attempts alg=none privilege escalation.",
        )
    if re.match(r"^[0-9a-fA-F]{32,}$", s):
        return (
            "Hex-Encoded Crypto Asset",
            "Attacker reuses static key material against the backend API.",
        )
    if re.match(r"^[A-Za-z0-9+/=]+$", s):
        try:
            if base64.b64decode(s + "=="):
                return (
                    "Base64-Obfuscated Asset",
                    "Attacker decodes to uncover hidden API routes or credentials.",
                )
        except Exception:
            pass
    return (
        "High-Entropy Unknown Asset",
        "Attacker probes backend routes using the extracted string as bearer or seed material.",
    )
