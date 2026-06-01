"""
VENGAM Auditor — Pattern Loader
Compiles all pattern lists into COMPILED_PATTERNS with pre-built regex objects.
"""
from __future__ import annotations
import re
from vengam.patterns.general import GENERAL_PATTERNS
from vengam.patterns.game_engine import GAME_ENGINE_PATTERNS
from vengam.patterns.economy_anticheat_config import (
    ECONOMY_PATTERNS,
    ANTICHEAT_PATTERNS,
    CONFIG_PATTERNS,
)

ALL_PATTERNS: list[dict] = (
    GENERAL_PATTERNS
    + GAME_ENGINE_PATTERNS
    + ECONOMY_PATTERNS
    + ANTICHEAT_PATTERNS
    + CONFIG_PATTERNS
)

# Pre-compile all regexes once at import time
COMPILED_PATTERNS: list[dict] = [
    {**p, "_re": re.compile(p["regex"])} for p in ALL_PATTERNS
]

PATTERN_COUNT = len(COMPILED_PATTERNS)
