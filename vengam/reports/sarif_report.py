"""
VENGAM Auditor — SARIF 2.1.0 Report Generator
SARIF = Static Analysis Results Interchange Format (GitHub Code Scanning compatible)
"""
from __future__ import annotations
import json
import re
from vengam.core.models import ScanResult
from vengam.config import TOOL_NAME, TOOL_VERSION
from vengam.utils.logger import log

_SEV_MAP   = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
_SCORE_MAP = {"CRITICAL": 9.8, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0}


def generate(result: ScanResult, out_path: str) -> None:
    rules: list[dict]   = []
    results: list[dict] = []
    seen: set[str]      = set()

    for f in result.findings:
        rid = re.sub(r"[^A-Za-z0-9]", "", f.title)[:32]

        if rid not in seen:
            seen.add(rid)
            rules.append({
                "id":   rid,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription":  {"text": f.description},
                "defaultConfiguration": {
                    "level": _SEV_MAP.get(f.severity, "warning")
                },
                "properties": {
                    "tags":              ["security", f.category.lower()],
                    "precision":         f.confidence.lower(),
                    "security-severity": str(_SCORE_MAP.get(f.severity, 1.0)),
                },
            })

        for loc in f.locations:
            results.append({
                "ruleId": rid,
                "level":  _SEV_MAP.get(f.severity, "warning"),
                "message": {
                    "text": f"{f.description} | {f.simulation}"
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": loc.file.replace("\\", "/")
                        },
                        "region": {"startLine": loc.line},
                    }
                }],
            })

    sarif = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec"
            "/master/Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name":           TOOL_NAME,
                    "version":        TOOL_VERSION,
                    "informationUri": "https://github.com/vengam/gamesec",
                    "rules":          rules,
                }
            },
            "results": results,
        }],
    }

    with open(out_path, "w", encoding="utf-8") as sf:
        json.dump(sarif, sf, indent=2, ensure_ascii=False)

    log.info(f"SARIF report → {out_path}")
