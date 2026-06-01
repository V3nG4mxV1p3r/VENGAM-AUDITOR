"""
VENGAM Auditor — JSON Report Generator
"""
from __future__ import annotations
import json
from vengam.core.models import ScanResult
from vengam.core.risk_engine import derive_business_impacts
from vengam.config import TOOL_NAME, TOOL_VERSION
from vengam.utils.logger import log


def generate(result: ScanResult, out_path: str) -> None:

    def _set_default(obj):
        if isinstance(obj, set):
            return sorted(obj)
        raise TypeError

    payload = {
        "schema_version":  "vengam-v7",
        "tool":            TOOL_NAME,
        "tool_version":    TOOL_VERSION,
        "platform":        result.platform,
        "apk_name":        result.apk_name,
        "apk_sha256":      result.apk_sha256,
        "scan_timestamp":  result.scan_timestamp,
        "risk_score":      result.total_score,
        "verdict":         result.verdict,
        "engine_stats":    result.engine_stats.to_dict(),
        "findings":        [f.to_dict() for f in result.findings],
        "dynamic_findings": [
            {
                "hook_name":   df.hook_name,
                "severity":    df.severity,
                "description": df.description,
                "evidence":    df.evidence,
                "score_value": df.score_value,
            }
            for df in result.dynamic_findings
        ],
        "attack_surface": {
            "auth":         list(result.attack_surface.auth),
            "payment":      list(result.attack_surface.payment),
            "user_data":    list(result.attack_surface.user_data),
            "internal_api": list(result.attack_surface.internal_api),
            "other":        list(result.attack_surface.other),
        },
        "business_impacts": derive_business_impacts(
            result.findings, result.attack_surface
        ),
    }

    with open(out_path, "w", encoding="utf-8") as jf:
        json.dump(payload, jf, indent=2, default=_set_default, ensure_ascii=False)

    log.info(f"JSON report → {out_path}")
