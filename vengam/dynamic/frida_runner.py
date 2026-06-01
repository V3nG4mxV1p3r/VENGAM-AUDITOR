"""
VENGAM Auditor — Frida Dynamic Analysis Runner
"""
from __future__ import annotations
import threading
import time
from pathlib import Path
from vengam.core.models import DynamicFinding
from vengam.config import FRIDA_SCRIPTS_DIR
from vengam.utils.logger import log


def _load_script() -> str:
    path = FRIDA_SCRIPTS_DIR / "android-hooks.js"
    if path.exists():
        return path.read_text(encoding="utf-8")
    log.warning("frida-scripts/android-hooks.js not found — using built-in stub.")
    return "send({tag:'VENGAM',msg:'Frida stub loaded — no hook script found'});"


def run(package_name: str, timeout: int = 60) -> list[DynamicFinding]:
    try:
        import frida
    except ImportError:
        log.error("Frida not installed. Run: pip install frida frida-tools")
        return []

    log.info(f"=== FRIDA DYNAMIC ANALYSIS  [{package_name}] ===")
    log.info(f"Timeout: {timeout}s — ensure frida-server is running on device.")

    events: list[dict] = []

    def on_message(message, _data):
        if message.get("type") == "send":
            payload = message.get("payload", {})
            events.append(payload)
            log.debug(f"[{payload.get('tag','?')}] {payload.get('msg','')}")

    try:
        device  = frida.get_usb_device(timeout=10)
        session = device.attach(package_name)
        script  = session.create_script(_load_script())
        script.on("message", on_message)
        script.load()
        log.info(f"Hooked into {package_name}. Collecting for {timeout}s …")
        time.sleep(timeout)
        script.unload()
        session.detach()
    except Exception as exc:
        log.error(f"Frida error: {exc}")
        return []

    return _analyse(events)


# ── Event → DynamicFinding map ────────────────────────────────────────────────

_TAG_MAP: dict[str, dict] = {
    "SSL_PINNING": dict(
        hook_name="SSL Pinning Active", severity="INFO",
        description="Certificate pinning is implemented.", score_value=0,
    ),
    "ROOT_CHECK": dict(
        hook_name="Root Detection Active", severity="INFO",
        description="Root/integrity checks intercepted by Frida.", score_value=0,
    ),
    "IAP": dict(
        hook_name="IAP Flow Observed", severity="INFO",
        description="BillingClient purchase flow observed at runtime.", score_value=0,
    ),
    "IAP_VALIDATION": dict(
        hook_name="Receipt Validation Observed", severity="MEDIUM",
        description="Receipt validation method called — verify server-side enforcement.", score_value=10,
    ),
    "CRYPTO_HARDCODED_KEY": dict(
        hook_name="Hardcoded Crypto Key (Runtime Confirmed)", severity="CRITICAL",
        description=(
            "SecretKeySpec constructed from hardcoded byte array at runtime. "
            "Confirms a hardcoded encryption key in active use."
        ),
        score_value=30,
    ),
    "CRYPTO": dict(
        hook_name="Cipher Operation Observed", severity="INFO",
        description="Cipher.init() called during runtime. Review algorithm and key source.", score_value=0,
    ),
    "NATIVE": dict(
        hook_name="Native Library Loaded", severity="INFO",
        description="Game engine native library detected.", score_value=0,
    ),
    "SHARED_PREFS_SECRET": dict(
        hook_name="Secret in SharedPreferences (Runtime)", severity="HIGH",
        description=(
            "A token/key/auth value was read from SharedPreferences at runtime. "
            "SharedPreferences is not encrypted by default."
        ),
        score_value=20,
    ),
    "WEBVIEW_JS_INTERFACE": dict(
        hook_name="WebView JavaScript Interface Exposed", severity="MEDIUM",
        description=(
            "addJavascriptInterface() called — JS code can invoke native Android methods. "
            "Risk: XSS → RCE if WebView loads untrusted content."
        ),
        score_value=15,
    ),
}


def _analyse(events: list[dict]) -> list[DynamicFinding]:
    findings: dict[str, DynamicFinding] = {}

    for event in events:
        tag = event.get("tag", "UNKNOWN")
        msg = event.get("msg", "")

        if tag in findings:
            findings[tag].evidence.append(msg)
        elif tag in _TAG_MAP:
            info = _TAG_MAP[tag]
            findings[tag] = DynamicFinding(
                hook_name=info["hook_name"],
                severity=info["severity"],
                description=info["description"],
                evidence=[msg],
                score_value=info["score_value"],
            )
        else:
            if tag not in findings:
                findings[tag] = DynamicFinding(
                    hook_name=f"Unknown Hook: {tag}",
                    severity="INFO",
                    description=msg,
                    score_value=0,
                )
            else:
                findings[tag].evidence.append(msg)

    return list(findings.values())
