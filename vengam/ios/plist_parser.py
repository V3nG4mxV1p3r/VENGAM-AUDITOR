"""
VENGAM Auditor — iOS Plist Parser
Parses Info.plist and extracts security-relevant configuration.
"""
from __future__ import annotations
import plistlib
import subprocess
from pathlib import Path
from typing import Any
from vengam.utils.logger import log


def parse_plist(plist_path: str) -> dict:
    """
    Parse an Info.plist file. Handles both binary and XML formats.
    Returns empty dict on failure.
    """
    path = Path(plist_path)
    if not path.exists():
        log.warning(f"plist not found: {plist_path}")
        return {}

    # Try native plistlib first (XML plist)
    try:
        with open(plist_path, "rb") as f:
            return plistlib.load(f)
    except Exception:
        pass

    # Binary plist — try plutil conversion (macOS/Linux with libplist)
    try:
        result = subprocess.run(
            ["plutil", "-convert", "xml1", "-o", "-", plist_path],
            capture_output=True, timeout=10,
        )
        if result.returncode == 0:
            return plistlib.loads(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Try plistutil (Linux)
    try:
        result = subprocess.run(
            ["plistutil", "-i", plist_path, "-f", "xml"],
            capture_output=True, timeout=10,
        )
        if result.returncode == 0:
            return plistlib.loads(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    log.warning(f"Could not parse plist (binary format, no plutil/plistutil): {plist_path}")
    return {}


def extract_security_config(info: dict) -> dict:
    """
    Extract security-relevant keys from a parsed Info.plist dict.
    Returns a flat dict of findings-relevant values.
    """
    out: dict[str, Any] = {}

    # App Transport Security
    ats = info.get("NSAppTransportSecurity", {})
    out["ats_allows_arbitrary_loads"]              = ats.get("NSAllowsArbitraryLoads", False)
    out["ats_allows_arbitrary_loads_in_webview"]   = ats.get("NSAllowsArbitraryLoadsInWebContent", False)
    out["ats_allows_local_networking"]             = ats.get("NSAllowsLocalNetworking", False)
    out["ats_exception_domains"]                   = list(ats.get("NSExceptionDomains", {}).keys())

    # Permissions — privacy-sensitive
    permission_keys = [
        "NSCameraUsageDescription",
        "NSMicrophoneUsageDescription",
        "NSLocationWhenInUseUsageDescription",
        "NSLocationAlwaysUsageDescription",
        "NSContactsUsageDescription",
        "NSPhotoLibraryUsageDescription",
        "NSFaceIDUsageDescription",
        "NSBluetoothAlwaysUsageDescription",
    ]
    out["permissions"] = {k: info.get(k, None) for k in permission_keys if k in info}

    # Exported URL schemes (deep link attack surface)
    url_types = info.get("CFBundleURLTypes", [])
    out["url_schemes"] = []
    for ut in url_types:
        schemes = ut.get("CFBundleURLSchemes", [])
        out["url_schemes"].extend(schemes)

    # Queried URL schemes (what apps the game probes for)
    out["queried_url_schemes"] = info.get("LSApplicationQueriesSchemes", [])

    # Core identity
    out["bundle_id"]      = info.get("CFBundleIdentifier", "")
    out["bundle_version"] = info.get("CFBundleShortVersionString", "")
    out["min_ios"]        = info.get("MinimumOSVersion", "")
    out["executable"]     = info.get("CFBundleExecutable", "")

    # Background modes (persistence risk)
    out["background_modes"] = info.get("UIBackgroundModes", [])

    # App uses encrypted exports declaration
    out["uses_encryption"] = info.get("ITSAppUsesNonExemptEncryption", None)

    return out


def analyse_plist_security(plist_path: str) -> list[dict]:
    """
    Full security analysis of Info.plist.
    Returns list of raw finding dicts (title, severity, description, evidence).
    """
    info     = parse_plist(plist_path)
    if not info:
        return []

    config   = extract_security_config(info)
    findings = []

    # ── ATS: NSAllowsArbitraryLoads ──────────────────────────────
    if config.get("ats_allows_arbitrary_loads"):
        findings.append({
            "title":       "ATS NSAllowsArbitraryLoads Enabled",
            "severity":    "HIGH",
            "confidence":  "HIGH",
            "exploitability": "CONFIRMED",
            "secret_type": "Network Security Misconfiguration",
            "description": (
                "NSAllowsArbitraryLoads=true disables Apple's App Transport Security globally. "
                "All HTTP connections are permitted, enabling cleartext credential transmission."
            ),
            "simulation":  (
                "Attacker performs MITM on the local network. "
                "Unencrypted API responses expose player tokens and game state."
            ),
            "score_value": 25,
            "cwe_id":      "CWE-319",
            "owasp_ref":   "M3: Insecure Communication",
            "category":    "Config",
            "triage_note": (
                "Remove NSAllowsArbitraryLoads. Use NSExceptionDomains for specific CDN domains "
                "that genuinely require HTTP."
            ),
            "evidence":    "NSAllowsArbitraryLoads = true in Info.plist",
        })

    # ── ATS: WebView arbitrary loads ─────────────────────────────
    if config.get("ats_allows_arbitrary_loads_in_webview"):
        findings.append({
            "title":       "ATS NSAllowsArbitraryLoadsInWebContent Enabled",
            "severity":    "MEDIUM",
            "confidence":  "HIGH",
            "exploitability": "LIKELY",
            "secret_type": "Network Security Misconfiguration",
            "description": (
                "NSAllowsArbitraryLoadsInWebContent=true allows WebView components to load "
                "HTTP content, enabling mixed-content XSS attacks."
            ),
            "simulation":  (
                "Attacker injects malicious JS via a loaded HTTP resource in a WebView, "
                "stealing session tokens or triggering native bridge calls."
            ),
            "score_value": 15,
            "cwe_id":      "CWE-319",
            "owasp_ref":   "M3: Insecure Communication",
            "category":    "Config",
            "triage_note": "Restrict WebView to HTTPS-only sources. Review all addJavascriptInterface calls.",
            "evidence":    "NSAllowsArbitraryLoadsInWebContent = true in Info.plist",
        })

    # ── ATS exception domains (info only) ────────────────────────
    if config.get("ats_exception_domains"):
        findings.append({
            "title":       "ATS Exception Domains Declared",
            "severity":    "INFO",
            "confidence":  "HIGH",
            "exploitability": "THEORETICAL",
            "secret_type": "Network Security Configuration",
            "description": (
                f"ATS exception domains declared: "
                f"{', '.join(config['ats_exception_domains'][:5])}. "
                "Review whether each domain truly requires an ATS exception."
            ),
            "simulation":  "Attacker targets excepted domain for MITM if TLSMinimumSupportedVersion is weak.",
            "score_value": 3,
            "cwe_id":      "CWE-326",
            "owasp_ref":   "M3: Insecure Communication",
            "category":    "Config",
            "triage_note": "Audit each exception domain. Prefer NSRequiresCertificateTransparency=true.",
            "evidence":    f"Domains: {config['ats_exception_domains']}",
        })

    # ── FaceID/Biometric declared ────────────────────────────────
    if "NSFaceIDUsageDescription" in config.get("permissions", {}):
        findings.append({
            "title":       "FaceID / Biometric Usage Declared",
            "severity":    "INFO",
            "confidence":  "HIGH",
            "exploitability": "THEORETICAL",
            "secret_type": "Biometric Access",
            "description": (
                "App declares NSFaceIDUsageDescription — biometric authentication is in use. "
                "Verify LocalAuthentication fallback to passcode is handled securely."
            ),
            "simulation":  "Attacker bypasses biometric via LAPolicy fallback or Frida hook on LocalAuthentication.",
            "score_value": 3,
            "cwe_id":      "CWE-308",
            "owasp_ref":   "M4: Insecure Authentication",
            "category":    "Config",
            "triage_note": (
                "Ensure LAContext.evaluatePolicy uses .deviceOwnerAuthenticationWithBiometrics "
                "and does not silently fall back to passcode for sensitive operations."
            ),
            "evidence":    info.get("NSFaceIDUsageDescription", ""),
        })

    # ── Custom URL schemes ────────────────────────────────────────
    if config.get("url_schemes"):
        findings.append({
            "title":       "Custom URL Schemes Registered",
            "severity":    "MEDIUM",
            "confidence":  "HIGH",
            "exploitability": "LIKELY",
            "secret_type": "Deep Link Attack Surface",
            "description": (
                f"Custom URL schemes registered: {', '.join(config['url_schemes'])}. "
                "Unvalidated deep link parameters can trigger unintended actions."
            ),
            "simulation":  (
                "Attacker crafts a malicious URL (e.g. myscheme://admin?token=X) and "
                "tricks the user into tapping it, triggering privileged in-app navigation."
            ),
            "score_value": 10,
            "cwe_id":      "CWE-601",
            "owasp_ref":   "M1: Improper Platform Usage",
            "category":    "Config",
            "triage_note": (
                "Validate all URL scheme parameters server-side. "
                "Prefer Universal Links (HTTPS) over custom schemes."
            ),
            "evidence":    f"URL schemes: {config['url_schemes']}",
        })

    # ── Background modes ─────────────────────────────────────────
    dangerous_bg = {"fetch", "remote-notification", "processing", "voip"}
    active_bg = dangerous_bg & set(config.get("background_modes", []))
    if active_bg:
        findings.append({
            "title":       "Background Execution Modes Enabled",
            "severity":    "LOW",
            "confidence":  "HIGH",
            "exploitability": "THEORETICAL",
            "secret_type": "Persistence / Battery Drain Risk",
            "description": (
                f"Background modes active: {', '.join(active_bg)}. "
                "Game may execute code in the background beyond gameplay needs."
            ),
            "simulation":  (
                "Attacker triggers background fetch with crafted push notification "
                "to force token refresh and exfiltrate it via a rogue network call."
            ),
            "score_value": 5,
            "cwe_id":      "CWE-200",
            "owasp_ref":   "M1: Improper Platform Usage",
            "category":    "Config",
            "triage_note": "Disable background modes that are not essential for gameplay.",
            "evidence":    f"UIBackgroundModes: {list(active_bg)}",
        })

    return findings
