"""
VENGAM Auditor — Mach-O Binary Wrapper
Extracts strings, symbols, and security properties from iOS Mach-O binaries
using available system tools (strings, otool, jtool2, nm).
No native binary parsing library required.
"""
from __future__ import annotations
import re
import subprocess
import shutil
from pathlib import Path
from vengam.utils.logger import log


# ── Tool availability check ───────────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = 30) -> str:
    """Run a subprocess, return stdout as string. Empty string on failure."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout or ""
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        return ""


def available_tools() -> dict[str, bool]:
    return {
        "strings":  shutil.which("strings") is not None,
        "otool":    shutil.which("otool")   is not None,
        "jtool2":   shutil.which("jtool2")  is not None,
        "nm":       shutil.which("nm")      is not None,
        "rabin2":   shutil.which("rabin2")  is not None,   # radare2
    }


# ── String extraction ─────────────────────────────────────────────────────────

def extract_strings(binary_path: str, min_length: int = 8) -> list[str]:
    """
    Extract printable strings from a Mach-O binary.
    Uses `strings` (universal), falls back to Python byte scanning.
    """
    if not Path(binary_path).exists():
        log.warning(f"Binary not found: {binary_path}")
        return []

    # Try `strings` command first (fastest)
    if shutil.which("strings"):
        out = _run(["strings", "-n", str(min_length), binary_path])
        if out:
            return [s.strip() for s in out.splitlines() if len(s.strip()) >= min_length]

    # Python fallback: scan for ASCII printable sequences
    log.warning("strings command not found — using Python fallback for string extraction.")
    try:
        data = Path(binary_path).read_bytes()
        pattern = re.compile(rb"[ -~]{" + str(min_length).encode() + rb",}")
        return [m.group(0).decode("ascii", errors="ignore") for m in pattern.finditer(data)]
    except OSError as exc:
        log.error(f"Cannot read binary: {exc}")
        return []


# ── Symbol table ─────────────────────────────────────────────────────────────

def extract_symbols(binary_path: str) -> list[str]:
    """Extract exported/imported symbol names using nm or jtool2."""
    if shutil.which("nm"):
        out = _run(["nm", "-g", binary_path])
        return [line.split()[-1] for line in out.splitlines() if line.strip()]

    if shutil.which("jtool2"):
        out = _run(["jtool2", "--symbols", binary_path])
        return [line.strip() for line in out.splitlines() if line.strip()]

    return []


# ── Linked libraries ──────────────────────────────────────────────────────────

def extract_linked_libs(binary_path: str) -> list[str]:
    """Return list of linked dylib paths."""
    if shutil.which("otool"):
        out = _run(["otool", "-L", binary_path])
        libs = []
        for line in out.splitlines()[1:]:   # skip first line (binary name)
            parts = line.strip().split("(")
            if parts:
                libs.append(parts[0].strip())
        return libs

    if shutil.which("jtool2"):
        out = _run(["jtool2", "--libraries", binary_path])
        return [line.strip() for line in out.splitlines() if line.strip()]

    return []


# ── Security properties (PIE, stack canary, ARC, etc.) ───────────────────────

def extract_security_flags(binary_path: str) -> dict[str, bool | str]:
    """
    Extract binary security properties.
    Uses otool / jtool2 / rabin2.
    Returns dict of flag_name → bool or value.
    """
    flags: dict[str, bool | str] = {
        "pie":            False,   # Position Independent Executable
        "arc":            False,   # Automatic Reference Counting
        "stack_canary":   False,   # Stack smashing protection
        "encrypted":      False,   # Binary encrypted (DRM)
        "rpath":          False,   # @rpath usage (dylib hijack risk)
        "bitcode":        False,   # Bitcode embedded
        "platform":       "unknown",
    }

    # otool -h (Mach-O header)
    if shutil.which("otool"):
        header_out = _run(["otool", "-hv", binary_path])
        if "PIE" in header_out:
            flags["pie"] = True

        # otool -l (load commands)
        lc_out = _run(["otool", "-l", binary_path])

        if "LC_ENCRYPTION_INFO" in lc_out:
            # Check cryptid field — 0 = not encrypted, 1 = encrypted
            for line in lc_out.splitlines():
                if "cryptid" in line and "1" in line:
                    flags["encrypted"] = True
                    break

        if "_objc_release" in _run(["otool", "-Iv", binary_path]):
            flags["arc"] = True

        if "__stack_chk_guard" in _run(["otool", "-Iv", binary_path]):
            flags["stack_canary"] = True

        if "@rpath" in lc_out:
            flags["rpath"] = True

        if "LC_SOURCE_VERSION" in lc_out or "__LLVM" in lc_out:
            flags["bitcode"] = True

        # Platform from LC_BUILD_VERSION or LC_VERSION_MIN_IPHONEOS
        if "IPHONE" in lc_out.upper() or "ios" in lc_out.lower():
            flags["platform"] = "iOS"
        elif "MACOS" in lc_out.upper():
            flags["platform"] = "macOS"

    # rabin2 fallback
    elif shutil.which("rabin2"):
        out = _run(["rabin2", "-I", binary_path])
        flags["pie"]          = "pic   true"   in out or "canary" in out
        flags["stack_canary"] = "canary true"  in out
        flags["arc"]          = "arc    true"  in out

    return flags


# ── High-level analysis ───────────────────────────────────────────────────────

def analyse_binary(binary_path: str) -> dict:
    """
    Full Mach-O analysis. Returns structured result dict.
    """
    log.info(f"Analysing binary: {Path(binary_path).name}")
    tools = available_tools()
    log.debug(f"Available tools: {tools}")

    strings_list = extract_strings(binary_path, min_length=8)
    symbols      = extract_symbols(binary_path)
    linked_libs  = extract_linked_libs(binary_path)
    sec_flags    = extract_security_flags(binary_path)

    result = {
        "binary_path":    binary_path,
        "tools_used":     [k for k, v in tools.items() if v],
        "strings_count":  len(strings_list),
        "strings":        strings_list,
        "symbols":        symbols,
        "linked_libs":    linked_libs,
        "security_flags": sec_flags,
    }

    log.info(
        f"Binary analysis: {len(strings_list)} strings | "
        f"{len(symbols)} symbols | "
        f"{len(linked_libs)} linked libs"
    )
    return result


def analyse_binary_security(binary_path: str) -> list[dict]:
    """
    Security-focused analysis of Mach-O binary.
    Returns list of raw finding dicts.
    """
    analysis = analyse_binary(binary_path)
    flags    = analysis["security_flags"]
    findings = []

    # ── PIE disabled ─────────────────────────────────────────────
    if not flags.get("pie"):
        findings.append({
            "title":       "PIE (ASLR) Not Enabled",
            "severity":    "MEDIUM",
            "confidence":  "HIGH",
            "exploitability": "LIKELY",
            "secret_type": "Binary Hardening",
            "description": (
                "The binary is not compiled as Position Independent Executable. "
                "ASLR cannot fully randomise the binary's base address, making "
                "ROP chain construction easier."
            ),
            "simulation":  (
                "Attacker builds a ROP chain using fixed binary addresses. "
                "Without ASLR entropy from PIE, the chain is reliable across devices."
            ),
            "score_value": 10,
            "cwe_id":      "CWE-119",
            "owasp_ref":   "M8: Code Tampering",
            "category":    "Config",
            "triage_note": "Compile with -fPIE -pie. All modern Xcode projects default to PIE=YES.",
            "evidence":    "PIE flag absent in Mach-O header",
        })

    # ── Stack canary disabled ─────────────────────────────────────
    if not flags.get("stack_canary"):
        findings.append({
            "title":       "Stack Canary Not Present",
            "severity":    "MEDIUM",
            "confidence":  "MEDIUM",
            "exploitability": "THEORETICAL",
            "secret_type": "Binary Hardening",
            "description": (
                "No __stack_chk_guard symbol found — stack smashing protection "
                "may not be enabled. Stack buffer overflows go undetected."
            ),
            "simulation":  (
                "Attacker exploits a stack buffer overflow in a native game function "
                "without triggering the canary check, enabling arbitrary code execution."
            ),
            "score_value": 8,
            "cwe_id":      "CWE-121",
            "owasp_ref":   "M8: Code Tampering",
            "category":    "Config",
            "triage_note": "Enable stack protection: OTHER_CFLAGS = -fstack-protector-all in Xcode.",
            "evidence":    "__stack_chk_guard not found in symbol table",
        })

    # ── ARC disabled ──────────────────────────────────────────────
    if not flags.get("arc"):
        findings.append({
            "title":       "ARC (Automatic Reference Counting) Not Detected",
            "severity":    "LOW",
            "confidence":  "LOW",
            "exploitability": "THEORETICAL",
            "secret_type": "Binary Hardening",
            "description": (
                "ARC does not appear to be in use. Manual memory management increases "
                "risk of use-after-free and double-free vulnerabilities."
            ),
            "simulation":  "Attacker exploits a use-after-free in a native Objective-C object for privilege escalation.",
            "score_value": 5,
            "cwe_id":      "CWE-416",
            "owasp_ref":   "M8: Code Tampering",
            "category":    "Config",
            "triage_note": "Enable ARC in Xcode Build Settings: CLANG_ENABLE_OBJC_ARC = YES.",
            "evidence":    "_objc_release not found in imports",
        })

    # ── Encryption ────────────────────────────────────────────────
    if not flags.get("encrypted"):
        findings.append({
            "title":       "Binary Not Encrypted (No FairPlay DRM)",
            "severity":    "INFO",
            "confidence":  "HIGH",
            "exploitability": "THEORETICAL",
            "secret_type": "Reverse Engineering Risk",
            "description": (
                "The binary does not appear to be encrypted with Apple FairPlay DRM. "
                "This is expected for development/enterprise builds but not for App Store releases. "
                "Unencrypted binaries are significantly easier to reverse engineer."
            ),
            "simulation":  "Attacker loads binary directly into Ghidra/IDA without needing a memory dump.",
            "score_value": 3,
            "cwe_id":      "CWE-311",
            "owasp_ref":   "M9: Insecure Data Storage",
            "category":    "Config",
            "triage_note": "App Store releases are automatically encrypted. For enterprise: consider DexGuard/iXGuard.",
            "evidence":    "LC_ENCRYPTION_INFO cryptid = 0",
        })

    # ── @rpath usage ──────────────────────────────────────────────
    if flags.get("rpath"):
        findings.append({
            "title":       "@rpath Dylib Loading (Hijack Risk)",
            "severity":    "LOW",
            "confidence":  "MEDIUM",
            "exploitability": "THEORETICAL",
            "secret_type": "Dylib Hijacking Risk",
            "description": (
                "Binary uses @rpath for dylib loading. If the rpath includes "
                "writable directories, a malicious dylib could be injected."
            ),
            "simulation":  "Attacker places a malicious .dylib in an @rpath directory to intercept calls.",
            "score_value": 5,
            "cwe_id":      "CWE-427",
            "owasp_ref":   "M8: Code Tampering",
            "category":    "Config",
            "triage_note": "Audit all @rpath entries. Use absolute paths for internal frameworks.",
            "evidence":    "@rpath found in LC_LOAD_DYLIB commands",
        })

    # ── Dangerous linked libraries ────────────────────────────────
    dangerous_libs = {
        "libcrypto":   "OpenSSL — ensure version is patched and not using deprecated APIs",
        "libssl":      "OpenSSL TLS — prefer Apple Security.framework",
        "libsqlite3":  "Direct SQLite usage — check for SQL injection in game queries",
    }
    for lib_fragment, note in dangerous_libs.items():
        matched = [l for l in analysis["linked_libs"] if lib_fragment in l.lower()]
        if matched:
            findings.append({
                "title":       f"Potentially Risky Linked Library: {lib_fragment}",
                "severity":    "INFO",
                "confidence":  "HIGH",
                "exploitability": "THEORETICAL",
                "secret_type": "Third-Party Library Risk",
                "description": f"Binary links against {matched[0]}. Note: {note}",
                "simulation":  "Attacker exploits known CVE in linked library version.",
                "score_value": 3,
                "cwe_id":      "CWE-1104",
                "owasp_ref":   "M8: Code Tampering",
                "category":    "Config",
                "triage_note": note,
                "evidence":    str(matched),
            })

    return findings
