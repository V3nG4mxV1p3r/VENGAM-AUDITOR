"""
VENGAM Auditor — Native Binary Analyzer (Python wrapper)
Bridges Python ↔ Rust phantom_native extension.

Falls back gracefully to pure-Python implementations if the Rust
extension has not been compiled yet (maturin develop not run).
"""
from __future__ import annotations
from pathlib import Path
from vengam.utils.logger import log

# ── Try importing compiled Rust extension ─────────────────────────────────────
try:
    import phantom_native as _native
    NATIVE_AVAILABLE = True
    log.debug("phantom_native Rust extension loaded ✓")
except ImportError:
    _native = None          # type: ignore
    NATIVE_AVAILABLE = False
    log.debug("phantom_native not compiled — using Python fallback")


# ── String extraction ─────────────────────────────────────────────────────────

def extract_strings(path: str, min_length: int = 8) -> list[str]:
    """Extract printable strings from a binary file."""
    if NATIVE_AVAILABLE:
        return _native.extract_strings(path, min_length, True)

    # Pure-Python fallback
    import re
    try:
        data    = Path(path).read_bytes()
        pattern = re.compile(
            rb"[ -~]{" + str(min_length).encode() + rb",}"
        )
        return [m.group(0).decode("ascii", errors="ignore")
                for m in pattern.finditer(data)]
    except OSError as exc:
        log.error(f"Cannot read binary {path}: {exc}")
        return []


# ── Entropy ───────────────────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    """Shannon entropy of a string (bits per character)."""
    if NATIVE_AVAILABLE:
        return _native.shannon_entropy(s)

    # Python fallback
    import math
    from collections import Counter
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum(
        (c / length) * math.log2(c / length) for c in counts.values()
    )


def scan_high_entropy_strings(
    strings: list[str],
    threshold: float = 4.5,
    min_len: int = 12,
) -> list[tuple[str, float]]:
    """Return (string, entropy) pairs above threshold."""
    if NATIVE_AVAILABLE:
        return _native.scan_high_entropy_strings(strings, threshold, min_len)

    return [
        (s, shannon_entropy(s))
        for s in strings
        if len(s) >= min_len and shannon_entropy(s) >= threshold
    ]


# ── ELF / SO analysis ─────────────────────────────────────────────────────────

def scan_elf(path: str) -> dict:
    """
    Analyse an ELF/SO binary.
    Returns dict with keys: security_flags, symbol_findings, linked_libs.
    """
    if NATIVE_AVAILABLE:
        return _native.scan_elf(path)

    # Fallback: use 'strings' + 'nm' if available
    import shutil, subprocess
    result: dict = {
        "security_flags": {
            "pie": None, "nx": None, "relro": None,
            "canary": None, "stripped": None,
            "rpath": None, "soname": "",
        },
        "symbol_findings": [],
        "linked_libs":     [],
        "note": "phantom_native not compiled — limited analysis",
    }

    # Try readelf for basic flag detection
    if shutil.which("readelf"):
        try:
            out = subprocess.run(
                ["readelf", "-d", path],
                capture_output=True, text=True, timeout=10
            ).stdout
            result["security_flags"]["rpath"] = "RPATH" in out
        except Exception:
            pass
    return result


def get_elf_security_flags(path: str) -> dict:
    """Return only security flags for an ELF binary."""
    if NATIVE_AVAILABLE:
        return _native.get_elf_security_flags(path)
    return scan_elf(path).get("security_flags", {})


# ── IL2CPP metadata ───────────────────────────────────────────────────────────

def parse_il2cpp_metadata(path: str) -> dict:
    """
    Parse IL2CPP global-metadata.dat.
    Returns dict: valid, version, string_count, literal_count, security_findings.
    """
    if NATIVE_AVAILABLE:
        return _native.parse_il2cpp_metadata(path)

    # Pure-Python fallback: magic check + basic string scan
    try:
        data = Path(path).read_bytes()
    except OSError:
        return {"valid": False, "error": "Cannot read file"}

    IL2CPP_MAGIC = b"\xAF\x1B\xB1\xFA"
    if not data[:4] == IL2CPP_MAGIC:
        return {"valid": False}

    # Basic ASCII string extraction for keyword search
    import re
    strings = [
        m.group(0).decode("ascii", errors="ignore")
        for m in re.finditer(rb"[ -~]{6,}", data)
    ]

    SECURITY_KEYWORDS = [
        ("api_key", "Hardcoded Credential", "CRITICAL"),
        ("secret",  "Hardcoded Credential", "HIGH"),
        ("AIza",    "Firebase API Key",     "CRITICAL"),
        ("AKIA",    "AWS Access Key",       "CRITICAL"),
        ("god_mode","Debug Flag",           "HIGH"),
        ("bypass",  "Bypass String",        "CRITICAL"),
    ]

    findings = []
    seen: set[str] = set()
    for s in strings:
        s_lower = s.lower()
        for kw, cat, sev in SECURITY_KEYWORDS:
            if kw.lower() in s_lower and s not in seen:
                seen.add(s)
                findings.append({"value": s, "category": cat, "severity": sev})
                break

    return {
        "valid":             True,
        "string_count":      len(strings),
        "security_findings": findings,
        "note":              "phantom_native not compiled — basic scan only",
    }


def find_il2cpp_binary(search_dir: str) -> list[str]:
    """Find IL2CPP related files in a directory tree."""
    if NATIVE_AVAILABLE:
        return _native.find_il2cpp_binary(search_dir)

    targets  = {"global-metadata.dat", "libil2cpp.so", "libil2cpp.dylib"}
    found    = []
    for path in Path(search_dir).rglob("*"):
        if path.is_file() and path.name in targets:
            found.append(str(path))
    return found


# ── High-level: full SO directory scan ───────────────────────────────────────

def scan_so_files(decompiled_dir: str) -> list[dict]:
    """
    Find all .so files in the decompiled APK and run ELF security analysis.
    Returns list of finding dicts ready for ScanResult.
    """
    from vengam.core.models import Finding, FindingLocation
    findings_raw: list[dict] = []

    so_files = list(Path(decompiled_dir).rglob("*.so"))
    if not so_files:
        log.info("No .so files found in decompiled directory.")
        return []

    log.info(f"Found {len(so_files)} .so file(s) — running ELF analysis ...")

    for so_path in so_files:
        relative = so_path.name
        log.debug(f"Analysing: {relative}")

        elf_result   = scan_elf(str(so_path))
        flags        = elf_result.get("security_flags", {})
        sym_findings = elf_result.get("symbol_findings", [])

        # ── Binary hardening findings ─────────────────────────────
        hardening_checks = [
            ("pie",    "PIE (ASLR) Disabled in Native Library",
             "MEDIUM", 10,
             "ELF .so is not position-independent. ROP chains are easier to construct.",
             "Use -fPIC when compiling native game code."),
            ("nx",     "Non-Executable Stack Missing",
             "MEDIUM", 8,
             "GNU_STACK is executable — shellcode can run on the stack.",
             "Compile with -z noexecstack. Check NDK build flags."),
            ("canary", "Stack Canary Missing in Native Library",
             "MEDIUM", 8,
             "No __stack_chk_fail symbol — stack overflow protection may be absent.",
             "Compile with -fstack-protector-all in Android NDK."),
            ("relro",  "RELRO Not Enabled",
             "LOW", 5,
             "RELRO not present — GOT overwrite attacks are possible.",
             "Link with -Wl,-z,relro,-z,now for full RELRO."),
        ]

        for flag_key, title, severity, score, desc, triage in hardening_checks:
            flag_val = flags.get(flag_key)
            # None = couldn't determine; False = definitely disabled
            if flag_val is False:
                findings_raw.append({
                    "title":          title,
                    "severity":       severity,
                    "confidence":     "HIGH" if NATIVE_AVAILABLE else "MEDIUM",
                    "exploitability": "LIKELY",
                    "secret_type":    "Binary Hardening",
                    "description":    f"[{relative}] {desc}",
                    "simulation":     f"Attacker targets {relative} for memory corruption exploit.",
                    "score_value":    score,
                    "cwe_id":         "CWE-119",
                    "owasp_ref":      "M8: Code Tampering",
                    "category":       "Config",
                    "triage_note":    triage,
                    "locations": [FindingLocation(
                        file=f"lib/{relative}", line=1,
                        snippet=f"ELF flag: {flag_key}=False",
                    )],
                })

        # ── rpath findings ────────────────────────────────────────
        if flags.get("rpath"):
            findings_raw.append({
                "title":          "RPATH Set in Native Library (Dylib Hijack Risk)",
                "severity":       "LOW",
                "confidence":     "HIGH",
                "exploitability": "THEORETICAL",
                "secret_type":    "Native Library Risk",
                "description":    f"[{relative}] DT_RPATH is set — dylib hijacking possible if rpath is writable.",
                "simulation":     "Attacker places malicious .so in rpath directory to intercept calls.",
                "score_value":    5,
                "cwe_id":         "CWE-427",
                "owasp_ref":      "M8: Code Tampering",
                "category":       "Config",
                "triage_note":    "Replace DT_RPATH with DT_RUNPATH or absolute paths.",
                "locations": [FindingLocation(
                    file=f"lib/{relative}", line=1,
                    snippet="DT_RPATH present in ELF dynamic section",
                )],
            })

        # ── Symbol-based findings ─────────────────────────────────
        for sym_f in sym_findings:
            sev = sym_f.get("severity", "MEDIUM")
            if sev in ("INFO",):
                continue
            findings_raw.append({
                "title":          f"Suspicious Symbol in Native Library: {sym_f.get('title','')}",
                "severity":       sev,
                "confidence":     "MEDIUM",
                "exploitability": "LIKELY",
                "secret_type":    "Native Symbol",
                "description":    (
                    f"Symbol '{sym_f.get('symbol','')}' found in {relative}. "
                    f"Category: {sym_f.get('title','')}"
                ),
                "simulation":     "Attacker hooks this symbol with Frida to manipulate game logic.",
                "score_value":    15 if sev == "CRITICAL" else 8,
                "cwe_id":         "CWE-693",
                "owasp_ref":      "M8: Code Tampering",
                "category":       "AntiCheat",
                "triage_note":    "Verify this symbol is stripped from release builds.",
                "locations": [FindingLocation(
                    file=f"lib/{relative}", line=1,
                    snippet=f"Symbol: {sym_f.get('symbol','')}",
                )],
            })

    log.info(f"ELF analysis: {len(so_files)} libs → {len(findings_raw)} findings")
    return findings_raw


# ── High-level: IL2CPP scan ───────────────────────────────────────────────────

def scan_il2cpp(decompiled_dir: str) -> list[dict]:
    """
    Find and analyse IL2CPP metadata files.
    Returns list of finding dicts.
    """
    from vengam.core.models import FindingLocation
    findings_raw: list[dict] = []

    il2cpp_files = find_il2cpp_binary(decompiled_dir)
    if not il2cpp_files:
        log.info("No IL2CPP metadata files found.")
        return []

    log.info(f"Found {len(il2cpp_files)} IL2CPP file(s) ...")

    for fpath in il2cpp_files:
        fname  = Path(fpath).name
        result = parse_il2cpp_metadata(fpath)

        if not result.get("valid"):
            continue

        sec = result.get("security_findings", [])
        log.info(
            f"IL2CPP [{fname}]: "
            f"version={result.get('version','?')} | "
            f"strings={result.get('string_count','?')} | "
            f"security hits={len(sec)}"
        )

        # IL2CPP symbols present = reverse engineering risk
        findings_raw.append({
            "title":          "IL2CPP Metadata Present (Reverse Engineering Risk)",
            "severity":       "MEDIUM",
            "confidence":     "HIGH",
            "exploitability": "LIKELY",
            "secret_type":    "Debug Symbol Leak",
            "description":    (
                f"global-metadata.dat found (IL2CPP v{result.get('version','?')}). "
                f"Contains {result.get('string_count',0)} type/method strings. "
                "Significantly accelerates reverse engineering of Unity game logic."
            ),
            "simulation":     (
                "Attacker uses IL2CPPDumper with global-metadata.dat + libil2cpp.so "
                "to recover all class/method names and hook them with Frida."
            ),
            "score_value":    15,
            "cwe_id":         "CWE-540",
            "owasp_ref":      "M10: Extraneous Functionality",
            "category":       "GameEngine",
            "triage_note":    (
                "Disable IL2CPP symbol generation in Unity Build Settings. "
                "Enable IL2CPP code stripping. Consider obfuscating metadata."
            ),
            "locations": [FindingLocation(file=fname, line=1,
                snippet=f"IL2CPP metadata v{result.get('version','?')}")],
        })

        # Security strings in metadata
        for hit in sec:
            sev = hit.get("severity", "MEDIUM")
            findings_raw.append({
                "title":          f"Hardcoded Value in IL2CPP Metadata: {hit.get('category','')}",
                "severity":       sev,
                "confidence":     "MEDIUM",
                "exploitability": "LIKELY",
                "secret_type":    hit.get("category", "Hardcoded Value"),
                "description":    (
                    f"Security-sensitive string found in IL2CPP metadata: "
                    f"'{hit.get('value','')[:60]}'"
                ),
                "simulation":     "Attacker extracts value from metadata using IL2CPPDumper.",
                "score_value":    25 if sev == "CRITICAL" else 10,
                "cwe_id":         "CWE-798",
                "owasp_ref":      "M9: Insecure Data Storage",
                "category":       "General",
                "triage_note":    "Remove hardcoded values from game code. Fetch secrets post-auth.",
                "locations": [FindingLocation(
                    file=fname, line=1,
                    snippet=hit.get("value", "")[:80],
                )],
            })

    return findings_raw
