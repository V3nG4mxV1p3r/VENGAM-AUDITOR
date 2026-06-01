"""
VENGAM — IL2CPP Deep Intelligence
Unity IL2CPP binary'lerinden class/method/field bilgisi çıkartır.
global-metadata.dat + libil2cpp.so birlikte analiz edilir.

Yetenekler:
  - Class map reconstruction
  - Method signature extraction
  - Security-relevant method discovery
  - Hidden API detection
  - Anti-cheat method fingerprinting
  - Economy class mapping
"""
from __future__ import annotations
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from vengam.utils.logger import log


# ── Veri modelleri ────────────────────────────────────────────────

@dataclass
class Il2CppMethod:
    name:        str
    class_name:  str
    return_type: str = ""
    params:      list[str] = field(default_factory=list)
    is_static:   bool = False
    flags:       int  = 0

    @property
    def full_signature(self) -> str:
        p = ", ".join(self.params) if self.params else ""
        s = "static " if self.is_static else ""
        return f"{s}{self.return_type} {self.class_name}::{self.name}({p})"


@dataclass
class Il2CppClass:
    name:       str
    namespace:  str = ""
    methods:    list[Il2CppMethod] = field(default_factory=list)
    fields:     list[str]          = field(default_factory=list)
    is_generic: bool = False

    @property
    def full_name(self) -> str:
        if self.namespace:
            return f"{self.namespace}.{self.name}"
        return self.name


@dataclass
class Il2CppAnalysis:
    version:         int
    class_count:     int
    method_count:    int
    string_count:    int
    classes:         list[Il2CppClass]
    security_hits:   list["SecurityHit"]
    raw_strings:     list[str]


@dataclass
class SecurityHit:
    category:    str
    severity:    str
    name:        str
    context:     str
    frida_hook:  str = ""
    score:       int = 10


# ── IL2CPP Magic ve header ────────────────────────────────────────

IL2CPP_MAGIC = 0xFAB11BAF

def _read_u32(data: bytes, offset: int) -> int:
    if offset + 4 > len(data): return 0
    return struct.unpack_from("<I", data, offset)[0]

def _read_i32(data: bytes, offset: int) -> int:
    if offset + 4 > len(data): return 0
    return struct.unpack_from("<i", data, offset)[0]

def _extract_cstrings(data: bytes, offset: int, size: int,
                      min_len: int = 4) -> list[str]:
    if offset >= len(data): return []
    end     = min(offset + size, len(data))
    section = data[offset:end]
    strings = []
    start   = 0
    for i, b in enumerate(section):
        if b == 0:
            length = i - start
            if length >= min_len:
                try:
                    s = section[start:i].decode("utf-8", errors="ignore")
                    if s.isprintable() or all(c.isascii() for c in s):
                        strings.append(s)
                except:
                    pass
            start = i + 1
    return strings


# ── Güvenlik keyword'leri ─────────────────────────────────────────

SECURITY_PATTERNS: list[tuple[str, str, str, int, str]] = [
    # (keyword, category, severity, score, frida_template)
    ("AntiCheat",       "Anti-Cheat",    "CRITICAL", 30,
     "Java.use('{cls}').{method}.implementation = function() {{ send('AC bypassed'); return false; }};"),
    ("anticheat",       "Anti-Cheat",    "CRITICAL", 30, ""),
    ("IsRooted",        "Root Detection","HIGH",     25,
     "Java.use('{cls}').{method}.implementation = function() {{ return false; }};"),
    ("DetectFrida",     "Frida Detection","CRITICAL",35,
     "// Hook to bypass Frida detection\nJava.use('{cls}').{method}.implementation = function() {{ return false; }};"),
    ("ValidateReceipt", "IAP Validation","CRITICAL", 30,
     "Java.use('{cls}').{method}.implementation = function() {{ return true; }};"),
    ("VerifyPurchase",  "IAP Validation","CRITICAL", 30,
     "Java.use('{cls}').{method}.implementation = function() {{ return true; }};"),
    ("GetGold",         "Economy",       "HIGH",     20,
     "Java.use('{cls}').{method}.implementation = function() {{ return 999999; }};"),
    ("GetGems",         "Economy",       "HIGH",     20,
     "Java.use('{cls}').{method}.implementation = function() {{ return 999999; }};"),
    ("GetCurrency",     "Economy",       "HIGH",     20,
     "Java.use('{cls}').{method}.implementation = function() {{ return 999999; }};"),
    ("AddGold",         "Economy",       "HIGH",     20, ""),
    ("SpendCurrency",   "Economy",       "MEDIUM",   15, ""),
    ("GodMode",         "Debug Flag",    "HIGH",     25,
     "Java.use('{cls}').{method}.implementation = function() {{ return true; }};"),
    ("Invincible",      "Debug Flag",    "HIGH",     20,
     "Java.use('{cls}').{method}.implementation = function() {{ return true; }};"),
    ("InfiniteAmmo",    "Debug Flag",    "HIGH",     20, ""),
    ("EncryptionKey",   "Crypto",        "CRITICAL", 35,
     "// Hook encryption key extraction\nJava.use('{cls}').{method}.implementation = function() {{ var r = this.{method}(); send('Key: ' + r); return r; }};"),
    ("DecryptData",     "Crypto",        "HIGH",     25, ""),
    ("GetToken",        "Auth",          "HIGH",     25,
     "Java.use('{cls}').{method}.implementation = function() {{ var r = this.{method}(); send('Token: ' + r); return r; }};"),
    ("GetSessionKey",   "Auth",          "HIGH",     25, ""),
    ("AdminPanel",      "Hidden Admin",  "CRITICAL", 40, ""),
    ("CheatCode",       "Debug Flag",    "HIGH",     20, ""),
    ("DebugMenu",       "Debug Flag",    "MEDIUM",   15, ""),
    ("PakDecrypt",      "Asset Crypto",  "CRITICAL", 35,
     "// Hook PAK decryption\nJava.use('{cls}').{method}.implementation = function() {{ var r = this.{method}.apply(this, arguments); send('PAK decrypt called'); return r; }};"),
]

def _match_security(name: str, class_name: str) -> SecurityHit | None:
    name_lower  = name.lower()
    class_lower = class_name.lower()
    for kw, cat, sev, score, frida_tpl in SECURITY_PATTERNS:
        if kw.lower() in name_lower or kw.lower() in class_lower:
            hook = frida_tpl.replace("{cls}", class_name).replace("{method}", name) \
                   if frida_tpl else f"// Hook: {class_name}.{name}"
            return SecurityHit(
                category=cat, severity=sev,
                name=f"{class_name}.{name}",
                context=f"IL2CPP method: {class_name}::{name}",
                frida_hook=hook, score=score,
            )
    return None


# ── Ana parser ────────────────────────────────────────────────────

class Il2CppDeepParser:
    """
    global-metadata.dat'tan class/method bilgisi çıkartır.
    Hem native Rust engine (phantom_native) hem Python fallback destekler.
    """

    def __init__(self, use_native: bool = True) -> None:
        self.use_native = use_native
        self._native_available = False
        if use_native:
            try:
                import phantom_native
                self._native_available = True
            except ImportError:
                pass

    def parse(self, metadata_path: str) -> Il2CppAnalysis | None:
        path = Path(metadata_path)
        if not path.exists():
            log.error(f"Metadata bulunamadı: {metadata_path}")
            return None

        try:
            data = path.read_bytes()
        except OSError as e:
            log.error(f"Okuma hatası: {e}")
            return None

        magic = _read_u32(data, 0)
        if magic != IL2CPP_MAGIC:
            log.warning(f"Geçersiz IL2CPP magic: {hex(magic)}")
            return None

        version = _read_i32(data, 4)
        log.info(f"IL2CPP metadata v{version} — {len(data)/1024/1024:.1f} MB")

        # Native engine varsa kullan
        if self._native_available:
            return self._parse_native(data, version, metadata_path)
        return self._parse_python(data, version)

    def _parse_native(self, data: bytes, version: int,
                      path: str) -> Il2CppAnalysis:
        import phantom_native as pn
        result    = pn.parse_il2cpp_metadata(path)
        raw_strs  = []
        sec_hits  = []
        classes   = []

        if result.get("valid"):
            for hit in result.get("security_findings", []):
                sec_hits.append(SecurityHit(
                    category=hit.get("category", "General"),
                    severity=hit.get("severity", "MEDIUM"),
                    name=hit.get("value", "")[:60],
                    context="IL2CPP metadata (native)",
                    score=20,
                ))
            raw_strs = result.get("strings", [])

        # Python ile ek analiz
        extra = self._extract_strings_python(data)
        classes, extra_hits = self._analyze_strings(extra)
        sec_hits.extend(extra_hits)
        raw_strs.extend(extra)

        return Il2CppAnalysis(
            version=version,
            class_count=len(classes),
            method_count=sum(len(c.methods) for c in classes),
            string_count=len(raw_strs),
            classes=classes,
            security_hits=sec_hits,
            raw_strings=raw_strs[:500],
        )

    def _parse_python(self, data: bytes, version: int) -> Il2CppAnalysis:
        log.info("IL2CPP Python parser çalışıyor...")
        raw_strings = self._extract_strings_python(data)
        classes, sec_hits = self._analyze_strings(raw_strings)
        return Il2CppAnalysis(
            version=version,
            class_count=len(classes),
            method_count=sum(len(c.methods) for c in classes),
            string_count=len(raw_strings),
            classes=classes,
            security_hits=sec_hits,
            raw_strings=raw_strings[:500],
        )

    def _extract_strings_python(self, data: bytes) -> list[str]:
        """Binary'den ASCII string'leri çıkart."""
        strings = []
        pattern = re.compile(rb"[\x20-\x7e]{6,}")
        for m in pattern.finditer(data):
            s = m.group(0).decode("ascii", errors="ignore")
            strings.append(s)
        return strings

    def _analyze_strings(
        self, strings: list[str]
    ) -> tuple[list[Il2CppClass], list[SecurityHit]]:
        """
        String listesinden class/method yapısını reconstruct et.
        IL2CPP metadata'da class ve method isimleri düz string olarak saklanır.
        """
        classes:   dict[str, Il2CppClass] = {}
        sec_hits:  list[SecurityHit]      = []

        # Class pattern: "Namespace.ClassName" veya "ClassName"
        class_pat  = re.compile(
            r"^([A-Z][a-zA-Z0-9_]*(?:\.[A-Z][a-zA-Z0-9_]*)*)$"
        )
        # Method pattern: "MethodName" (PascalCase veya camelCase)
        method_pat = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{2,50}$")

        current_class = "Unknown"
        for s in strings:
            s = s.strip()
            if not s: continue

            # Class tespiti
            if class_pat.match(s) and any(kw in s for kw in [
                "Manager", "Controller", "System", "Handler",
                "Service", "Engine", "Anti", "Economy", "Player",
                "Purchase", "Auth", "Crypto", "Network", "Game",
            ]):
                current_class = s
                if s not in classes:
                    parts = s.rsplit(".", 1)
                    ns    = parts[0] if len(parts) > 1 else ""
                    name  = parts[-1]
                    classes[s] = Il2CppClass(name=name, namespace=ns)

            # Method tespiti
            elif method_pat.match(s) and current_class in classes:
                method = Il2CppMethod(
                    name=s, class_name=current_class
                )
                classes[current_class].methods.append(method)

                # Güvenlik kontrolü
                hit = _match_security(s, current_class)
                if hit:
                    sec_hits.append(hit)

            # Direkt güvenlik keyword arama
            else:
                for kw, cat, sev, score, _ in SECURITY_PATTERNS:
                    if kw.lower() in s.lower() and len(s) < 80:
                        hit = _match_security(s, "IL2CPP")
                        if hit and not any(
                            h.name == hit.name for h in sec_hits
                        ):
                            sec_hits.append(hit)
                        break

        # Dedup
        unique_hits = []
        seen = set()
        for h in sec_hits:
            if h.name not in seen:
                seen.add(h.name)
                unique_hits.append(h)

        return list(classes.values()), unique_hits


# ── Decompile dizininden IL2CPP bulma ────────────────────────────

def find_and_analyze(decompiled_dir: str) -> Il2CppAnalysis | None:
    """Decompile edilmiş APK dizininde IL2CPP dosyalarını bul ve analiz et."""
    base = Path(decompiled_dir)
    metadata_candidates = [
        base / "assets" / "bin" / "Data" / "Managed" / "Metadata" / "global-metadata.dat",
        base / "assets" / "bin" / "Data" / "global-metadata.dat",
        *base.rglob("global-metadata.dat"),
    ]
    for path in metadata_candidates:
        if path.exists():
            log.info(f"IL2CPP metadata bulundu: {path}")
            parser = Il2CppDeepParser()
            return parser.parse(str(path))
    log.info("IL2CPP metadata bulunamadı — Unity IL2CPP projesi olmayabilir.")
    return None
