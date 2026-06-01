"""
VENGAM — YAML Rule Engine
Araştırmacılar kendi detection kurallarını YAML ile yazabilir.

Kural formatı:
──────────────
  id:          unique_rule_id
  title:       İnsan okunabilir başlık
  description: Ne tespit ediyor
  severity:    CRITICAL / HIGH / MEDIUM / LOW / INFO
  confidence:  HIGH / MEDIUM / LOW
  category:    General / GameEngine / AntiCheat / Economy / Config
  platform:    android / ios / both
  tags:        [list, of, tags]

  detection:
    # Aşağıdakilerden biri veya kombinasyonu:
    pattern:   regex           # Tek regex
    patterns:  [regex1, ...]   # Birden fazla (OR)
    all_of:    [regex1, ...]   # Hepsi eşleşmeli (AND)
    keywords:  [kw1, kw2]     # Basit string arama (büyük/küçük harf yok sayılır)
    entropy:   5.0             # Minimum entropy eşiği
    file_ext:  [.smali, .xml]  # Sadece bu uzantılarda ara

  context:
    require_keywords: [game, economy]  # Bağlam şartı (FP azaltır)
    exclude_paths:    [androidx, com/google]
    exclude_patterns: [regex_to_ignore]

  simulation:   Saldırı senaryosu
  triage_note:  Triage rehberi
  frida_hook:   Önerilen Frida hook (opsiyonel)
  score_value:  10
  cvss_vector:  CVSS:3.1/...
  cwe_id:       CWE-798
  owasp_ref:    M9: ...
  references:
    - https://...
"""
from __future__ import annotations
import re
import math
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from vengam.utils.logger import log

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    log.warning("PyYAML yok — pip install pyyaml")


# ── Veri modelleri ────────────────────────────────────────────────

@dataclass
class RuleDetection:
    pattern:          str | None          = None
    patterns:         list[str]           = field(default_factory=list)
    all_of:           list[str]           = field(default_factory=list)
    keywords:         list[str]           = field(default_factory=list)
    entropy_threshold: float | None       = None
    file_extensions:  list[str]           = field(default_factory=list)
    # Compiled
    _compiled_pattern:  re.Pattern | None = field(default=None, repr=False)
    _compiled_patterns: list[re.Pattern]  = field(default_factory=list, repr=False)
    _compiled_all_of:   list[re.Pattern]  = field(default_factory=list, repr=False)


@dataclass
class RuleContext:
    require_keywords: list[str] = field(default_factory=list)
    exclude_paths:    list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=list)
    _compiled_excl:   list[re.Pattern] = field(default_factory=list, repr=False)


@dataclass
class Rule:
    id:           str
    title:        str
    description:  str
    severity:     str
    confidence:   str
    category:     str
    platform:     str          # android / ios / both
    detection:    RuleDetection
    context:      RuleContext
    simulation:   str          = ""
    triage_note:  str          = ""
    frida_hook:   str          = ""
    score_value:  int          = 10
    cvss_vector:  str          = ""
    cwe_id:       str          = ""
    owasp_ref:    str          = ""
    tags:         list[str]    = field(default_factory=list)
    references:   list[str]    = field(default_factory=list)
    source_file:  str          = ""


@dataclass
class RuleMatch:
    rule:         Rule
    matched_line: str
    matched_text: str
    line_number:  int
    file_path:    str


# ── Kural yükleyici ───────────────────────────────────────────────

class RuleLoader:
    """YAML dosyalarından Rule nesneleri yükler ve compile eder."""

    VALID_SEVERITIES  = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    VALID_CONFIDENCES = {"HIGH", "MEDIUM", "LOW"}
    VALID_CATEGORIES  = {"General", "GameEngine", "AntiCheat", "Economy", "Config"}
    VALID_PLATFORMS   = {"android", "ios", "both"}

    def load_file(self, path: str | Path) -> list[Rule]:
        if not YAML_AVAILABLE:
            raise ImportError("PyYAML gerekli: pip install pyyaml")
        path = Path(path)
        try:
            with open(path, encoding="utf-8") as f:
                docs = list(yaml.safe_load_all(f))
            rules = []
            for doc in docs:
                if doc is None:
                    continue
                # Tek kural veya liste
                if isinstance(doc, list):
                    for item in doc:
                        r = self._parse_rule(item, str(path))
                        if r:
                            rules.append(r)
                elif isinstance(doc, dict):
                    r = self._parse_rule(doc, str(path))
                    if r:
                        rules.append(r)
            log.debug(f"Kural dosyası yüklendi: {path} → {len(rules)} kural")
            return rules
        except Exception as exc:
            log.error(f"Kural yükleme hatası {path}: {exc}")
            return []

    def load_directory(self, directory: str | Path) -> list[Rule]:
        directory = Path(directory)
        if not directory.exists():
            return []
        rules = []
        for yml_file in sorted(directory.rglob("*.yml")) + sorted(directory.rglob("*.yaml")):
            rules.extend(self.load_file(yml_file))
        log.info(f"Kural dizini yüklendi: {directory} → {len(rules)} kural")
        return rules

    def _parse_rule(self, data: dict, source: str) -> Rule | None:
        try:
            rule_id    = str(data.get("id", "")).strip()
            title      = str(data.get("title", "")).strip()
            if not rule_id or not title:
                log.warning(f"Kural ID veya başlık eksik: {source}")
                return None

            severity   = str(data.get("severity", "MEDIUM")).upper()
            confidence = str(data.get("confidence", "MEDIUM")).upper()
            category   = str(data.get("category", "General"))
            platform   = str(data.get("platform", "both")).lower()

            if severity   not in self.VALID_SEVERITIES:   severity   = "MEDIUM"
            if confidence not in self.VALID_CONFIDENCES:  confidence = "MEDIUM"
            if category   not in self.VALID_CATEGORIES:   category   = "General"
            if platform   not in self.VALID_PLATFORMS:    platform   = "both"

            det_raw = data.get("detection", {}) or {}
            detection = self._parse_detection(det_raw)

            ctx_raw = data.get("context", {}) or {}
            context = self._parse_context(ctx_raw)

            return Rule(
                id=rule_id, title=title,
                description=str(data.get("description", "")),
                severity=severity, confidence=confidence,
                category=category, platform=platform,
                detection=detection, context=context,
                simulation=str(data.get("simulation", "")),
                triage_note=str(data.get("triage_note", "")),
                frida_hook=str(data.get("frida_hook", "")),
                score_value=int(data.get("score_value", 10)),
                cvss_vector=str(data.get("cvss_vector", "")),
                cwe_id=str(data.get("cwe_id", "")),
                owasp_ref=str(data.get("owasp_ref", "")),
                tags=list(data.get("tags", [])),
                references=list(data.get("references", [])),
                source_file=source,
            )
        except Exception as exc:
            log.error(f"Kural parse hatası ({source}): {exc}")
            return None

    def _parse_detection(self, d: dict) -> RuleDetection:
        det = RuleDetection(
            pattern           = d.get("pattern"),
            patterns          = list(d.get("patterns", [])),
            all_of            = list(d.get("all_of", [])),
            keywords          = [k.lower() for k in d.get("keywords", [])],
            entropy_threshold = d.get("entropy"),
            file_extensions   = [e.lower() for e in d.get("file_ext", [])],
        )
        # Compile regex'leri
        flags = re.IGNORECASE
        if det.pattern:
            try:
                det._compiled_pattern = re.compile(det.pattern, flags)
            except re.error as e:
                log.warning(f"Geçersiz pattern regex: {det.pattern} — {e}")
                det._compiled_pattern = None

        for p in det.patterns:
            try:
                det._compiled_patterns.append(re.compile(p, flags))
            except re.error as e:
                log.warning(f"Geçersiz patterns regex: {p} — {e}")

        for p in det.all_of:
            try:
                det._compiled_all_of.append(re.compile(p, flags))
            except re.error as e:
                log.warning(f"Geçersiz all_of regex: {p} — {e}")

        return det

    def _parse_context(self, c: dict) -> RuleContext:
        ctx = RuleContext(
            require_keywords = [k.lower() for k in c.get("require_keywords", [])],
            exclude_paths    = [p.lower() for p in c.get("exclude_paths", [])],
            exclude_patterns = list(c.get("exclude_patterns", [])),
        )
        for p in ctx.exclude_patterns:
            try:
                ctx._compiled_excl.append(re.compile(p, re.IGNORECASE))
            except re.error as e:
                log.warning(f"Geçersiz exclude_pattern: {p} — {e}")
        return ctx


# ── Kural motoru ──────────────────────────────────────────────────

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c/n)*math.log2(c/n) for c in counts.values())


class RuleEngine:
    """
    Yüklenen kuralları metin satırlarına karşı çalıştırır.
    Araştırmacı kuralları built-in pattern'lerle paralel çalışır.
    """

    def __init__(self) -> None:
        self._rules: list[Rule] = []
        self._loader = RuleLoader()

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def load_rules_from_dir(self, directory: str | Path) -> int:
        new_rules = self._loader.load_directory(directory)
        self._rules.extend(new_rules)
        return len(new_rules)

    def load_rules_from_file(self, path: str | Path) -> int:
        new_rules = self._loader.load_file(path)
        self._rules.extend(new_rules)
        return len(new_rules)

    def add_rule(self, rule: Rule) -> None:
        self._rules.append(rule)

    def clear(self) -> None:
        self._rules.clear()

    def match_line(
        self,
        line: str,
        filename: str,
        line_number: int,
        platform: str = "android",
    ) -> list[RuleMatch]:
        matches: list[RuleMatch] = []
        fname_lower = filename.lower().replace("\\", "/")
        line_lower  = line.lower()

        for rule in self._rules:
            # Platform filtresi
            if rule.platform != "both" and rule.platform != platform:
                continue

            det = rule.detection
            ctx = rule.context

            # Dosya uzantısı filtresi
            if det.file_extensions:
                ext = Path(filename).suffix.lower()
                if ext not in det.file_extensions:
                    continue

            # Context: exclude_paths
            if any(ep in fname_lower for ep in ctx.exclude_paths):
                continue

            # Context: exclude_patterns
            if any(rx.search(line) for rx in ctx._compiled_excl):
                continue

            # Context: require_keywords
            if ctx.require_keywords:
                if not any(kw in line_lower for kw in ctx.require_keywords):
                    continue

            # Detection logic
            matched_text = ""
            hit = False

            if det._compiled_pattern:
                m = det._compiled_pattern.search(line)
                if m:
                    matched_text = m.group(0)
                    hit = True

            if not hit and det._compiled_patterns:
                for rx in det._compiled_patterns:
                    m = rx.search(line)
                    if m:
                        matched_text = m.group(0)
                        hit = True
                        break

            if not hit and det._compiled_all_of:
                if all(rx.search(line) for rx in det._compiled_all_of):
                    matched_text = line.strip()[:80]
                    hit = True

            if not hit and det.keywords:
                if any(kw in line_lower for kw in det.keywords):
                    matched_text = line.strip()[:80]
                    hit = True

            if not hit and det.entropy_threshold is not None:
                # String extraction için basit regex
                for m in re.finditer(r"['\"]([^'\"]{12,256})['\"]", line):
                    val = m.group(1)
                    if _entropy(val) >= det.entropy_threshold:
                        matched_text = val[:40] + "..."
                        hit = True
                        break

            if hit:
                matches.append(RuleMatch(
                    rule=rule,
                    matched_line=line.strip()[:120],
                    matched_text=matched_text[:80],
                    line_number=line_number,
                    file_path=filename,
                ))

        return matches

    def get_rules_by_tag(self, tag: str) -> list[Rule]:
        return [r for r in self._rules if tag in r.tags]

    def get_rules_by_severity(self, severity: str) -> list[Rule]:
        return [r for r in self._rules if r.severity == severity.upper()]


# ── Singleton ─────────────────────────────────────────────────────
_engine: RuleEngine | None = None

def get_rule_engine() -> RuleEngine:
    global _engine
    if _engine is None:
        _engine = RuleEngine()
        # Varsayılan kural dizinini yükle
        rules_dir = Path(__file__).parent.parent / "rules"
        if rules_dir.exists():
            loaded = _engine.load_rules_from_dir(rules_dir)
            if loaded:
                log.info(f"Kural motoru: {loaded} kural yüklendi ({rules_dir})")
    return _engine
