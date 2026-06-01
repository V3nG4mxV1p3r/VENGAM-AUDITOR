"""
VENGAM — Oyun-Özel Tehdit Skoru
Generic CVSS yerine mobile game abuse senaryolarına göre özelleştirilmiş
risk skoru hesaplama motoru.

Scoring faktörleri:
  1. Economy Abuse Risk     — para birimi, IAP, leaderboard manipülasyonu
  2. Multiplayer Risk       — hile, sync manipülasyonu, oda istismarı
  3. Monetization Impact    — gelir kaybı, fraud
  4. Anti-Cheat Bypass      — god mode, wallhack, speedhack
  5. Client Authority       — sunucu doğrulaması olmayan istemci kararları
  6. Credential Exposure    — API key, secret, token sızıntısı
  7. Data Privacy           — PII, kullanıcı verisi sızıntısı
  8. Infrastructure Risk    — cloud, backend, CI/CD zafiyetleri
"""
from __future__ import annotations
from dataclasses import dataclass, field
from vengam.core.models import AttackSurface, Finding


# ── Skor bileşenleri ──────────────────────────────────────────────

@dataclass
class GameThreatScore:
    """Oyun güvenlik tehdit skoru — 0-100 arası."""

    # Ham bulgulardan gelen temel skor
    base_score:            int = 0

    # Oyun-spesifik kategori skorları
    economy_abuse:         int = 0   # IAP bypass, currency hack
    multiplayer_abuse:     int = 0   # Photon, EOS, anti-cheat bypass
    monetization_impact:   int = 0   # Gelir kaybı riski
    anticheat_bypass:      int = 0   # Debug flag, god mode
    client_authority:      int = 0   # Client-side validation
    credential_exposure:   int = 0   # API key, secret
    data_privacy:          int = 0   # PII, GDPR riski
    infrastructure_risk:   int = 0   # Cloud, CI/CD
    attack_surface_bonus:  int = 0   # Exposed endpoints

    # Combo cezaları
    combo_penalties: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        raw = (
            self.base_score
            + self.economy_abuse
            + self.multiplayer_abuse
            + self.monetization_impact
            + self.anticheat_bypass
            + self.client_authority
            + self.credential_exposure
            + self.data_privacy
            + self.infrastructure_risk
            + self.attack_surface_bonus
        )
        return max(0, min(100, raw))

    @property
    def verdict(self) -> str:
        t = self.total
        if t >= 75: return "BLOCK RELEASE"
        if t >= 40: return "AT RISK — REMEDIATION REQUIRED"
        return "CONDITIONALLY SAFE"

    @property
    def risk_level(self) -> str:
        t = self.total
        if t >= 75: return "CRITICAL"
        if t >= 50: return "HIGH"
        if t >= 25: return "MEDIUM"
        return "LOW"

    def breakdown(self) -> dict:
        return {
            "total":                self.total,
            "verdict":              self.verdict,
            "risk_level":           self.risk_level,
            "base_score":           self.base_score,
            "economy_abuse":        self.economy_abuse,
            "multiplayer_abuse":    self.multiplayer_abuse,
            "monetization_impact":  self.monetization_impact,
            "anticheat_bypass":     self.anticheat_bypass,
            "client_authority":     self.client_authority,
            "credential_exposure":  self.credential_exposure,
            "data_privacy":         self.data_privacy,
            "infrastructure_risk":  self.infrastructure_risk,
            "attack_surface_bonus": self.attack_surface_bonus,
            "combo_penalties":      self.combo_penalties,
        }


# ── Scoring motoru ────────────────────────────────────────────────

# Kategori → scoring bucket eşlemesi
_ECONOMY_TITLES = {
    "playfab", "gamesparks", "nakama", "lootlocker", "braincloud",
    "xsolla", "iap bypass", "receipt validation", "client-side currency",
    "leaderboard score", "game economy",
}

_MULTIPLAYER_TITLES = {
    "photon", "agora", "anti-cheat bypass", "root", "emulator detection",
    "ssl certificate pinning", "god mode", "debug", "il2cpp",
    "unreal engine encryption", "pak encryption",
}

_MONETIZATION_TITLES = {
    "stripe", "in-app purchase", "iap", "xsolla", "economy",
    "currency", "monetization",
}

_ANTICHEAT_TITLES = {
    "anti-cheat", "bypass", "god mode", "debug flag", "root detection",
    "ssl pinning", "frida", "emulator",
}

_CREDENTIAL_TITLES = {
    "firebase", "aws", "github", "jwt", "stripe", "sendgrid",
    "twilio", "agora", "applovin", "private key", "hardcoded password",
    "hardcoded credential", "secret", "api key",
}

_PRIVACY_TITLES = {
    "allowbackup", "exported component", "network_security",
    "cleartext", "user data", "pii",
}

_INFRA_TITLES = {
    "github", "aws", "cloud", "ci/cd", "unity cloud", "eos",
    "playfab", "firebase",
}


def _title_matches(finding_title: str, keyword_set: set[str]) -> bool:
    t = finding_title.lower()
    return any(kw in t for kw in keyword_set)


def calculate_game_score(
    findings:       list[Finding],
    surface:        AttackSurface,
    rule_matches:   list | None = None,
) -> GameThreatScore:
    """
    Oyun güvenlik tehdit skoru hesapla.
    Hem built-in pattern hem araştırmacı kural bulgularını hesaba katar.
    """
    score = GameThreatScore()

    # ── Base skor (severity ağırlıklı) ────────────────────────────
    severity_weights = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.5,
                        "LOW": 0.3, "INFO": 0.1}
    for f in findings:
        w = severity_weights.get(f.severity, 0.5)
        score.base_score += int(f.score_value * w)

    # ── Kategori bazlı puanlama ───────────────────────────────────
    titles = [f.title for f in findings]

    for f in findings:
        t = f.title.lower()
        sv = f.score_value

        # Economy abuse
        if _title_matches(f.title, _ECONOMY_TITLES):
            score.economy_abuse += min(sv, 20)

        # Multiplayer / anti-cheat
        if _title_matches(f.title, _MULTIPLAYER_TITLES):
            score.multiplayer_abuse += min(sv, 15)

        # Monetization
        if _title_matches(f.title, _MONETIZATION_TITLES):
            score.monetization_impact += min(sv, 15)

        # Anti-cheat bypass
        if f.category == "AntiCheat":
            score.anticheat_bypass += min(sv, 20)

        # Client authority
        if f.category == "Economy" and "client" in t:
            score.client_authority += min(sv, 15)

        # Credential exposure
        if _title_matches(f.title, _CREDENTIAL_TITLES) or f.category == "General":
            if f.severity in ("CRITICAL", "HIGH"):
                score.credential_exposure += min(sv, 20)

        # Data privacy
        if _title_matches(f.title, _PRIVACY_TITLES) or f.category == "Config":
            score.data_privacy += min(sv, 10)

        # Infrastructure
        if _title_matches(f.title, _INFRA_TITLES):
            score.infrastructure_risk += min(sv, 15)

    # ── Attack surface bonus ──────────────────────────────────────
    if surface.payment:                    score.attack_surface_bonus += 10
    if surface.auth:                       score.attack_surface_bonus += 8
    if len(surface.internal_api) > 5:     score.attack_surface_bonus += 7
    if len(surface.user_data) > 3:        score.attack_surface_bonus += 5

    # ── Kural motoru eşleşmeleri ──────────────────────────────────
    if rule_matches:
        for rm in rule_matches:
            rule = rm.rule
            w = severity_weights.get(rule.severity, 0.5)
            score.base_score += int(rule.score_value * w * 0.8)  # %80 ağırlık

    # ── Combo cezaları ────────────────────────────────────────────
    title_set = {f.title.lower() for f in findings}

    def has(*kws: str) -> bool:
        return any(any(kw in t for t in title_set) for kw in kws)

    # Combo 1: Backend key + auth route
    if has("playfab", "gamesparks", "nakama") and surface.auth:
        score.combo_penalties.append("Backend secret + auth routes: +15")
        score.base_score += 15

    # Combo 2: Anti-cheat bypass + IAP bypass = complete game exploit
    if has("anti-cheat") and has("iap", "receipt"):
        score.combo_penalties.append("Anti-cheat bypass + IAP bypass: +20")
        score.base_score += 20

    # Combo 3: SSL pinning disable + JWT = MITM + session hijack
    if has("ssl", "pinning") and has("jwt"):
        score.combo_penalties.append("SSL pinning disabled + JWT exposed: +15")
        score.base_score += 15

    # Combo 4: PAK encryption key + root bypass = full asset theft
    if has("pak", "encryption") and has("root", "bypass"):
        score.combo_penalties.append("PAK key + root bypass: +15")
        score.base_score += 15

    # Combo 5: Firebase key + payment routes = financial risk
    if has("firebase", "aws") and surface.payment:
        score.combo_penalties.append("Cloud credential + payment routes: +10")
        score.base_score += 10

    # Combo 6: Client-side currency + no server auth = economy collapse
    if has("client-side", "clientvalidat") and has("leaderboard", "score"):
        score.combo_penalties.append("Client-side economy + unauth leaderboard: +15")
        score.base_score += 15

    return score


# ── Exploit öncelik sıralama ──────────────────────────────────────

def rank_findings_by_exploitability(
    findings: list[Finding],
) -> list[tuple[Finding, int]]:
    """
    Bulguları exploit edilebilirlik önceliğine göre sırala.
    (finding, priority_score) tuple listesi döner.
    """
    priority_map = {
        "CONFIRMED":   3,
        "LIKELY":      2,
        "THEORETICAL": 1,
    }
    severity_map = {
        "CRITICAL": 5,
        "HIGH":     4,
        "MEDIUM":   3,
        "LOW":      2,
        "INFO":     1,
    }

    ranked = []
    for f in findings:
        p = (
            priority_map.get(f.exploitability, 1) * 10
            + severity_map.get(f.severity, 1) * 5
            + f.score_value
        )
        ranked.append((f, p))

    ranked.sort(key=lambda x: x[1], reverse=True)
    return ranked


def get_top_findings(
    findings: list[Finding],
    n: int = 5,
) -> list[Finding]:
    """En kritik n bulguyu döner."""
    return [f for f, _ in rank_findings_by_exploitability(findings)[:n]]
