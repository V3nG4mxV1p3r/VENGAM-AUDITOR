"""
VENGAM Auditor — Risk Scoring Engine
Combo bonuses awarded for correlated, high-value finding pairs.
"""
from __future__ import annotations
from vengam.core.models import AttackSurface, Finding
from vengam.config import (
    SCORE_BLOCK_RELEASE,
    SCORE_AT_RISK,
)


def calculate_risk(
    findings: list[Finding],
    surface: AttackSurface,
) -> tuple[int, str]:
    """
    Returns (total_score, verdict_string).
    Score is capped at 100.
    """
    score = sum(f.score_value for f in findings)

    # ── Attack surface modifiers ──────────────────────────────────
    if surface.payment:                    score += 15
    if surface.auth:                       score += 10
    if len(surface.internal_api) > 5:      score += 10

    # ── Combo penalties ───────────────────────────────────────────
    titles = {f.title.lower() for f in findings}

    def has(*keywords: str) -> bool:
        return any(any(kw in t for t in titles) for kw in keywords)

    # Key + relevant route
    if has("firebase") and surface.auth:          score += 10
    if has("jwt") and surface.auth:               score += 10
    if has("playfab", "gamesparks", "braincloud") and surface.user_data:
                                                   score += 15
    if has("stripe") and surface.payment:         score += 10

    # Bypass chain — double exposure
    if has("anti-cheat bypass") and has("iap"):   score += 15
    if has("pak encryption") and has("root"):     score += 10

    # Weak crypto + exposed key = amplified risk
    if has("aes-ecb") and has("hardcoded"):       score += 10

    score = max(0, min(100, score))
    verdict = _verdict(score)
    return score, verdict


def _verdict(score: int) -> str:
    if score >= SCORE_BLOCK_RELEASE:
        return "BLOCK RELEASE"
    if score >= SCORE_AT_RISK:
        return "AT RISK — REMEDIATION REQUIRED"
    return "CONDITIONALLY SAFE"


def verdict_explanation(verdict: str) -> tuple[str, str]:
    """Returns (reason, recommended_action)."""
    if verdict == "BLOCK RELEASE":
        return (
            "Critical credentials and high-value attack chains confirmed.",
            "HALT deployment. Rotate ALL exposed credentials. Remediate before re-submission.",
        )
    if "AT RISK" in verdict:
        return (
            "Exploitation vectors exist. Sensitive routes and/or obfuscated secrets exposed.",
            "Security team must validate all endpoints and remove hardcoded secrets before release.",
        )
    return (
        "No critical secrets exposed. Security posture is acceptable.",
        "Approved under standard monitoring protocols. Maintain automated scanning in CI/CD.",
    )


def derive_business_impacts(findings: list[Finding], surface: AttackSurface) -> list[str]:
    impacts: list[str] = []
    titles = " ".join(f.title.lower() + " " + f.secret_type.lower() for f in findings)

    def has(kw: str) -> bool:
        return kw.lower() in titles

    if has("cloud credential") or has("api key"):
        impacts.append("Infrastructure Compromise (Data Exfiltration / Ransomware Pivot)")
    if has("stripe") or surface.payment:
        impacts.append("Financial Fraud & PCI-DSS Compliance Failure")
    if surface.user_data:
        impacts.append("PII Leakage & GDPR / KVKK Non-Compliance")
    if surface.auth:
        impacts.append("Account Takeover (ATO) & Identity Theft")
    if has("private key"):
        impacts.append("TLS Certificate Compromise & Traffic Interception")
    if has("github"):
        impacts.append("Source Code Exfiltration & Supply Chain Attack")
    if has("playfab") or has("gamesparks") or has("braincloud"):
        impacts.append("Game Economy Manipulation & Player Data Breach")
    if has("anti-cheat") or has("iap bypass"):
        impacts.append("Cheating Enablement & Revenue Loss (IAP Bypass)")
    if has("pak encryption"):
        impacts.append("Game IP Theft & Modded Client Distribution")
    if has("photon") or has("agora"):
        impacts.append("Multiplayer Infrastructure Abuse & Player Privacy Violation")
    if has("allowbackup") or has("exported"):
        impacts.append("Android Platform Misconfiguration (Data Leakage via ADB/IPC)")
    return impacts
