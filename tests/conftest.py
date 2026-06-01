"""
VENGAM Auditor — Pytest Shared Fixtures
"""
import datetime
import pytest
from pathlib import Path
from vengam.core.models import (
    Finding, FindingLocation, ScanResult,
    AttackSurface, EngineStats,
)


@pytest.fixture
def sample_finding() -> Finding:
    return Finding(
        title="Google / Firebase API Key",
        severity="CRITICAL",
        confidence="HIGH",
        exploitability="CONFIRMED",
        secret_type="Cloud API Key",
        description="A Firebase API key was found.",
        simulation="Attacker calls Firebase REST API.",
        score_value=30,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cwe_id="CWE-798",
        owasp_ref="M9: Insecure Data Storage",
        category="General",
        triage_note="Verify Firebase security rules.",
        locations=[
            FindingLocation(
                file="smali/com/studio/Config.smali",
                line=42,
                snippet='const-string v0, "AIzaSy..."',
                redacted_match="AIza****...Xq2a",
            )
        ],
    )


@pytest.fixture
def sample_scan_result(sample_finding) -> ScanResult:
    surface = AttackSurface(
        auth={"/auth/login", "/auth/refresh"},
        payment={"/pay/checkout"},
        user_data={"/api/v1/player"},
        internal_api={"/api/v1/game", "/api/v2/leaderboard"},
        other={"/cdn/assets"},
    )
    return ScanResult(
        apk_name="TestGame.apk",
        apk_sha256="abc123def456" * 4,
        scan_timestamp=datetime.datetime.utcnow().isoformat() + "Z",
        findings=[sample_finding],
        dynamic_findings=[],
        attack_surface=surface,
        total_score=55,
        verdict="AT RISK — REMEDIATION REQUIRED",
        engine_stats=EngineStats(
            files_scanned=120,
            lines_scanned=45000,
            fp_suppressed=18,
            patterns_run=42,
            scan_duration_sec=3.7,
        ),
        platform="android",
    )


@pytest.fixture
def mock_apk_dir(tmp_path) -> str:
    """Empty mock decompiled APK directory."""
    d = tmp_path / "decompiled"
    d.mkdir()
    return str(d)


@pytest.fixture
def mock_apk_dir_with_secrets(tmp_path) -> str:
    """Mock decompiled APK directory with embedded secrets."""
    d = tmp_path / "decompiled"
    d.mkdir()

    smali = d / "smali" / "com" / "studio" / "game"
    smali.mkdir(parents=True)

    (smali / "Config.smali").write_text(
        '.class public Lcom/studio/game/Config;\n'
        '.super Ljava/lang/Object;\n\n'
        '.field public static API_KEY:Ljava/lang/String;\n\n'
        '.method static constructor <clinit>()V\n'
        '    const-string v0, "AIzaSyABCDEF1234567890abcdefghijk-XY"\n'
        '    sput-object v0, Lcom/studio/game/Config;->API_KEY:Ljava/lang/String;\n'
        '    return-void\n'
        '.end method\n',
        encoding="utf-8",
    )

    assets = d / "assets"
    assets.mkdir()
    (assets / "game_config.json").write_text(
        '{\n'
        '  "playfab_secret_key": "ABCDEFGHIJKLMNOPQRST12345678",\n'
        '  "environment": "production"\n'
        '}\n',
        encoding="utf-8",
    )

    manifest = d / "AndroidManifest.xml"
    manifest.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
        '    package="com.studio.game">\n'
        '    <application\n'
        '        android:allowBackup="true"\n'
        '        android:label="TestGame">\n'
        '    </application>\n'
        '</manifest>\n',
        encoding="utf-8",
    )

    return str(d)
