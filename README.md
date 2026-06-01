<div align="center">

<img src="https://img.shields.io/badge/VENGAM-Auditor-22c55e?style=for-the-badge&labelColor=0b0e0b&color=22c55e" alt="VENGAM Auditor">

```
 ██╗   ██╗███████╗███╗   ██╗ ██████╗  █████╗ ███╗   ███╗
 ██║   ██║██╔════╝████╗  ██║██╔════╝ ██╔══██╗████╗ ████║
 ██║   ██║█████╗  ██╔██╗ ██║██║  ███╗███████║██╔████╔██║
 ╚██╗ ██╔╝██╔══╝  ██║╚██╗██║██║   ██║██╔══██║██║╚██╔╝██║
  ╚████╔╝ ███████╗██║ ╚████║╚██████╔╝██║  ██║██║ ╚═╝ ██║
   ╚═══╝  ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝
```

### Professional Mobile Game Security Analysis Platform

[![Python](https://img.shields.io/badge/Python-3.11+-22c55e?style=flat-square&logo=python&logoColor=white&labelColor=0b0e0b)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-22c55e?style=flat-square&logo=fastapi&logoColor=white&labelColor=0b0e0b)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square&labelColor=0b0e0b)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Android%20%7C%20iOS-22c55e?style=flat-square&labelColor=0b0e0b)](https://github.com/vengam/vengam-auditor)
[![Patterns](https://img.shields.io/badge/Detection%20Patterns-42+-22c55e?style=flat-square&labelColor=0b0e0b)](vengam/patterns/)
[![Stars](https://img.shields.io/github/stars/vengam/vengam-auditor?style=flat-square&labelColor=0b0e0b&color=22c55e)](https://github.com/vengam/vengam-auditor)

**VENGAM Auditor** is a professional security analysis platform built specifically for mobile games. It statically and dynamically analyzes Android APK and iOS IPA files, detecting game economy exploits, anti-cheat bypasses, embedded credentials, and attack surfaces with game-specific intelligence unavailable in any other tool.

[Features](#-features) · [Installation](#-installation) · [Usage](#-usage) · [Architecture](#-architecture) · [Patterns](#-detection-patterns) · [Contributing](#-contributing)

</div>

---

## 📸 Screenshots

<div align="center">

| Web Dashboard | Finding Detail | Scan Results |
|---|---|---|
| Upload & Scan | Triage Guidance | Risk Score |

</div>

---

## 🎯 Why VENGAM?

Existing mobile security tools (MobSF, NowSecure, Oversecured) are general-purpose and fall short when it comes to game-specific vulnerabilities. VENGAM is designed from the ground up for game security researchers:

| Feature | VENGAM | MobSF | NowSecure |
|---|:---:|:---:|:---:|
| Game economy patterns | ✅ | ❌ | ❌ |
| PlayFab / Nakama / Xsolla detection | ✅ | ❌ | ❌ |
| IL2CPP deep analysis | ✅ | ⚠️ | ✅ |
| Auto Frida hook generator | ✅ | ❌ | ❌ |
| Anti-cheat bypass detection | ✅ | ⚠️ | ⚠️ |
| Attack graph visualization | ✅ | ❌ | ❌ |
| Automatic PoC generator | ✅ | ❌ | ❌ |
| YAML rule engine | ✅ | ❌ | ❌ |
| Plugin system | ✅ | ⚠️ | ❌ |
| Diff / version comparison | ✅ | ❌ | ⚠️ |
| Free & open source | ✅ | ✅ | ❌ |

---

## ✨ Features

### 🔍 Static Analysis

- **42+ game-specific detection patterns** — Firebase, AWS, PlayFab, Nakama, Xsolla, Photon, Unity Cloud, GameSparks, LootLocker and more
- **11-layer false positive filter** — Ad SDKs (MBridge, AppLovin, ByteDance), Huawei AGC, and AndroidX libraries are automatically suppressed
- **Android Manifest analysis** — `allowBackup`, exported components, network security config
- **iOS plist analysis** — ATS, FaceID, URL schemes, background modes
- **Shannon entropy analysis** — High-entropy embedded string detection
- **Attack surface mapping** — Auth, Payment, User Data, and Internal API endpoints automatically categorized

### 🎮 Game Security

- **Economy abuse detection** — IAP bypass, client-side currency validation, receipt validation bypass
- **Anti-cheat analysis** — God mode, debug flags, speed hack, wallhack, memory protection bypass
- **Game engine patterns** — Unity IL2CPP, Unreal PAK encryption, Photon, EOS, GameAnalytics
- **Economy attack simulator** — Generates real attack scenarios from detected vulnerabilities
- **Multiplayer security** — Client-authoritative game state, unsigned messages, predictable room IDs

### 🦎 Dynamic Analysis (Frida)

- **Auto Frida hook generator** — Generates ready-to-use JavaScript scripts based on findings
- **SSL pinning bypass** — OkHttp, TrustManager automatic hooking
- **Root/emulator detection bypass** — Bypasses 4+ common detection methods
- **IAP receipt bypass** — Automatic `verifyPurchase`, `validateReceipt` hooks
- **Crypto key extractor** — Runtime key extraction via `Cipher.init`, `SecretKeySpec`
- **Economy monitor** — Hooks `getGold`, `getCurrency`, `addGems` methods
- **iOS hooks** — SSL, StoreKit, Keychain, LAContext, WKWebView

### 🧠 Intelligence Layer

- **IL2CPP Deep Parser** — Class/method reconstruction from Unity IL2CPP binaries, security hit detection
- **Endpoint Intelligence** — GraphQL, WebSocket, and Protobuf endpoint detection
- **Attack Graph** — D3.js force-directed attack graph with 5 auto-detected attack chains
- **SDK Vulnerability Profiler** — Scans for known CVEs in 10+ ad/analytics SDKs
- **Obfuscated String Decoder** — Decodes Base64 and hex-encoded strings

### 📊 Reporting

- **TXT** — Human-readable full report
- **JSON** — Machine-readable for CI/CD pipeline integration
- **SARIF** — Direct integration with GitHub Code Scanning
- **PDF** — Cover page, executive summary, full finding details (WeasyPrint)
- **Diff Report** — Security changes between two APK versions (NEW/FIXED/WORSENED/IMPROVED)

### 🔌 Plugin System

```python
# vengam/plugins/community/my_scanner.py
class MyScanner(ScannerPlugin):
    def scan(self, decompiled_dir: str, platform: str) -> list[Finding]:
        # Add your own analysis logic
        return findings
```

Researchers can extend VENGAM by dropping a Python file into `vengam/plugins/community/`. Plugins are automatically discovered and loaded.

### 🏢 Enterprise

- **JWT Authentication** — Token-based auth, refresh tokens, brute-force protection
- **Multi-Tenant** — Organization-level isolation with API key support
- **Audit Log** — GDPR/SOC2 compliant, all actions logged in JSONL format
- **Rate Limiting** — Scan: 3/min, History: 30/min, Reports: 20/min

### 🔧 DevOps

- **GitHub Action** — CI/CD integration via `uses: ./phantom-action`
- **Docker** — Multi-stage build, production-ready
- **Exit codes** — `0` SAFE · `1` AT RISK · `2` BLOCK RELEASE ← halts pipeline

---

## 🚀 Installation

### Requirements

| Requirement | Minimum | Recommended |
|---|:---:|:---:|
| Python | 3.11 | 3.12 |
| Java | 11 | 17 |
| RAM | 2 GB | 4 GB |
| Disk | 1 GB | 4 GB |

### Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/vengam/vengam-auditor.git
cd vengam-auditor

# 2. Install apktool (required for Android analysis)
# Windows:
mkdir C:\apktool
curl -L https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar -o C:\apktool\apktool.jar

# Linux/macOS:
mkdir -p ~/apktool
wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar -O ~/apktool/apktool.jar
export VENGAM_APKTOOL=$HOME/apktool/apktool.jar

# 3. Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate     # Windows

# 4. Launch with a single command
python vengam_launcher.py
```

Web UI opens automatically: **http://localhost:8000/ui**

### Docker

```bash
docker-compose up -d
# API: http://localhost:8000
# Web: http://localhost:3000
```

---

## 📖 Usage

### CLI

```bash
# Basic scan
python -m vengam.cli -t MyGame.apk

# Critical findings only
python -m vengam.cli -t MyGame.apk --severity-filter CRITICAL

# Category filter
python -m vengam.cli -t MyGame.apk --category-filter Economy,AntiCheat

# Specify output directory
python -m vengam.cli -t MyGame.apk -o reports/

# iOS IPA
python -m vengam.cli --ios -t MyGame.ipa

# Version comparison
python -m vengam.cli --diff v1.0.apk v1.1.apk -o diff_reports/

# Frida dynamic analysis
python -m vengam.cli -t MyGame.apk --frida --pkg com.studio.mygame
```

### Web Dashboard

```bash
python vengam_launcher.py
# → http://localhost:8000/ui
```

1. Drag and drop or click to select an APK or IPA file
2. Choose platform (Android/iOS) and severity filter
3. Click **RUN SECURITY AUDIT**
4. Filter results in the sidebar, inspect finding cards
5. Download TXT / JSON / SARIF / PDF reports

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: VENGAM Security Scan

on:
  push:
    branches: [main, release/*]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: VENGAM Security Scan
        uses: ./phantom-action
        with:
          apk_path: app/build/outputs/apk/release/app-release.apk
          fail_on:  BLOCK_RELEASE    # Halt the pipeline
          upload_sarif: 'true'       # Upload to GitHub Code Scanning
```

### Python API

```python
from vengam.android.static import scan_directory
from vengam.core.decompiler import decompile_apk
from vengam.reports import json_report

# Scan APK
decompile_apk("MyGame.apk", "output/", force=True)
result = scan_directory("output/", "MyGame.apk")

print(f"Risk Score: {result.total_score}/100")
print(f"Verdict:    {result.verdict}")
print(f"Findings:   {len(result.findings)}")

# Generate report
json_report.generate(result, "report.json")
```

---

## 🏗️ Architecture

```
vengam-auditor/
├── vengam/                    # Core analysis engine
│   ├── core/
│   │   ├── models.py          # ScanResult, Finding, AttackSurface
│   │   ├── risk_engine.py     # Risk score & verdict calculation
│   │   ├── fp_filter.py       # 11-layer false positive filter
│   │   ├── rule_engine.py     # Sigma-like YAML rule engine
│   │   ├── sandbox.py         # Process isolation, ReDoS protection
│   │   ├── scoring.py         # Game-specific threat scoring
│   │   └── workspace.py       # Secure temp file management
│   ├── patterns/
│   │   ├── general.py         # Firebase, AWS, JWT, Stripe, GitHub...
│   │   ├── game_engine.py     # Unity, Unreal, Photon, EOS...
│   │   └── economy_anticheat_config.py
│   ├── android/
│   │   ├── static.py          # Core Android scanning engine
│   │   └── attack_surface.py  # URL/endpoint categorization
│   ├── ios/
│   │   ├── static.py          # iOS IPA scanning engine
│   │   ├── plist_parser.py    # Info.plist security analysis
│   │   └── macho_wrapper.py   # Mach-O binary analysis
│   ├── intel/
│   │   ├── il2cpp_deep.py     # Unity IL2CPP deep analysis
│   │   ├── frida_gen.py       # Auto Frida hook generator
│   │   ├── endpoint.py        # GraphQL/WebSocket/Protobuf detection
│   │   └── attack_graph.py    # Attack graph generator
│   ├── plugins/
│   │   ├── base.py            # Plugin interfaces
│   │   ├── loader.py          # Dynamic plugin discovery & loading
│   │   └── community/         # Researcher plugins
│   ├── rules/community/       # YAML detection rules
│   │   ├── economy.yml
│   │   ├── anticheat.yml
│   │   ├── credentials.yml
│   │   └── multiplayer.yml
│   ├── enterprise/
│   │   ├── multi_tenant.py    # Organization management
│   │   └── audit_log.py       # GDPR/SOC2 audit logging
│   └── reports/
│       ├── text_report.py
│       ├── json_report.py
│       ├── sarif_report.py
│       ├── pdf_report.py
│       └── diff_report.py
├── phantom_api/               # FastAPI backend
│   ├── main.py                # All routers, security headers, rate limiting
│   ├── auth/
│   │   └── jwt_auth.py        # JWT tokens, bcrypt, brute-force protection
│   ├── routers/
│   │   ├── scan.py            # APK/IPA upload & analysis
│   │   ├── reports.py         # Report downloads
│   │   ├── history.py         # Scan history
│   │   ├── auth.py            # Login/logout/refresh
│   │   ├── intel.py           # Attack graph, Frida, IL2CPP
│   │   └── enterprise.py      # Org management, audit log
│   └── db/
│       └── database.py        # SQLite/PostgreSQL async ORM
├── phantom_native/            # Rust native engine
│   └── src/
│       ├── parallel_scan.rs   # Rayon multi-thread pattern scanning
│       ├── elf_deep.rs        # ELF/JNI deep analysis
│       ├── il2cpp.rs          # IL2CPP metadata parser
│       ├── string_extractor.rs
│       └── entropy.rs
├── phantom-action/            # GitHub Action
│   └── action.yml
├── vengam_ui/
│   └── dashboard.html         # Standalone web dashboard
├── frida-scripts/
│   ├── android-hooks.js       # Android Frida hooks
│   └── ios-hooks.js           # iOS Frida hooks
├── docs/
│   ├── INSTALL.md
│   └── TESTING.md
├── tests/
│   ├── unit/                  # 130+ unit tests
│   └── integration/           # End-to-end integration tests
├── docker-compose.yml
├── Dockerfile
├── vengam_launcher.py         # Single-command launcher
└── vengam_cleanup.py          # Storage cleanup utility
```

---

## 🎯 Detection Patterns

### Credential Exposure (CRITICAL)

| Pattern | Description |
|---|---|
| Firebase / Google API Key | `AIza[0-9A-Za-z\-_]{35}` |
| AWS Access Key | `AKIA[0-9A-Z]{16}` |
| GitHub Personal Access Token | `ghp_[A-Za-z0-9]{36}` |
| Stripe Live Secret | `sk_live_[A-Za-z0-9]{24,}` |
| JWT Token | `eyJ[A-Za-z0-9]{10,}\.eyJ[A-Za-z0-9]{10,}` |
| RSA Private Key | `-----BEGIN RSA PRIVATE KEY-----` |
| PlayFab Secret Key | `[A-Z0-9]{32}` near `playfab` |
| Nakama Server Key | near `nakama`, `defaultkey` |
| Twilio SID + Auth Token | `AC[a-f0-9]{32}` |
| Agora App Certificate | near `agora`, `appCertificate` |

### Game Security (CRITICAL/HIGH)

| Pattern | Category |
|---|---|
| IAP Receipt Validation Disabled | Economy |
| Anti-Cheat Bypass String | AntiCheat |
| Client-Side Currency Validation | Economy |
| SSL Certificate Pinning Disabled | AntiCheat |
| Root/Jailbreak Detection Bypass | AntiCheat |
| God Mode / Debug Flag | AntiCheat |
| Unreal PAK Encryption Key | GameEngine |
| Unity Cloud Build Key | GameEngine |
| PlayFab Economy Config | Economy |
| Leaderboard Score Manipulation | Economy |

### Android Manifest (MEDIUM)

| Pattern | CWE |
|---|---|
| `android:allowBackup="true"` | CWE-312 |
| Exported component without permission | CWE-926 |
| Cleartext traffic enabled | CWE-319 |
| Debuggable release build | CWE-489 |

---

## 🔴 Risk Score & Verdict

```
0  – 39  →  CONDITIONALLY SAFE     (release approved)
40 – 74  →  AT RISK                (remediation required)
75 – 100 →  BLOCK RELEASE          (halt deployment)
```

### Game-Specific Scoring Factors

- **Economy Abuse Risk** — IAP bypass, currency hack, leaderboard manipulation
- **Multiplayer Risk** — Client-authoritative state, packet injection
- **Anti-Cheat Bypass** — God mode, memory protection bypass
- **Credential Exposure** — API key, secret, token leakage
- **Combo Penalties** — Anti-cheat + IAP found together: +20 bonus penalty

---

## 🦎 Frida Integration

```bash
# 1. Install and start frida-server on device
adb push frida-server /data/local/tmp/
adb shell chmod +x /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# 2. Dynamic analysis with VENGAM
python -m vengam.cli -t MyGame.apk --frida --pkg com.studio.mygame

# 3. Use pre-built scripts
frida -U -f com.studio.mygame -l frida-scripts/android-hooks.js --no-pause
```

### Auto Hook Generation

VENGAM generates Frida scripts automatically based on static analysis findings:

```python
from vengam.intel.frida_gen import FridaHookGenerator

gen    = FridaHookGenerator()
script = gen.generate_from_findings(findings, "MyGame.apk")
# → Ready-to-run JavaScript Frida script
```

---

## 📝 YAML Rule Engine

Researchers can write custom detection rules in YAML format:

```yaml
# vengam/rules/community/my_rules.yml
id: CUSTOM-001
title: "Custom Economy Exploit Pattern"
severity: CRITICAL
confidence: HIGH
category: Economy
platform: android

detection:
  pattern: '(?i)(free_currency|bypass_payment|skip_purchase)\s*=\s*(true|1)'
  file_ext: [.smali, .java, .kt]

context:
  require_keywords: [game, economy]
  exclude_paths: [androidx, test]

simulation: "Attacker activates this flag to skip payment steps."
triage_note: "Validate this value server-side."
frida_hook: |
  Java.use('com.game.Economy').bypass_payment.implementation = function() {
    return false;
  };
score_value: 35
```

---

## 🧪 Testing

```bash
# All tests (130+)
pytest tests/ -v

# Unit tests only
pytest tests/unit/ -v

# Integration tests
pytest tests/integration/ -v

# Coverage report
pytest tests/ --cov=vengam --cov-report=html
```

---

## 🔒 Security Architecture

VENGAM protects itself against malicious APKs:

- **Process Isolation** — Every scan runs in an isolated subprocess
- **Timeout Control** — Maximum 10-minute scan duration
- **Memory Limiting** — 2 GB RAM limit (Unix)
- **ReDoS Protection** — Regex patterns run with timeout
- **Secure Temp Files** — Files written to `_workspace/`, automatically deleted after scan
- **File Validation** — Magic bytes check, extension verification, path injection protection
- **Rate Limiting** — Per-IP request limits on all API endpoints
- **Security Headers** — X-Frame-Options, CSP, XSS-Protection, nosniff

---

## 🐳 Docker

```bash
# Start all services
docker-compose up -d

# API only
docker build -t vengam-auditor .
docker run -p 8000:8000 vengam-auditor

# Health check
curl http://localhost:8000/api/health
```

---

## 🔌 API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/scan/android` | POST | Upload and scan APK |
| `/api/scan/ios` | POST | Upload and scan IPA |
| `/api/reports/{id}/{fmt}` | GET | Download report (txt/json/sarif/pdf) |
| `/api/history` | GET | Scan history |
| `/api/history/{id}` | DELETE | Delete scan |
| `/api/intel/attack-graph/{id}` | GET | Attack graph |
| `/api/intel/frida/{id}` | GET | Frida script |
| `/api/intel/il2cpp/{id}` | GET | IL2CPP analysis |
| `/api/auth/login` | POST | Get JWT token |
| `/api/auth/refresh` | POST | Refresh token |
| `/api/health` | GET | Health check |

Swagger UI: `http://localhost:8000/docs`

---

## 🤝 Contributing

Contributions are welcome! Especially:

- 🎮 New game engine patterns (Godot, Cocos2d, LibGDX...)
- 🦎 Frida hook templates
- 📝 YAML rule contributions (`vengam/rules/community/`)
- 🔌 Plugin development (`vengam/plugins/community/`)
- 🐛 Bug reports and fixes

```bash
# Fork → Branch → Commit → PR
git checkout -b feature/new-pattern
git commit -m "feat: add Godot engine detection patterns"
git push origin feature/new-pattern
```

---

## 📄 License

MIT License — See [LICENSE](LICENSE) for details.

---

## ⚠️ Disclaimer

VENGAM Auditor is designed exclusively for **authorized security testing** and **research purposes**. Only use this tool on applications you own or have explicit written permission to test. Unauthorized use is illegal and unethical.

---

<div align="center">

**VENGAM Auditor** — Built for game security researchers, by game security researchers.

[![GitHub](https://img.shields.io/badge/GitHub-vengam--auditor-22c55e?style=flat-square&logo=github&labelColor=0b0e0b)](https://github.com/vengam/vengam-auditor)

</div>
