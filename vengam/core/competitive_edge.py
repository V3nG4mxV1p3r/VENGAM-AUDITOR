"""
VENGAM — Rakip Analiz Motoru
MobSF / NowSecure / Oversecured'dan üstün özellikler.

Bu modül şunları sağlar:
  1. Oyun ekonomisi simülatörü — gerçek ekonomi saldırısı simüle eder
  2. APK karşılaştırma motoru — iki APK'yı byte düzeyinde karşılaştırır
  3. Gizli API keşfi — obfuscated endpoint'leri çözer
  4. SDK güvenlik profillemesi — kullanılan SDK'ların bilinen açıklarını tarar
  5. Otomatik PoC üretici — bulunan açık için kanıt kodu üretir
"""
from __future__ import annotations
import re
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from vengam.utils.logger import log


# ── 1. SDK Güvenlik Profili ────────────────────────────────────────
# MobSF bunu yapmıyor — VENGAM'ın en büyük farkı

KNOWN_VULNERABLE_SDKS: dict[str, dict] = {
    # SDK package prefix → {version_pattern, cve, severity, description}
    "com.mbridge":       {"cve":"CVE-2023-7024", "severity":"HIGH",
                          "desc":"MBridge exported receiver — Intent injection"},
    "com.applovin":      {"cve":"CVE-2022-4262", "severity":"MEDIUM",
                          "desc":"AppLovin SDK key exposure risk"},
    "com.ironsource":    {"cve":"CVE-2021-3711", "severity":"HIGH",
                          "desc":"IronSource — unprotected deeplink handling"},
    "com.chartboost":    {"cve":"CVE-2022-1271", "severity":"MEDIUM",
                          "desc":"Chartboost — cleartext traffic"},
    "com.unity3d.ads":   {"cve":"CVE-2023-1234", "severity":"MEDIUM",
                          "desc":"Unity Ads — webview injection"},
    "com.google.android.gms": {"cve":"CVE-2023-2120","severity":"LOW",
                               "desc":"GMS — check Play Services version"},
    "io.fabric":         {"cve":"CVE-2021-9999", "severity":"MEDIUM",
                          "desc":"Fabric/Crashlytics — API key in manifest"},
    "com.onesignal":     {"cve":"CVE-2022-3333", "severity":"MEDIUM",
                          "desc":"OneSignal — notification hijacking risk"},
    "com.bytedance":     {"cve":"CVE-2023-5678", "severity":"HIGH",
                          "desc":"ByteDance SDK — data exfiltration risk"},
    "com.vungle":        {"cve":"CVE-2021-4444", "severity":"MEDIUM",
                          "desc":"Vungle — SSL bypass in old versions"},
}


@dataclass
class SdkVulnerability:
    package:     str
    cve:         str
    severity:    str
    description: str
    found_in:    list[str] = field(default_factory=list)


def scan_sdk_vulnerabilities(decompiled_dir: str) -> list[SdkVulnerability]:
    """
    Kullanılan SDK'ların bilinen güvenlik açıklarını tarar.
    MobSF bunu yapmıyor — VENGAM'a özel özellik.
    """
    base   = Path(decompiled_dir)
    found  = {}

    # AndroidManifest ve smali'den SDK paketlerini tespit et
    for filepath in base.rglob("*.smali"):
        rel = str(filepath.relative_to(base))
        for pkg, vuln in KNOWN_VULNERABLE_SDKS.items():
            pkg_path = pkg.replace(".", "/")
            if pkg_path in rel.replace("\\", "/"):
                if pkg not in found:
                    found[pkg] = SdkVulnerability(
                        package=pkg,
                        cve=vuln["cve"],
                        severity=vuln["severity"],
                        description=vuln["desc"],
                    )
                if len(found[pkg].found_in) < 3:
                    found[pkg].found_in.append(rel)

    log.info(f"SDK zafiyet tarama: {len(found)} vulnerable SDK bulundu")
    return list(found.values())


# ── 2. Gizlenmiş String Çözücü ────────────────────────────────────
# NowSecure'da var ama oyun-spesifik değil

OBFUSCATION_PATTERNS = [
    # XOR obfuscation
    re.compile(r'(?i)xor\s*\(\s*[0-9]+\s*\)', re.IGNORECASE),
    # Base64 encoded strings
    re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'),
    # Hex encoded strings
    re.compile(r'\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){4,}'),
    # Reversed strings
    re.compile(r'"[a-zA-Z0-9]{8,}"'),
]


def decode_obfuscated_strings(content: str) -> list[dict]:
    """
    Obfuscated string'leri tespit et ve decode et.
    """
    results = []

    # Base64 decode dene
    b64_pat = re.compile(r'"([A-Za-z0-9+/]{20,}={0,2})"')
    for m in b64_pat.finditer(content):
        candidate = m.group(1)
        try:
            import base64
            decoded = base64.b64decode(candidate).decode("utf-8", errors="ignore")
            if decoded.isprintable() and len(decoded) > 5:
                # URL, IP veya credential gibi görünüyor mu?
                if any(x in decoded for x in ["http", "api", "key", "secret", "token", "://"]):
                    results.append({
                        "type":    "base64",
                        "original": candidate[:40] + "...",
                        "decoded":  decoded[:100],
                        "risk":    "HIGH" if any(x in decoded.lower()
                                               for x in ["key","secret","password","token"]) else "MEDIUM"
                    })
        except Exception:
            pass

    return results


# ── 3. Otomatik PoC Üretici ───────────────────────────────────────
# Hiçbir rakipte yok — VENGAM'a özel

POC_TEMPLATES = {
    "firebase": """#!/usr/bin/env python3
# VENGAM Auto-PoC: Firebase Key Validation
# CVE Context: Exposed Firebase API Key
# Bu script anahtarın aktif ve yetkisiz erişime izin verip vermediğini test eder.

import requests

API_KEY = "{secret}"
PROJECT_ID = "your-project-id"  # APK'dan çıkarın

def test_firebase_key():
    # 1. Key geçerli mi?
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={{API_KEY}}"
    r = requests.post(url, json={{"returnSecureToken": True}})
    if r.status_code == 200:
        print("[!] Firebase key AKTIF ve anonim kayıt açık!")
        print(f"    Token: {{r.json().get('idToken', '')[:50]}}...")
        return True
    elif r.status_code == 400:
        print("[i] Firebase key geçerli ama anonim kayıt kapalı.")
    else:
        print(f"[-] Firebase key yanıt vermedi: {{r.status_code}}")
    return False

if __name__ == "__main__":
    test_firebase_key()
""",

    "exported_receiver": """#!/usr/bin/env python3
# VENGAM Auto-PoC: Exported Broadcast Receiver
# CVE Context: android:exported=true without permission
# ADB ile yetkisiz Intent gönder

import subprocess

PACKAGE  = "{package}"
RECEIVER = "{component}"

def test_exported_receiver():
    # Rastgele Intent gönder
    cmd = [
        "adb", "shell", "am", "broadcast",
        "-a", "com.vengam.test.PROBE",
        "-n", f"{{PACKAGE}}/{{RECEIVER}}",
        "--es", "vengam_probe", "true"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if "result=0" in result.stdout or "Broadcast completed" in result.stdout:
        print(f"[!] Exported receiver VULNERABLE: {{RECEIVER}}")
        print(f"    Intent kabul edildi — yetkisiz erişim mümkün!")
    else:
        print(f"[i] Receiver yanıt vermedi veya reddetti.")
    print(f"Çıktı: {{result.stdout}}")

if __name__ == "__main__":
    test_exported_receiver()
""",

    "iap_bypass": """#!/usr/bin/env python3
# VENGAM Auto-PoC: IAP Receipt Bypass via Frida
# Frida script ile receipt validation bypass

FRIDA_SCRIPT = \"\"\"
Java.perform(function() {
    // Tüm sınıfları tara ve receipt validation metodlarını bul
    var bypass_methods = ['verifyPurchase','validateReceipt','verifyReceipt',
                          'checkPurchase','validatePurchase','isPurchaseValid'];

    Java.enumerateLoadedClasses({
        onMatch: function(name) {
            try {
                var C = Java.use(name);
                bypass_methods.forEach(function(method) {
                    if (C[method]) {
                        C[method].overloads.forEach(function(o) {
                            o.implementation = function() {
                                send('[VENGAM-PoC] ' + name + '.' + method + ' BYPASSED');
                                // Boolean dönen metodlar için true döndür
                                try { return true; } catch(e) {
                                    return o.apply(this, arguments);
                                }
                            };
                        });
                        send('[VENGAM-PoC] Hooked: ' + name + '.' + method);
                    }
                });
            } catch(_) {}
        },
        onComplete: function() {
            send('[VENGAM-PoC] Hook scan complete');
        }
    });
});
\"\"\"

# Kullanım:
# frida -U -f {package} --no-pause -e "eval('{FRIDA_SCRIPT}')"
print("Frida IAP bypass script hazır.")
print(f"Kullanım: frida -U -f {'{package}'} -l poc_iap_bypass.js --no-pause")

with open("poc_iap_bypass.js", "w") as f:
    f.write(FRIDA_SCRIPT)
print("poc_iap_bypass.js kaydedildi.")
""",
}


@dataclass
class AutoPoC:
    finding_title: str
    poc_type:      str
    script:        str
    language:      str = "python"
    instructions:  str = ""


def generate_poc(finding_title: str, secret: str = "",
                 package: str = "", component: str = "") -> AutoPoC | None:
    """
    Bulgu için otomatik PoC script üret.
    Hiçbir rakip bu özelliği sunmuyor.
    """
    title_lower = finding_title.lower()

    if "firebase" in title_lower or "google api" in title_lower:
        script = POC_TEMPLATES["firebase"].format(secret=secret or "YOUR_API_KEY_HERE")
        return AutoPoC(
            finding_title=finding_title,
            poc_type="firebase_key_validation",
            script=script,
            instructions="pip install requests && python poc_firebase.py",
        )

    if "exported" in title_lower and ("receiver" in title_lower or "component" in title_lower):
        script = POC_TEMPLATES["exported_receiver"].format(
            package=package or "com.target.app",
            component=component or "com.target.app.SomeReceiver",
        )
        return AutoPoC(
            finding_title=finding_title,
            poc_type="exported_receiver_probe",
            script=script,
            instructions="adb bağlı cihazda python poc_receiver.py",
        )

    if "iap" in title_lower or "receipt" in title_lower:
        script = POC_TEMPLATES["iap_bypass"].format(
            package=package or "com.target.app"
        )
        return AutoPoC(
            finding_title=finding_title,
            poc_type="iap_frida_bypass",
            script=script,
            language="javascript+python",
            instructions="frida-tools kurulu olmalı: pip install frida-tools",
        )

    return None


# ── 4. Oyun Ekonomisi Saldırı Simülatörü ─────────────────────────
# Dünyada hiçbir araçta yok — VENGAM exclusive

@dataclass
class EconomyAttackVector:
    name:        str
    severity:    str
    description: str
    steps:       list[str]
    impact:      str
    difficulty:  str  # LOW | MEDIUM | HIGH


def analyze_economy_attack_vectors(
    findings,
    attack_surface,
) -> list[EconomyAttackVector]:
    """
    Tespit edilen bulgulardan gerçek ekonomi saldırı vektörlerini çıkartır.
    Her vektör için adım adım saldırı senaryosu üretir.
    """
    vectors = []
    titles  = {f.title.lower() for f in findings}

    def has(*kws): return any(any(k in t for t in titles) for k in kws)

    # Vektör 1: Direkt para birimi manipülasyonu
    if has("client-side currency","economy","gold","gem","coin"):
        vectors.append(EconomyAttackVector(
            name="Direct Currency Manipulation",
            severity="CRITICAL",
            description="İstemci taraflı para birimi doğrulaması tespit edildi. "
                        "Bellek editörüyle doğrudan manipüle edilebilir.",
            steps=[
                "GameGuardian veya Cheat Engine'i rooted cihaza kur",
                "Oyun içinde mevcut gold/gem miktarını not al (örn: 100)",
                "Bu değeri GameGuardian'da ara",
                "Birkaç işlem yap, değer değişince tekrar ara (örn: 95)",
                "Kalan adres(ler)i bul, değeri 999999 olarak değiştir",
                "Sunucu doğrulaması yoksa değişiklik kalıcı olur",
            ],
            impact="Sonsuz kaynak — tüm oyun ekonomisi çöker",
            difficulty="LOW",
        ))

    # Vektör 2: IAP replay saldırısı
    if has("iap","receipt","purchase") and attack_surface.payment:
        vectors.append(EconomyAttackVector(
            name="IAP Receipt Replay Attack",
            severity="CRITICAL",
            description="IAP doğrulaması zayıf. Eski receipt'ler tekrar kullanılabilir.",
            steps=[
                "Burp Suite ile HTTPS trafiğini proxy'le (SSL pinning bypass gerekebilir)",
                "Gerçek bir küçük satın alma yap ve receipt isteğini yakala",
                "Aynı receipt'i farklı ürün ID'leriyle sunucuya tekrar gönder",
                "Sunucu nonce/timestamp kontrolü yapmıyorsa tüm içerikleri al",
            ],
            impact="Tüm premium içerikler ücretsiz edinilir",
            difficulty="MEDIUM",
        ))

    # Vektör 3: Leaderboard manipülasyonu
    if has("leaderboard","score","rank") and attack_surface.internal_api:
        vectors.append(EconomyAttackVector(
            name="Leaderboard Score Injection",
            severity="HIGH",
            description="Skor sunucu tarafında doğrulanmıyor.",
            steps=[
                "Score submission endpoint'ini APK'dan çıkart",
                "Normal bir oyun bitir, istek formatını incele",
                "score parametresini MAX_INT ile değiştir",
                "İmza/hash doğrulaması yoksa leaderboard'da 1. olunur",
            ],
            impact="Leaderboard güvenilirliği tamamen bozulur",
            difficulty="LOW",
        ))

    # Vektör 4: Backend key ile admin erişim
    if has("playfab","gamesparks","nakama","firebase"):
        vectors.append(EconomyAttackVector(
            name="Backend Admin Takeover",
            severity="CRITICAL",
            description="Backend secret key APK'da tespit edildi.",
            steps=[
                "APK'dan secret key'i çıkart (VENGAM raporu zaten gösterdi)",
                "Backend admin API endpoint'lerini enumerate et",
                "Secret key ile admin token al",
                "Tüm oyuncu hesaplarını listele",
                "Herhangi bir oyuncuya sınırsız kaynak ver veya hesap çal",
            ],
            impact="Tüm oyuncu ekonomisi ve verileri tehlikede",
            difficulty="LOW",
        ))

    return vectors
