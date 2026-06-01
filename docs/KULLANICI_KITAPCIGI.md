# VENGAM Auditor v7.0
## Kullanıcı El Kitapçığı

---

## Bu Tool Nedir?

VENGAM Auditor, Android ve iOS mobil oyunlarını güvenlik açıkları
açısından otomatik olarak analiz eden profesyonel bir güvenlik aracıdır.

**Ne yapar?**
- APK veya IPA dosyasını decompile eder
- 42+ güvenlik pattern'ini tarar
- Gömülü API key, şifre, token, bypass string tespit eder
- Oyun ekonomisi açıklarını (IAP bypass, client-side currency) bulur
- Anti-cheat bypass ve debug flag'lerini saptar
- Android Manifest güvenlik hatalarını raporlar
- Saldırı yüzeyi (API endpoint'leri) haritalandırır
- Frida ile runtime analiz yapar
- TXT, JSON, SARIF, PDF formatında rapor üretir

**Kimin için?**
- Mobil oyun güvenlik araştırmacıları
- Game studio güvenlik ekipleri
- Pentest uzmanları
- CI/CD pipeline entegrasyonu

---

## Kurulum (Hızlı Başlangıç)

```bash
# 1. Klasöre gir
cd VENGAM

# 2. Sanal ortam oluştur
python -m venv .venv

# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# 3. Kur
pip install -e .

# 4. apktool yolunu ayarla (AndroidManifest için)
# Windows — config.py içinde zaten C:\apktool\apktool.jar yazıyor
# Değiştirmek için:
set VENGAM_APKTOOL=C:\apktool\apktool.jar
```

---

## Temel Kullanım

### Android APK Tarama

```bash
# Standart tarama — tüm formatlar
vengam -t MyGame.apk

# Sadece kritik bulgular
vengam -t MyGame.apk --severity-filter CRITICAL

# Sadece kritik ve yüksek
vengam -t MyGame.apk --severity-filter CRITICAL,HIGH

# Sadece oyun ekonomisi kategorisi
vengam -t MyGame.apk --category-filter Economy

# Anti-cheat + ekonomi kategorileri
vengam -t MyGame.apk --category-filter Economy,AntiCheat

# Raporu belirli klasöre kaydet
vengam -t MyGame.apk -o C:\raporlar\

# Sadece JSON çıktısı
vengam -t MyGame.apk --format json

# Zaten decompile edilmiş dizin
vengam --dir MyGame_vengam_out\
```

### iOS IPA Tarama

```bash
vengam --ios -t MyGame.ipa
vengam --ios -t MyGame.ipa --severity-filter CRITICAL,HIGH
```

### Frida ile Dinamik Analiz

```bash
# Önce frida-server'ı cihazda başlat:
adb shell /data/local/tmp/frida-server &

# Statik + dinamik birlikte
vengam -t MyGame.apk --frida --pkg com.studio.mygame

# Sadece Frida (APK taramadan)
vengam --frida --pkg com.studio.mygame --timeout 90
```

### Versiyon Karşılaştırma

```bash
# v1 ile v2 arasındaki güvenlik değişiklikleri
vengam --diff v1.0.apk v1.1.apk -o diff_raporlar\

# Çıktı:
# diff_v1.0_vs_v1.1.txt  → okunabilir karşılaştırma
# diff_v1.0_vs_v1.1.json → makine-okunabilir
```

### Web Dashboard

```bash
# Backend başlat
pip install fastapi uvicorn sqlalchemy aiosqlite python-multipart
uvicorn phantom-api.main:app --reload --port 8000

# Frontend başlat (ayrı terminal)
cd phantom-web
npm install
npm run dev

# Aç: http://localhost:3000
```

---

## Çıktı Dosyaları

Tarama sonunda output dizininde şu dosyalar oluşur:

```
raporlar/
├── MyGame_vengam_report.txt    ← İnsan okunabilir tam rapor
├── MyGame_vengam_report.json   ← CI/CD entegrasyonu için
└── MyGame_vengam_report.sarif  ← GitHub Code Scanning için
```

### TXT Rapor Bölümleri
1. **SCAN METADATA** — Hedef, SHA-256, tarama süresi
2. **EXECUTIVE SUMMARY** — Risk skoru, verdict, business riskler
3. **STATIC FINDINGS** — Tüm bulgular (severity, lokasyon, triage)
4. **DYNAMIC FINDINGS** — Frida runtime bulguları (varsa)
5. **ATTACK SURFACE** — Bulunan API endpoint'leri
6. **RISK SCORE BREAKDOWN** — Puan hesaplama detayı
7. **REMEDIATION** — Düzeltme önerileri
8. **FINAL VERDICT** — Release kararı

---

## Bulgular ve Kategoriler

### Severity Seviyeleri

| Seviye | Anlam | Örnek |
|---|---|---|
| 🔴 CRITICAL | Anında exploit edilebilir | Firebase key, PlayFab secret, PAK encryption key |
| 🟠 HIGH | Yüksek risk, kısa sürede exploit | JWT token, debug flag, SSL pinning disabled |
| 🟡 MEDIUM | Orta risk, ek şart gerekebilir | AES-ECB kullanımı, exported component |
| 🔵 LOW | Düşük risk, bilgi amaçlı | allowBackup=true, insecure RNG |
| ⚪ INFO | Bilgi amaçlı | Unity remote config URL |

### Kategoriler

| Kategori | İçerik |
|---|---|
| **General** | Firebase, AWS, Stripe, JWT, GitHub PAT, Twilio, Agora, Xsolla |
| **GameEngine** | Unity Cloud Build, IL2CPP, Unreal PAK key, EOS, Photon, GameAnalytics |
| **Economy** | PlayFab, GameSparks, Nakama, LootLocker, Braincloud, IAP bypass |
| **AntiCheat** | Bypass string, god mode, root detection disable, SSL pinning disable |
| **Config** | AndroidManifest, network_security_config, allowBackup, exported component |

---

## Risk Skoru ve Verdict

```
0–39   → CONDITIONALLY SAFE     (release onayı)
40–74  → AT RISK                (remediation gerekli)
75–100 → BLOCK RELEASE          (yayın durdurulmalı)
```

### Exit Kodları (CI/CD için)

```
0 → CONDITIONALLY SAFE
1 → AT RISK
2 → BLOCK RELEASE  ← pipeline bu kodda durmalı
3 → HIGH bulgu var, CRITICAL yok
```

---

## APKPure'den İndirilen APK Testi

### Adım Adım

```bash
# 1. APKPure'den APK indir (örnek: herhangi bir oyun)

# 2. Klasörüne koy
mkdir C:\vengam_test
# APK'yı C:\vengam_test\ içine koy

# 3. Temel tarama
cd VENGAM
vengam -t C:\vengam_test\oyun.apk -o C:\vengam_test\raporlar\

# 4. Sadece kritik bul
vengam -t C:\vengam_test\oyun.apk --severity-filter CRITICAL -o C:\vengam_test\raporlar\

# 5. Raporu oku
# C:\vengam_test\raporlar\oyun_vengam_report.txt dosyasını aç
```

### Test Sırasında Ne Göreceksin?

```
╔══════════════════════════════════════════════════════════════════╗
║      VENGAM Auditor  ·  v7.0  Professional Edition               ║
╚══════════════════════════════════════════════════════════════════╝

10:23:45  [INFO]  Checking apktool dependency...
10:23:45  [INFO]  apktool OK (2.9.3)
10:23:45  [INFO]  Decompiling oyun.apk ...
10:24:12  [INFO]  Decompilation complete → oyun_vengam_out
10:24:12  [INFO]  === PHASE 2: STATIC ANALYSIS ===
10:24:12  [INFO]  Patterns loaded: 42
10:24:18  [INFO]  Scan done: 1240 files | 387,450 lines | 7 findings | 23 FP suppressed | 6.2s

════════════════════════════════════════════════════════════════
  SCAN COMPLETE  —  oyun.apk
  Risk Score       : 45 / 100
  Verdict          : AT RISK — REMEDIATION REQUIRED
  Static Findings  : 7
  FP Suppressed    : 23
  Scan Duration    : 6.2s
  Reports saved to : C:\vengam_test\raporlar\
════════════════════════════════════════════════════════════════
```

---

## Sık Karşılaşılan Durumlar

### "apktool bulunamıyor" Hatası

```bash
# Java kurulu mu?
java -version

# VENGAM_APKTOOL doğru mu?
echo %VENGAM_APKTOOL%   # Windows
echo $VENGAM_APKTOOL    # Linux

# Manuel ayarla
set VENGAM_APKTOOL=C:\apktool\apktool.jar
```

### "Çok fazla bulgu geliyor"

```bash
# Sadece kritik ve yüksek göster
vengam -t oyun.apk --severity-filter CRITICAL,HIGH

# Sadece oyun kategorileri
vengam -t oyun.apk --category-filter GameEngine,Economy,AntiCheat
```

### "False positive şüphem var"

TXT rapordaki **TRIAGE GUIDANCE** bölümünü oku.
Her bulgu için `▶` ile başlayan satır manuel doğrulama rehberi verir.

### Büyük APK yavaş tarıyor

```bash
# Önceki decompile'ı yeniden kullan
vengam --dir oyun_vengam_out\ -o raporlar\

# Sadece kritik tara (daha hızlı)
vengam -t oyun.apk --severity-filter CRITICAL
```

---

## Test Sonuçlarını Yorumlama

### Gerçek Bulgu mu, False Positive mi?

Her bulguda şunlara bak:

1. **Confidence: HIGH** → Gerçek olma ihtimali yüksek
2. **Confidence: MEDIUM** → Manuel doğrulama gerekli
3. **TRIAGE GUIDANCE** → ▶ ile başlayan satır sana ne yapacağını söyler
4. **Lokasyon** → Dosya yoluna bak, oyun kodu mu yoksa 3. parti lib mi?

### Örnek Yorum

```
[01] 🔴 CRITICAL  [General]  —  Google / Firebase API Key
      Type           : Cloud API Key
      Confidence     : HIGH
      Exploitability : CONFIRMED
      Score Impact   : +30 pts

      TRIAGE GUIDANCE
      ▶ Verify Firebase security rules — key alone may not grant
      ▶ write access if rules require auth.

      LOCATIONS
        → smali/com/studio/Config.smali  :  line 42
          const-string v0, "AIza..."
          Matched: AIza****...Xq2a
```

**Bu bulgu için yapılacaklar:**
1. Firebase Console'a gir
2. Security Rules'u kontrol et — kimlik doğrulama gerektiriyor mu?
3. Key'i rotate et
4. Key'i APK'dan kaldır, sunucu tarafına taşı

---

## GitHub Action Entegrasyonu

```yaml
# .github/workflows/security.yml
- name: VENGAM Security Scan
  uses: ./phantom-action
  with:
    apk_path: app/build/outputs/apk/release/app-release.apk
    fail_on:  BLOCK_RELEASE
```

---

## Destek ve Geri Bildirim

- Yanlış tespit (false positive) gördüysen: pattern'i ve dosya yolunu not al
- Yeni pattern önerileri için: `vengam/patterns/` altındaki dosyalara ekle
- Test sonuçlarını paylaş — tool'u birlikte geliştiriyoruz
