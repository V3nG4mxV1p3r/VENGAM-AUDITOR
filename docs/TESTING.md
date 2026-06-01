# VENGAM Auditor — Test Kılavuzu

## Test Yapısı

```
tests/
├── conftest.py              # Shared fixtures
├── unit/
│   ├── test_sprint1.py      # Core engine, patterns, FP filter
│   ├── test_sprint2.py      # iOS IPA analizi
│   ├── test_sprint3.py      # Native binary engine
│   ├── test_sprint4.py      # FastAPI endpoints (opsiyonel)
│   ├── test_sprint5.py      # PDF rapor, diff scan
│   └── test_sprint7.py      # Son birim testler
└── integration/
    └── test_integration.py  # Uçtan uca entegrasyon testleri
```

---

## Testleri Çalıştırma

```bash
# Tüm testler
pytest tests/ -v

# Sadece unit testler
pytest tests/unit/ -v

# Sadece entegrasyon testleri
pytest tests/integration/ -v

# Belirli bir test dosyası
pytest tests/unit/test_sprint1.py -v

# Belirli bir test
pytest tests/unit/test_sprint1.py::TestFalsePositiveFilter::test_firebase_key -v

# Coverage raporu ile
pip install pytest-cov
pytest tests/ --cov=vengam --cov-report=html
# → htmlcov/index.html
```

---

## Manuel Test Senaryoları

### 1. Firebase API Key Tespiti

```bash
# Test dosyası oluştur
mkdir -p test_apk/smali/com/studio/game
cat > test_apk/smali/com/studio/game/Config.smali << 'EOF'
.class public Lcom/studio/game/Config;
.super Ljava/lang/Object;
.field public static API_KEY:Ljava/lang/String; = "AIzaSyABCDEF1234567890abcdefghijk-XY"
EOF

# Dizin olarak tara
vengam --dir test_apk/ -o test_reports/

# Beklenen: Firebase API Key CRITICAL bulgusu
```

### 2. False Positive — Huawei AGC

```bash
mkdir -p test_fp/res/values
cat > test_fp/res/values/agc_config.xml << 'EOF'
<?xml version="1.0"?>
<resources>
  <string name="agc_account_sid">ACabc123def456abc123def456abc12345</string>
</resources>
EOF

vengam --dir test_fp/ -o test_fp_reports/

# Beklenen: Twilio SID bulgusu OLMAMALI (FP suppress)
```

### 3. Severity Filter

```bash
vengam --dir test_apk/ --severity-filter CRITICAL -o reports/
# Beklenen: Sadece CRITICAL bulgular
```

### 4. Category Filter

```bash
vengam --dir test_apk/ --category-filter Economy,AntiCheat -o reports/
# Beklenen: Sadece Economy ve AntiCheat kategorisi
```

### 5. iOS IPA Scan

```bash
# IPA dosyanız varsa
vengam --ios -t MyGame.ipa -o ios_reports/
```

### 6. Diff Scan

```bash
vengam --diff v1.0.apk v1.1.apk -o diff_reports/
# Çıktı: diff_v1.0_vs_v1.1.txt ve diff_v1.0_vs_v1.1.json
```

### 7. Web Dashboard

```bash
# Backend başlat
uvicorn phantom-api.main:app --reload --port 8000

# Tarayıcıda aç
# http://localhost:8000/docs   → API Swagger UI
# http://localhost:3000        → React Dashboard
```

---

## Test Fixtures (conftest.py)

```python
# Hazır fixture kullanımı
def test_my_feature(sample_finding, sample_scan_result, mock_apk_dir_with_secrets):
    # sample_finding         → Firebase CRITICAL Finding nesnesi
    # sample_scan_result     → Tam ScanResult nesnesi
    # mock_apk_dir_with_secrets → Gizli anahtarlı mock APK dizini
    pass
```

---

## CI/CD Test Komutu

```yaml
# GitHub Actions'ta
- name: Run tests
  run: |
    pip install -e ".[dev]"
    pytest tests/ -v --tb=short --cov=vengam \
      --cov-report=xml --cov-fail-under=70
```

---

## Beklenen Test Sonuçları

| Test Grubu | Test Sayısı | Süre |
|---|---|---|
| Unit Sprint 1 | 20 | ~2s |
| Unit Sprint 2 | 22 | ~3s |
| Unit Sprint 3 | 28 | ~2s |
| Unit Sprint 5 | 34 | ~3s |
| Integration | 25 | ~10s |
| **Toplam** | **~130** | **~20s** |
