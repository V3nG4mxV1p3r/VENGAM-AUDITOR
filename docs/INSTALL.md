# VENGAM Auditor — Kurulum Kılavuzu

## Sistem Gereksinimleri

| Gereksinim | Minimum | Önerilen |
|---|---|---|
| Python | 3.11 | 3.12 |
| Java | 11 | 17 |
| RAM | 2 GB | 4 GB |
| Disk | 500 MB | 2 GB |
| İşletim Sistemi | Windows 10 / Ubuntu 20.04 / macOS 12 | — |

---

## 1. Python Kurulumu

```bash
# Python 3.11+ gerekli
python --version   # Python 3.11.x olmalı

# Repository klonla
git clone https://github.com/vengam/gamesec.git
cd gamesec

# Sanal ortam oluştur (önerilir)
python -m venv .venv

# Aktifleştir
# Windows:
.venv\Scripts\activate
# Linux / macOS:
source .venv/bin/activate

# Temel kurulum
pip install -e .

# Web dashboard ile
pip install -e ".[web]"

# PDF rapor ile
pip install -e ".[pdf]"

# Frida dinamik analiz ile
pip install -e ".[frida]"

# Her şey
pip install -e ".[all]"
```

---

## 2. apktool Kurulumu (Android için zorunlu)

### Windows

```powershell
# apktool klasörü oluştur
New-Item -ItemType Directory -Path C:\apktool

# apktool.jar indir
Invoke-WebRequest `
  -Uri "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar" `
  -OutFile "C:\apktool\apktool.jar"

# VENGAM_APKTOOL ortam değişkeni ayarla
[System.Environment]::SetEnvironmentVariable(
  "VENGAM_APKTOOL", "C:\apktool\apktool.jar", "User"
)
```

### Linux / macOS

```bash
mkdir -p ~/apktool
wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar \
     -O ~/apktool/apktool.jar

# .bashrc veya .zshrc'ye ekle
echo 'export VENGAM_APKTOOL=$HOME/apktool/apktool.jar' >> ~/.bashrc
source ~/.bashrc
```

---

## 3. Java Kurulumu

### Windows
```powershell
winget install Microsoft.OpenJDK.17
```

### Ubuntu / Debian
```bash
sudo apt update
sudo apt install openjdk-17-jre-headless
```

### macOS
```bash
brew install openjdk@17
```

---

## 4. Kurulumu Doğrula

```bash
# apktool çalışıyor mu?
java -jar $VENGAM_APKTOOL --version

# VENGAM CLI çalışıyor mu?
vengam --help

# Hızlı test
vengam -t örnek.apk --severity-filter CRITICAL
```

---

## 5. Docker ile Kurulum (en kolay yol)

```bash
# Repoyu klonla
git clone https://github.com/vengam/gamesec.git
cd gamesec

# Tüm servisleri başlat
docker-compose up -d

# API: http://localhost:8000
# Web: http://localhost:3000
# Sağlık kontrolü:
curl http://localhost:8000/api/health
```

---

## 6. Web Dashboard (Manuel)

```bash
# Backend
pip install -e ".[web]"
uvicorn phantom-api.main:app --reload --port 8000

# Frontend (ayrı terminal)
cd phantom-web
npm install
npm run dev
# http://localhost:3000
```

---

## 7. iOS Ek Gereksinimleri

iOS IPA analizi için:

| Araç | Platform | Kurulum |
|---|---|---|
| `plutil` | macOS (dahili) | — |
| `plistutil` | Linux | `sudo apt install libplist-utils` |
| `strings` | Linux/macOS | `sudo apt install binutils` |
| `otool` | macOS (Xcode) | `xcode-select --install` |
| `jtool2` | macOS/Linux | https://newosxbook.com/tools/jtool.html |

---

## 8. Frida (Dinamik Analiz)

```bash
# Python paketi
pip install frida frida-tools

# Android cihaz/emülatör için frida-server
# 1. https://github.com/frida/frida/releases adresinden indir
# 2. Cihaza yükle:
adb push frida-server /data/local/tmp/
adb shell chmod +x /data/local/tmp/frida-server

# 3. Başlat:
adb shell /data/local/tmp/frida-server &

# 4. VENGAM ile kullan:
vengam -t MyGame.apk --frida --pkg com.studio.mygame
```

---

## 9. Ortam Değişkenleri

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `VENGAM_APKTOOL` | `C:\apktool\apktool.jar` | apktool.jar yolu |
| `VENGAM_REPORTS_DIR` | `vengam_reports` | Rapor çıktı dizini |
| `VENGAM_DB` | `vengam_scans.db` | SQLite veritabanı yolu |

---

## 10. Sorun Giderme

**apktool bulunamıyor:**
```bash
# Java kurulu mu?
java -version

# VENGAM_APKTOOL doğru mu?
echo $VENGAM_APKTOOL
ls -la $VENGAM_APKTOOL
```

**WeasyPrint PDF hatası (Linux):**
```bash
sudo apt install libpango-1.0-0 libpangocairo-1.0-0 \
     libcairo2 libgdk-pixbuf2.0-0
pip install weasyprint
```

**Frida bağlanamıyor:**
```bash
# frida-server çalışıyor mu?
adb shell ps | grep frida

# Cihaz bağlı mı?
adb devices
```
