"""
VENGAM — Process Sandbox
Kötü niyetli APK'lardan korunmak için her tarama izole süreçte çalışır.

Özellikler:
  - Process isolation (subprocess)
  - Timeout kontrolü
  - Memory limit
  - Crash isolation — ana process etkilenmez
  - Temp dosya güvenli temizlik
  - ReDoS koruması (regex timeout)
"""
from __future__ import annotations
import json
import multiprocessing
import os
import queue
import resource
import shutil
import signal
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from vengam.utils.logger import log

# ── Sabitler ─────────────────────────────────────────────────────
DEFAULT_TIMEOUT_SEC  = 600      # 10 dakika maksimum tarama süresi
DEFAULT_MEMORY_MB    = 2048     # 2 GB RAM limiti
REGEX_TIMEOUT_SEC    = 5        # Tek bir regex için timeout
MAX_FILE_SIZE_MB     = 500      # Maksimum APK boyutu


# ── Sandbox sonuç modeli ──────────────────────────────────────────

@dataclass
class SandboxResult:
    success:      bool
    result_json:  str | None   = None   # ScanResult JSON
    error:        str | None   = None
    duration_sec: float        = 0.0
    killed:       bool         = False  # timeout/OOM ile öldürüldü mü


# ── Regex güvenli çalıştırıcı (ReDoS koruması) ───────────────────

class SafeRegex:
    """
    Regex'leri timeout ile çalıştırır.
    ReDoS (catastrophic backtracking) saldırılarına karşı koruma.
    """

    @staticmethod
    def search(pattern, text: str, timeout: float = REGEX_TIMEOUT_SEC):
        """
        Timeout ile regex search. None döner timeout'ta.
        """
        import re
        result_holder = [None]
        exc_holder    = [None]

        def _run():
            try:
                result_holder[0] = pattern.search(text)
            except Exception as e:
                exc_holder[0] = e

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        t.join(timeout=timeout)

        if t.is_alive():
            # Thread hala çalışıyor = timeout
            log.warning(f"Regex timeout ({timeout}s): {str(pattern.pattern)[:50]}")
            return None

        if exc_holder[0]:
            raise exc_holder[0]

        return result_holder[0]

    @staticmethod
    def findall(pattern, text: str, timeout: float = REGEX_TIMEOUT_SEC) -> list:
        result_holder = [[]]
        def _run():
            try:
                result_holder[0] = pattern.findall(text)
            except Exception:
                pass
        t = threading.Thread(target=_run, daemon=True)
        t.start()
        t.join(timeout=timeout)
        if t.is_alive():
            log.warning(f"Regex findall timeout: {str(pattern.pattern)[:50]}")
            return []
        return result_holder[0]


# ── Temp dosya yöneticisi ─────────────────────────────────────────

class SecureTempDir:
    """
    Context manager — temp dizini güvenli oluştur ve temizle.
    Çıkışta (hata dahil) her zaman siler.
    """

    def __init__(self, prefix: str = "vengam_scan_") -> None:
        self.prefix = prefix
        self.path:  str | None = None

    def __enter__(self) -> str:
        self.path = tempfile.mkdtemp(prefix=self.prefix)
        os.chmod(self.path, 0o700)  # Sadece owner erişebilir
        return self.path

    def __exit__(self, *_) -> None:
        if self.path and os.path.exists(self.path):
            try:
                shutil.rmtree(self.path, ignore_errors=True)
            except Exception as e:
                log.warning(f"Temp temizlik hatası: {e}")


# ── Worker fonksiyonu (izole süreçte çalışır) ─────────────────────

def _scan_worker(
    apk_path:       str,
    result_queue:   multiprocessing.Queue,
    severity_filter: set[str] | None,
    category_filter: set[str] | None,
    enable_native:  bool,
) -> None:
    """
    Bu fonksiyon ayrı bir subprocess'te çalışır.
    Ana process'e sadece JSON üzerinden sonuç döner.
    Crash olursa ana process etkilenmez.
    """
    try:
        # Memory limit (Unix only)
        if sys.platform != "win32":
            try:
                mem_bytes = DEFAULT_MEMORY_MB * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
            except Exception:
                pass

        # Import'ları burada yap (subprocess isolation için)
        from vengam.core.decompiler import check_apktool, decompile_apk
        from vengam.android.static import scan_directory

        with SecureTempDir("vengam_worker_") as tmp:
            decomp = os.path.join(tmp, "decompiled")

            if not check_apktool():
                result_queue.put({"error": "apktool bulunamadı"})
                return

            if not decompile_apk(apk_path, decomp, force=True):
                result_queue.put({"error": "Decompilation başarısız"})
                return

            result = scan_directory(
                decomp, apk_path,
                severity_filter=severity_filter,
                category_filter=category_filter,
            )

            # Native analiz opsiyonel
            if enable_native:
                try:
                    from vengam.native.so_analyzer import scan_so_files, scan_il2cpp
                    so_findings  = scan_so_files(decomp)
                    il2_findings = scan_il2cpp(decomp)
                    # Finding'leri ekle
                    from vengam.core.models import Finding, FindingLocation
                    for raw in so_findings + il2_findings:
                        locs = raw.pop("locations", [])
                        f = Finding(**{k:v for k,v in raw.items()
                                       if k in Finding.__dataclass_fields__})
                        f.locations = locs
                        result.findings.append(f)
                except Exception as e:
                    log.warning(f"Native analiz atlandı: {e}")

            # Sonucu JSON olarak queue'ya gönder
            import dataclasses
            payload = {
                "apk_name":    result.apk_name,
                "apk_sha256":  result.apk_sha256,
                "scan_timestamp": result.scan_timestamp,
                "total_score": result.total_score,
                "verdict":     result.verdict,
                "platform":    result.platform,
                "findings":    [f.to_dict() for f in result.findings],
                "engine_stats": result.engine_stats.to_dict(),
                "attack_surface": {
                    "auth":         list(result.attack_surface.auth),
                    "payment":      list(result.attack_surface.payment),
                    "user_data":    list(result.attack_surface.user_data),
                    "internal_api": list(result.attack_surface.internal_api),
                    "other":        list(result.attack_surface.other),
                },
            }
            result_queue.put({"ok": True, "data": payload})

    except MemoryError:
        result_queue.put({"error": "Bellek limiti aşıldı (OOM)"})
    except Exception as exc:
        result_queue.put({"error": f"Worker hatası: {type(exc).__name__}: {exc}"})


# ── Ana sandbox sınıfı ────────────────────────────────────────────

class ScanSandbox:
    """
    APK taramasını izole subprocess'te çalıştırır.

    Kullanım:
        sandbox = ScanSandbox(timeout=300)
        result  = sandbox.run(apk_path, severity_filter={"CRITICAL","HIGH"})
        if result.success:
            data = json.loads(result.result_json)
    """

    def __init__(
        self,
        timeout_sec: int  = DEFAULT_TIMEOUT_SEC,
        memory_mb:   int  = DEFAULT_MEMORY_MB,
        enable_native: bool = True,
    ) -> None:
        self.timeout_sec   = timeout_sec
        self.memory_mb     = memory_mb
        self.enable_native = enable_native

    def run(
        self,
        apk_path:        str,
        severity_filter: set[str] | None = None,
        category_filter: set[str] | None = None,
    ) -> SandboxResult:
        start = time.monotonic()
        apk_path = str(apk_path)

        # Dosya boyutu kontrolü
        try:
            size_mb = os.path.getsize(apk_path) / 1024 / 1024
            if size_mb > MAX_FILE_SIZE_MB:
                return SandboxResult(
                    success=False,
                    error=f"Dosya çok büyük: {size_mb:.0f}MB (max {MAX_FILE_SIZE_MB}MB)"
                )
        except OSError as e:
            return SandboxResult(success=False, error=f"Dosya okunamadı: {e}")

        log.info(f"Sandbox başlatılıyor: {Path(apk_path).name} "
                 f"(timeout={self.timeout_sec}s)")

        result_queue: multiprocessing.Queue = multiprocessing.Queue()

        proc = multiprocessing.Process(
            target=_scan_worker,
            args=(apk_path, result_queue, severity_filter,
                  category_filter, self.enable_native),
            daemon=True,
        )
        proc.start()

        # Timeout ile bekle
        proc.join(timeout=self.timeout_sec)
        duration = round(time.monotonic() - start, 2)

        if proc.is_alive():
            log.warning(f"Sandbox timeout ({self.timeout_sec}s) — process öldürülüyor")
            proc.kill()
            proc.join(timeout=5)
            return SandboxResult(
                success=False,
                error=f"Tarama timeout ({self.timeout_sec}s) aşıldı.",
                duration_sec=duration,
                killed=True,
            )

        # Exit code kontrolü
        if proc.exitcode != 0:
            log.warning(f"Worker anormal çıkış: exitcode={proc.exitcode}")

        # Queue'dan sonucu al
        try:
            payload = result_queue.get_nowait()
        except Exception:
            return SandboxResult(
                success=False,
                error="Worker sonuç döndürmedi (crash olmuş olabilir).",
                duration_sec=duration,
                killed=proc.exitcode != 0,
            )

        if "error" in payload:
            return SandboxResult(
                success=False,
                error=payload["error"],
                duration_sec=duration,
            )

        return SandboxResult(
            success=True,
            result_json=json.dumps(payload["data"], ensure_ascii=False),
            duration_sec=duration,
        )


# ── Concurrent worker pool ────────────────────────────────────────

class SandboxPool:
    """
    Birden fazla APK'yı aynı anda taramak için worker pool.
    Maksimum eşzamanlı tarama sayısını sınırlar.

    Kullanım:
        pool = SandboxPool(max_workers=3)
        future = pool.submit(apk_path)
        result = future.get(timeout=600)
    """

    def __init__(
        self,
        max_workers:   int = 2,
        timeout_sec:   int = DEFAULT_TIMEOUT_SEC,
    ) -> None:
        self.max_workers = max_workers
        self.timeout_sec = timeout_sec
        self._semaphore  = threading.Semaphore(max_workers)
        self._sandbox    = ScanSandbox(timeout_sec=timeout_sec)

    def submit(
        self,
        apk_path:        str,
        severity_filter: set[str] | None = None,
        category_filter: set[str] | None = None,
    ) -> "SandboxFuture":
        future = SandboxFuture()

        def _run():
            self._semaphore.acquire()
            try:
                result = self._sandbox.run(apk_path, severity_filter, category_filter)
                future._set_result(result)
            finally:
                self._semaphore.release()

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        return future

    @property
    def active_count(self) -> int:
        return self.max_workers - self._semaphore._value


class SandboxFuture:
    """Asenkron sandbox sonucu için future nesnesi."""

    def __init__(self) -> None:
        self._event  = threading.Event()
        self._result: SandboxResult | None = None

    def _set_result(self, result: SandboxResult) -> None:
        self._result = result
        self._event.set()

    def get(self, timeout: float | None = None) -> SandboxResult | None:
        if self._event.wait(timeout=timeout):
            return self._result
        return None

    def done(self) -> bool:
        return self._event.is_set()
