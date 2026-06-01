"""
VENGAM — Workspace Manager
Tüm decompile işlemleri VENGAM/_workspace/ altında yapılır.
- Tarama bitince otomatik silinir
- Launcher başlarken eski workspace'ler temizlenir
- Depolama hiçbir zaman şişmez
"""
from __future__ import annotations
import os
import shutil
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from vengam.utils.logger import log

# VENGAM kök klasörü → _workspace/ buraya
ROOT      = Path(__file__).parent.parent.parent.resolve()
WORKSPACE = Path(os.environ.get("VENGAM_WORKSPACE", str(ROOT / "_workspace")))
WORKSPACE.mkdir(exist_ok=True)

# .gitignore'a ekle
_gitignore = ROOT / ".gitignore"
if _gitignore.exists():
    content = _gitignore.read_text()
    if "_workspace/" not in content:
        _gitignore.write_text(content + "\n_workspace/\n")


def cleanup_old_workspaces(max_age_hours: float = 24.0) -> int:
    """
    _workspace/ içindeki eski klasörleri temizle.
    Launcher başlarken çağrılır.
    """
    if not WORKSPACE.exists():
        return 0
    cutoff  = time.time() - max_age_hours * 3600
    deleted = 0
    for item in WORKSPACE.iterdir():
        if not item.is_dir():
            continue
        try:
            if item.stat().st_mtime < cutoff:
                shutil.rmtree(item, ignore_errors=True)
                deleted += 1
                log.info(f"Eski workspace temizlendi: {item.name}")
        except Exception as e:
            log.warning(f"Workspace temizlik hatası: {e}")
    if deleted:
        log.info(f"Toplam {deleted} eski workspace temizlendi")
    return deleted


def cleanup_all_workspaces() -> tuple[int, float]:
    """Tüm workspace'i temizle. Manuel çağrı için."""
    if not WORKSPACE.exists():
        return 0, 0.0
    items   = list(WORKSPACE.iterdir())
    total_bytes = 0
    for item in items:
        if item.is_dir():
            try:
                total_bytes += sum(
                    f.stat().st_size for f in item.rglob("*") if f.is_file()
                )
                shutil.rmtree(item, ignore_errors=True)
            except Exception:
                pass
    return len(items), total_bytes / (1024 * 1024)


def workspace_size_mb() -> float:
    """Mevcut workspace boyutu (MB)."""
    if not WORKSPACE.exists():
        return 0.0
    try:
        return sum(
            f.stat().st_size for f in WORKSPACE.rglob("*") if f.is_file()
        ) / (1024 * 1024)
    except Exception:
        return 0.0


@contextmanager
def scan_workspace(prefix: str = "scan"):
    """
    Context manager — tarama için temp klasör oluştur, bitince sil.

    Kullanım:
        with scan_workspace("android") as ws:
            apk_path   = ws / "game.apk"
            decomp_dir = ws / "decompiled"
            ...
    # Blok bitince ws otomatik silinir
    """
    scan_id  = str(uuid.uuid4())[:8]
    ws_path  = WORKSPACE / f"{prefix}_{scan_id}"
    ws_path.mkdir(parents=True, exist_ok=True)
    log.info(f"Workspace oluşturuldu: {ws_path.name}")
    try:
        yield ws_path
    finally:
        if ws_path.exists():
            shutil.rmtree(ws_path, ignore_errors=True)
            log.info(f"Workspace temizlendi: {ws_path.name}")
