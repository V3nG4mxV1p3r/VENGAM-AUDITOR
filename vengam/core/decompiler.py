"""
VENGAM Auditor — APK Decompiler (apktool wrapper)
"""
from __future__ import annotations
import subprocess
from pathlib import Path
from typing import Optional
from vengam.config import APKTOOL_PATH
from vengam.utils.logger import log


def check_apktool() -> bool:
    """Return True if apktool is reachable via the configured path."""
    log.info("Checking apktool dependency...")
    try:
        r = subprocess.run(
            ["java", "-jar", APKTOOL_PATH, "--version"],
            capture_output=True, text=True, timeout=15,
        )
        log.info(f"apktool OK ({(r.stdout or r.stderr).strip()})")
        return True
    except FileNotFoundError:
        log.error("java not found — install JDK 11+.")
    except subprocess.TimeoutExpired:
        log.error("apktool check timed out.")
    except Exception as exc:
        log.error(f"apktool check failed: {exc}")
    return False


def decompile_apk(
    apk_path: str,
    output_dir: str,
    force: bool = False,
) -> Optional[str]:
    """
    Decompile an APK with apktool.
    Returns the output directory path on success, None on failure.
    """
    if not Path(apk_path).exists():
        log.error(f"APK not found: {apk_path}")
        return None

    log.info(f"Decompiling {Path(apk_path).name} ...")
    cmd = ["java", "-jar", APKTOOL_PATH, "d", apk_path, "-o", output_dir]
    if force:
        cmd.append("-f")

    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300)
        log.info(f"Decompilation complete → {output_dir}")
        return output_dir
    except subprocess.CalledProcessError as exc:
        log.error(f"apktool error (rc={exc.returncode})")
        log.debug(exc.stderr)
    except subprocess.TimeoutExpired:
        log.error("Decompilation timed out (5 min limit).")
    except Exception as exc:
        log.error(f"Decompilation failed: {exc}")
    return None
