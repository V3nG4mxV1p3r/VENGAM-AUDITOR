"""
VENGAM Auditor — iOS IPA Extractor
IPA = ZIP archive → Payload/AppName.app/
"""
from __future__ import annotations
import os
import shutil
import zipfile
from pathlib import Path
from typing import Optional
from vengam.utils.logger import log


def extract_ipa(ipa_path: str, output_dir: str, force: bool = False) -> Optional[str]:
    """
    Extract an IPA file to output_dir.
    Returns the .app bundle path on success, None on failure.
    """
    if not Path(ipa_path).exists():
        log.error(f"IPA not found: {ipa_path}")
        return None

    if Path(output_dir).exists():
        if force:
            shutil.rmtree(output_dir)
            log.info("Removed existing output dir (--force)")
        else:
            log.info(f"Reusing existing extraction: {output_dir}")
            return _find_app_bundle(output_dir)

    log.info(f"Extracting {Path(ipa_path).name} ...")

    if not zipfile.is_zipfile(ipa_path):
        log.error("File is not a valid IPA (ZIP) archive.")
        return None

    try:
        with zipfile.ZipFile(ipa_path, "r") as zf:
            zf.extractall(output_dir)
        log.info(f"Extraction complete → {output_dir}")
    except zipfile.BadZipFile as exc:
        log.error(f"IPA extraction failed: {exc}")
        return None
    except Exception as exc:
        log.error(f"Unexpected error during extraction: {exc}")
        return None

    return _find_app_bundle(output_dir)


def _find_app_bundle(output_dir: str) -> Optional[str]:
    """Locate the .app bundle inside Payload/"""
    payload = Path(output_dir) / "Payload"
    if not payload.exists():
        log.error("No Payload/ directory found in IPA.")
        return None

    bundles = list(payload.glob("*.app"))
    if not bundles:
        log.error("No .app bundle found inside Payload/.")
        return None

    if len(bundles) > 1:
        log.warning(f"Multiple .app bundles found — using: {bundles[0].name}")

    log.info(f"App bundle: {bundles[0]}")
    return str(bundles[0])


def get_ipa_structure(app_bundle: str) -> dict:
    """
    Walk the .app bundle and return a structural inventory dict:
    {
      "binary":         str  | None,   # main Mach-O binary path
      "info_plist":     str  | None,   # Info.plist path
      "entitlements":   str  | None,   # embedded.mobileprovision path
      "frameworks":     list[str],     # embedded .framework paths
      "extensions":     list[str],     # .appex paths
      "dylibs":         list[str],     # .dylib paths
      "resources":      list[str],     # all other files
      "total_files":    int,
    }
    """
    bundle = Path(app_bundle)
    bundle_name = bundle.stem            # e.g. "MyGame"

    structure: dict = {
        "binary":       None,
        "info_plist":   None,
        "entitlements": None,
        "frameworks":   [],
        "extensions":   [],
        "dylibs":       [],
        "resources":    [],
        "total_files":  0,
    }

    # Main binary (same name as bundle, directly inside .app)
    candidate_binary = bundle / bundle_name
    if candidate_binary.exists():
        structure["binary"] = str(candidate_binary)

    # Info.plist
    info = bundle / "Info.plist"
    if info.exists():
        structure["info_plist"] = str(info)

    # embedded.mobileprovision (entitlements)
    prov = bundle / "embedded.mobileprovision"
    if prov.exists():
        structure["entitlements"] = str(prov)

    # Walk everything
    for path in bundle.rglob("*"):
        structure["total_files"] += 1
        rel = str(path.relative_to(bundle))

        if path.suffix == ".framework" and path.is_dir():
            structure["frameworks"].append(rel)
        elif path.suffix == ".appex" and path.is_dir():
            structure["extensions"].append(rel)
        elif path.suffix == ".dylib":
            structure["dylibs"].append(str(path))
        elif path.is_file() and path.suffix not in {
            ".framework", ".appex", ".dylib", ".plist"
        }:
            structure["resources"].append(rel)

    log.info(
        f"IPA structure: {structure['total_files']} files | "
        f"{len(structure['frameworks'])} frameworks | "
        f"{len(structure['dylibs'])} dylibs | "
        f"{len(structure['extensions'])} extensions"
    )
    return structure
