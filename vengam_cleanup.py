#!/usr/bin/env python3
"""
VENGAM — Decompile Folder Cleaner
Use:
    python vengam_cleanup.py          → show what to delete
    python vengam_cleanup.py --delete → delete
    python vengam_cleanup.py --auto   → delete folders older than 24 hours
"""
from __future__ import annotations
import argparse
import os
import shutil
import time
from pathlib import Path

ROOT = Path(__file__).parent.resolve()

G  = "\033[92m"
R  = "\033[91m"
Y  = "\033[93m"
X  = "\033[0m"
B  = "\033[1m"


def find_decomp_dirs() -> list[Path]:
    """*_vengam_out Find the folders."""
    return sorted(ROOT.glob("*_vengam_out"))


def find_temp_dirs() -> list[Path]:
    """Find VENGAM temporary files in the system temp directory."""
    import tempfile
    tmp = Path(tempfile.gettempdir())
    return list(tmp.glob("*vengam*")) + list(tmp.glob("tmp*"))


def human_size(path: Path) -> str:
    total = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
    if total > 1024**3: return f"{total/1024**3:.1f} GB"
    if total > 1024**2: return f"{total/1024**2:.1f} MB"
    return f"{total/1024:.1f} KB"


def human_age(path: Path) -> str:
    age = time.time() - path.stat().st_mtime
    if age > 86400: return f"{age/86400:.1f} days ago"
    if age > 3600:  return f"{age/3600:.1f} hours ago"
    return f"{age/60:.0f} minutes ago"


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="vengam_cleanup",
        description="VENGAM decompile folders cleaner"
    )
    parser.add_argument("--delete", action="store_true", help="Delete all decompile folders")
    parser.add_argument("--auto",   action="store_true", help="Delete folders older than 24 hours")
    parser.add_argument("--reports",action="store_true", help="Delete old reports as well (older than 30 days)")
    args = parser.parse_args()

    dirs = find_decomp_dirs()

    print(f"\n{B}  VENGAM — Decompile Folder Cleaner{X}\n")
    print(f"  VENGAM root: {ROOT}\n")

    if not dirs:
        print(f"  {G}✓ No decompile folders to clean.{X}\n")
    else:
        print(f"  {Y}Found decompile folders:{X}")
        total_size = 0
        for d in dirs:
            size_str = human_size(d)
            age_str  = human_age(d)
            print(f"    {Y}→{X} {d.name:50} {size_str:10} ({age_str})")
            total_size += sum(f.stat().st_size for f in d.rglob("*") if f.is_file())

        mb = total_size / 1024 / 1024
        print(f"\n  {B}Total: {mb:.1f} MB{X}")

        if args.delete:
            print(f"\n  {R}Deleting...{X}")
            for d in dirs:
                shutil.rmtree(d, ignore_errors=True)
                print(f"  {G}✓ Deleted: {d.name}{X}")
            print(f"\n  {G}✓ {len(dirs)} folders cleaned, {mb:.1f} MB gained.{X}\n")

        elif args.auto:
            cutoff  = time.time() - 86400
            old     = [d for d in dirs if d.stat().st_mtime < cutoff]
            if old:
                print(f"\n  {Y}Older than 24 hours {len(old)} folders are being deleted...{X}")
                for d in old:
                    shutil.rmtree(d, ignore_errors=True)
                    print(f"  {G}✓ Deleted: {d.name}{X}")
            else:
                print(f"\n  {G}✓ No folders older than 24 hours.{X}")
            print()

        else:
            print(f"\n  To delete: {G}python vengam_cleanup.py --delete{X}")
            print(f"  Auto:      {G}python vengam_cleanup.py --auto{X}\n")

    # Report cleanup
    if args.reports:
        reports_dir = ROOT / "vengam_reports"
        if reports_dir.exists():
            cutoff  = time.time() - 30 * 86400  # 30 days
            deleted = 0
            for scan_dir in reports_dir.iterdir():
                if scan_dir.is_dir() and scan_dir.stat().st_mtime < cutoff:
                    shutil.rmtree(scan_dir, ignore_errors=True)
                    deleted += 1
            if deleted:
                print(f"  {G}✓ {deleted} old report folders deleted (older than 30 days).{X}\n")
            else:
                print(f"  {G}✓ No old reports to delete.{X}\n")


if __name__ == "__main__":
    main()
