#!/usr/bin/env python3
"""
VENGAM Auditor — Launcher
- It initially cleans up the old _workspace/ folders.
- The _workspace/ folder is inside VENGAM; each scan writes there.
- It is automatically deleted after scanning is complete, so storage doesn't get full.
"""
from __future__ import annotations
import argparse, os, subprocess, sys, time, threading, webbrowser
from pathlib import Path

G,R,Y,DIM,B,X = "\033[92m","\033[91m","\033[93m","\033[2m","\033[1m","\033[0m"

BANNER = f"""{G}{B}
 ██╗   ██╗███████╗███╗   ██╗ ██████╗  █████╗ ███╗   ███╗
 ██║   ██║██╔════╝████╗  ██║██╔════╝ ██╔══██╗████╗ ████║
 ██║   ██║█████╗  ██╔██╗ ██║██║  ███╗███████║██╔████╔██║
 ╚██╗ ██╔╝██╔══╝  ██║╚██╗██║██║   ██║██╔══██║██║╚██╔╝██║
  ╚████╔╝ ███████╗██║ ╚████║╚██████╔╝██║  ██║██║ ╚═╝ ██║
   ╚═══╝  ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝
{X}{DIM}  Auditor v7.0.0  ·  Mobile Security Analysis Engine{X}"""

ROOT = Path(__file__).parent.resolve()

REQUIRED = [
    "fastapi","uvicorn[standard]","sqlalchemy",
    "aiosqlite","python-multipart","rich","pyyaml",
]

def log(msg, level="info"):
    p = {"info":f"{G}[✓]{X}","warn":f"{Y}[!]{X}",
         "error":f"{R}[✗]{X}","step":f"{G}{B}[→]{X}"}.get(level,"[?]")
    print(f"  {p} {msg}")

def check_python():
    if sys.version_info < (3,11):
        log(f"Python 3.11+ gerekli. Mevcut: {sys.version}","error"); sys.exit(1)
    log(f"Python {sys.version.split()[0]} ✓")

def check_java():
    try:
        r = subprocess.run(["java","-version"],capture_output=True,text=True,timeout=5)
        log(f"Java: {(r.stderr or r.stdout).split()[2].strip('\"')}")
        return True
    except: log("Java not found — apktool will not work","warn"); return False

def check_apktool():
    apktool = os.environ.get("VENGAM_APKTOOL","")
    if not apktool:
        for c in [r"C:\apktool\apktool.jar",
                  str(Path.home()/"apktool"/"apktool.jar"),
                  "/usr/local/lib/apktool.jar"]:
            if Path(c).exists():
                os.environ["VENGAM_APKTOOL"] = c; apktool = c; break
    if apktool and Path(apktool).exists():
        log(f"apktool: {apktool}"); return True
    log("apktool not found","warn"); return False

def install_packages():
    log("Addictions are being controlled....","step")
    missing = []
    for pkg in REQUIRED:
        try: __import__(pkg.split("[")[0].replace("-","_"))
        except ImportError: missing.append(pkg)
    if missing:
        log(f"Eksik: {', '.join(missing)}")
        subprocess.run([sys.executable,"-m","pip","install","--quiet"]+missing,check=True)
        log("Packages have been uploaded. ✓")
    else:
        log("All dependencies are installed ✓")

def cleanup_workspace():
    """First, clean up the old workspace/ folders."""
    ws = ROOT / "_workspace"
    if not ws.exists():
        ws.mkdir(exist_ok=True)
        log("_workspace/ created ✓")
        return
    items = list(ws.iterdir())
    if not items:
        log("_workspace/ is clean ✓")
        return
    import shutil, time
    old    = [i for i in items if i.is_dir() and
              time.time()-i.stat().st_mtime > 3600]
    if old:
        for item in old:
            shutil.rmtree(item, ignore_errors=True)
        log(f"_workspace/ cleaned — {len(old)} old folder(s) deleted ✓")
    else:
        log(f"_workspace/ is ready ✓")

def ensure_dirs():
    for d in [ROOT/"vengam_reports", ROOT/"data", ROOT/"_workspace"]:
        d.mkdir(exist_ok=True)
    os.environ.setdefault("VENGAM_REPORTS_DIR", str(ROOT/"vengam_reports"))
    os.environ.setdefault("VENGAM_DB",          str(ROOT/"data"/"vengam_scans.db"))
    os.environ.setdefault("VENGAM_WORKSPACE",    str(ROOT/"_workspace"))

def setup_pythonpath():
    paths = [str(ROOT), str(ROOT/"phantom_api")]
    for p in paths:
        if p not in sys.path:
            sys.path.insert(0, p)
    existing = os.environ.get("PYTHONPATH","")
    os.environ["PYTHONPATH"] = os.pathsep.join(paths + ([existing] if existing else []))

def patch_imports():
    for base in [ROOT/"phantom_api", ROOT/"phantom_api"/"routers",
                 ROOT/"phantom_api"/"db", ROOT/"phantom_api"/"auth"]:
        if not base.exists(): continue
        for f in base.glob("*.py"):
            try:
                c = f.read_text(encoding="utf-8")
                if "from phantom_api." in c:
                    f.write_text(c.replace("from phantom_api.","from "), encoding="utf-8")
            except Exception: pass

def create_inits():
    for d in [ROOT/"phantom_api", ROOT/"phantom_api"/"routers",
              ROOT/"phantom_api"/"db", ROOT/"phantom_api"/"auth"]:
        if d.exists():
            init = d/"__init__.py"
            if not init.exists():
                init.write_text('"""VENGAM module"""\n')

def wait_for_server(host, port, timeout=30):
    import socket
    h = "127.0.0.1" if host == "0.0.0.0" else host
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((h, port), timeout=1): return True
        except: time.sleep(0.4)
    return False

def start_server(host, port):
    cmd = [sys.executable,"-m","uvicorn","main:app",
           "--host",host,"--port",str(port),"--log-level","warning"]
    env = os.environ.copy()
    proc = subprocess.Popen(cmd, cwd=str(ROOT/"phantom_api"),
                            env=env, stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE)
    def reader():
        for line in proc.stderr:
            txt = line.decode("utf-8",errors="ignore").strip()
            if txt and "INFO:" not in txt:
                print(f"  {DIM}[api] {txt}{X}")
    threading.Thread(target=reader, daemon=True).start()
    return proc

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host",       default="127.0.0.1")
    parser.add_argument("--port",       type=int, default=8000)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--public",     action="store_true")
    parser.add_argument("--clean",      action="store_true",
                        help="Tüm _workspace/ temizle ve çık")
    args = parser.parse_args()

    # Cleaning mode only
    if args.clean:
        import shutil
        ws = ROOT/"_workspace"
        if ws.exists():
            count = len(list(ws.iterdir()))
            shutil.rmtree(ws, ignore_errors=True)
            ws.mkdir()
            print(f"{G}✓ _workspace/ cleaned ({count} old folder(s) deleted){X}")
        else:
            print(f"{G}✓ _workspace/ is already clean{X}")
        return

    if args.public: args.host = "0.0.0.0"

    print(BANNER)
    print(f"{B}  Starting...{X}\n")

    log("System checks","step")
    check_python(); check_java(); check_apktool()

    print()
    log("Workspace is being prepared....","step")
    cleanup_workspace()

    print()
    log("Modules are being prepared...","step")
    setup_pythonpath(); create_inits(); patch_imports()
    log("Module paths are ready ✓")

    print()
    install_packages()

    print()
    log("Directories are being prepared...","step")
    ensure_dirs()
    log(f"Reports : {os.environ['VENGAM_REPORTS_DIR']}")
    log(f"Workspace : {os.environ['VENGAM_WORKSPACE']}")
    log(f"Database: {os.environ['VENGAM_DB']}")

    print()
    h = "localhost" if args.host in ("127.0.0.1","0.0.0.0") else args.host
    url = f"http://{h}:{args.port}"
    log(f"Backend starting ({args.host}:{args.port})...","step")
    proc = start_server(args.host, args.port)

    log("Server is waiting...")
    if not wait_for_server(args.host, args.port, 30):
        log("The server hasn't started.!","error"); proc.terminate(); sys.exit(1)
    log(f"Server is ready → {url}")

    if not args.no_browser:
        threading.Thread(
            target=lambda: (time.sleep(2), webbrowser.open(f"{url}/ui")),
            daemon=True
        ).start()

    print(f"\n  {'═'*54}")
    print(f"  {G}{B}  VENGAM Auditor it works!{X}")
    print(f"  {'─'*54}")
    print(f"  {G}  Web UI    {X}: {url}/ui")
    print(f"  {G}  API       {X}: {url}/api")
    print(f"  {G}  Docs      {X}: {url}/docs")
    print(f"  {G}  Workspace {X}: {os.environ['VENGAM_WORKSPACE']}")
    print(f"  {'─'*54}")
    print(f"  {DIM}  Stop with Ctrl+C | Clean the workspace with --clean{X}")
    print(f"  {'═'*54}\n")

    try:
        proc.wait()
    except KeyboardInterrupt:
        print(f"\n  {Y}It's being shut down....{X}")
        proc.terminate()
        try: proc.wait(timeout=5)
        except: proc.kill()
        # Clean the workspace upon exit
        import shutil
        ws = ROOT/"_workspace"
        if ws.exists():
            remaining = list(ws.iterdir())
            for item in remaining:
                if item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
        print(f"  {G}✓ VENGAM The process was stopped, and the workspace was cleaned.{X}\n")

if __name__ == "__main__":
    main()
