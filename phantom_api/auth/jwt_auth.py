"""
VENGAM — JWT Authentication
Web dashboard için token tabanlı kimlik doğrulama.

Özellikler:
  - JWT token üretimi ve doğrulaması
  - Refresh token desteği
  - Bcrypt şifre hash'leme
  - Token blacklist (logout desteği)
  - Brute-force koruması
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# ── Sabitler ─────────────────────────────────────────────────────
SECRET_KEY       = os.environ.get("VENGAM_SECRET_KEY", "")
ALGORITHM        = "HS256"
ACCESS_EXPIRE_M  = int(os.environ.get("VENGAM_ACCESS_EXPIRE_M",  "60"))    # 60 dakika
REFRESH_EXPIRE_D = int(os.environ.get("VENGAM_REFRESH_EXPIRE_D", "7"))     # 7 gün
MAX_FAILED_LOGINS= 5    # Bu kadar başarısız denemeden sonra kilitle
LOCKOUT_SEC      = 300  # 5 dakika kilitle

if not SECRET_KEY:
    import secrets
    SECRET_KEY = secrets.token_hex(32)


# ── Veri modelleri ────────────────────────────────────────────────

@dataclass
class TokenPair:
    access_token:  str
    refresh_token: str
    token_type:    str = "bearer"
    expires_in:    int = ACCESS_EXPIRE_M * 60


@dataclass
class TokenData:
    username: str
    role:     str = "analyst"
    exp:      int = 0


# ── Basit JWT implementasyonu (python-jose gerektirmez) ───────────

def _b64url_encode(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64url_decode(s: str) -> bytes:
    import base64
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)

def _make_jwt(payload: dict, secret: str) -> str:
    header  = {"alg": ALGORITHM, "typ": "JWT"}
    h_enc   = _b64url_encode(json.dumps(header,  separators=(',',':')).encode())
    p_enc   = _b64url_encode(json.dumps(payload, separators=(',',':')).encode())
    signing = f"{h_enc}.{p_enc}".encode()
    sig     = hmac.new(secret.encode(), signing, hashlib.sha256).digest()
    sig_enc = _b64url_encode(sig)
    return f"{h_enc}.{p_enc}.{sig_enc}"

def _verify_jwt(token: str, secret: str) -> dict | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        h_enc, p_enc, sig_enc = parts
        signing  = f"{h_enc}.{p_enc}".encode()
        expected = hmac.new(secret.encode(), signing, hashlib.sha256).digest()
        actual   = _b64url_decode(sig_enc)
        if not hmac.compare_digest(expected, actual):
            return None
        payload = json.loads(_b64url_decode(p_enc))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


# ── Şifre yönetimi ────────────────────────────────────────────────

def hash_password(password: str) -> str:
    try:
        import bcrypt
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    except ImportError:
        # bcrypt yoksa SHA-256 fallback (production'da bcrypt kullan!)
        import secrets
        salt = secrets.token_hex(16)
        h    = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
        return f"sha256${salt}${h}"

def verify_password(plain: str, hashed: str) -> bool:
    try:
        import bcrypt
        if hashed.startswith("sha256$"):
            _, salt, h = hashed.split("$")
            expected   = hashlib.sha256(f"{salt}{plain}".encode()).hexdigest()
            return hmac.compare_digest(expected, h)
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except ImportError:
        if hashed.startswith("sha256$"):
            _, salt, h = hashed.split("$")
            expected   = hashlib.sha256(f"{salt}{plain}".encode()).hexdigest()
            return hmac.compare_digest(expected, h)
        return False


# ── Token işlemleri ───────────────────────────────────────────────

_blacklist: set[str] = set()
_failed_attempts: dict[str, list[float]] = {}

def create_token_pair(username: str, role: str = "analyst") -> TokenPair:
    now     = time.time()
    access  = _make_jwt({
        "sub":  username,
        "role": role,
        "type": "access",
        "iat":  int(now),
        "exp":  int(now + ACCESS_EXPIRE_M * 60),
    }, SECRET_KEY)
    refresh = _make_jwt({
        "sub":  username,
        "role": role,
        "type": "refresh",
        "iat":  int(now),
        "exp":  int(now + REFRESH_EXPIRE_D * 86400),
    }, SECRET_KEY)
    return TokenPair(
        access_token=access,
        refresh_token=refresh,
        expires_in=ACCESS_EXPIRE_M * 60,
    )

def verify_access_token(token: str) -> TokenData | None:
    if token in _blacklist:
        return None
    payload = _verify_jwt(token, SECRET_KEY)
    if not payload or payload.get("type") != "access":
        return None
    return TokenData(
        username=payload["sub"],
        role=payload.get("role", "analyst"),
        exp=payload.get("exp", 0),
    )

def refresh_access_token(refresh_token: str) -> TokenPair | None:
    if refresh_token in _blacklist:
        return None
    payload = _verify_jwt(refresh_token, SECRET_KEY)
    if not payload or payload.get("type") != "refresh":
        return None
    return create_token_pair(payload["sub"], payload.get("role","analyst"))

def revoke_token(token: str) -> None:
    _blacklist.add(token)

def is_brute_forced(username: str) -> bool:
    now      = time.time()
    attempts = [t for t in _failed_attempts.get(username, [])
                if now - t < LOCKOUT_SEC]
    _failed_attempts[username] = attempts
    return len(attempts) >= MAX_FAILED_LOGINS

def record_failed_login(username: str) -> None:
    if username not in _failed_attempts:
        _failed_attempts[username] = []
    _failed_attempts[username].append(time.time())

def clear_failed_logins(username: str) -> None:
    _failed_attempts.pop(username, None)


# ── Kullanıcı yönetimi (basit dosya tabanlı) ─────────────────────

USERS_FILE = Path(os.environ.get("VENGAM_USERS_FILE",
                                  "data/vengam_users.json"))

def _load_users() -> dict:
    if not USERS_FILE.exists():
        return {}
    try:
        return json.loads(USERS_FILE.read_text())
    except Exception:
        return {}

def _save_users(users: dict) -> None:
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    USERS_FILE.write_text(json.dumps(users, indent=2))

def create_user(username: str, password: str, role: str = "analyst") -> bool:
    users = _load_users()
    if username in users:
        return False
    users[username] = {
        "password_hash": hash_password(password),
        "role":          role,
        "created_at":    datetime.now(timezone.utc).isoformat(),
    }
    _save_users(users)
    return True

def authenticate_user(username: str, password: str) -> TokenPair | None:
    if is_brute_forced(username):
        return None
    users = _load_users()
    user  = users.get(username)
    if not user:
        record_failed_login(username)
        return None
    if not verify_password(password, user["password_hash"]):
        record_failed_login(username)
        return None
    clear_failed_logins(username)
    return create_token_pair(username, user.get("role", "analyst"))

def ensure_default_user() -> None:
    """İlk çalıştırmada varsayılan admin kullanıcısı oluştur."""
    users = _load_users()
    if not users:
        import secrets
        default_pass = secrets.token_urlsafe(12)
        create_user("admin", default_pass, "admin")
        print(f"\n  [VENGAM] İlk kullanıcı oluşturuldu!")
        print(f"  [VENGAM] Kullanıcı adı: admin")
        print(f"  [VENGAM] Şifre       : {default_pass}")
        print(f"  [VENGAM] Bu şifreyi güvenli bir yere kaydedin!\n")
