"""
VENGAM — Auth Router
POST /api/auth/login    → token al
POST /api/auth/refresh  → token yenile
POST /api/auth/logout   → token iptal et
GET  /api/auth/me       → mevcut kullanıcı bilgisi
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from auth.jwt_auth import (
    authenticate_user, refresh_access_token,
    revoke_token, verify_access_token,
    create_user, ensure_default_user,
    TokenData,
)

router  = APIRouter()
bearer  = HTTPBearer(auto_error=False)


# ── Request/Response modelleri ────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str

class RefreshRequest(BaseModel):
    refresh_token: str

class CreateUserRequest(BaseModel):
    username: str
    password: str
    role:     str = "analyst"


# ── Dependency: token doğrulama ───────────────────────────────────

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
) -> TokenData:
    if not credentials:
        raise HTTPException(401, "Authentication required")
    token_data = verify_access_token(credentials.credentials)
    if not token_data:
        raise HTTPException(401, "Invalid or expired token")
    return token_data


async def require_admin(
    current_user: TokenData = Depends(get_current_user),
) -> TokenData:
    if current_user.role != "admin":
        raise HTTPException(403, "Admin role required")
    return current_user


# ── Endpoints ─────────────────────────────────────────────────────

@router.post("/login")
async def login(req: LoginRequest):
    token_pair = authenticate_user(req.username, req.password)
    if not token_pair:
        raise HTTPException(
            401,
            "Geçersiz kullanıcı adı/şifre veya hesap kilitli."
        )
    return {
        "access_token":  token_pair.access_token,
        "refresh_token": token_pair.refresh_token,
        "token_type":    token_pair.token_type,
        "expires_in":    token_pair.expires_in,
    }


@router.post("/refresh")
async def refresh(req: RefreshRequest):
    token_pair = refresh_access_token(req.refresh_token)
    if not token_pair:
        raise HTTPException(401, "Geçersiz veya süresi dolmuş refresh token")
    return {
        "access_token": token_pair.access_token,
        "token_type":   token_pair.token_type,
        "expires_in":   token_pair.expires_in,
    }


@router.post("/logout")
async def logout(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
):
    if credentials:
        revoke_token(credentials.credentials)
    return {"message": "Çıkış yapıldı"}


@router.get("/me")
async def me(current_user: TokenData = Depends(get_current_user)):
    return {
        "username": current_user.username,
        "role":     current_user.role,
    }


@router.post("/users", dependencies=[Depends(require_admin)])
async def create_new_user(req: CreateUserRequest):
    success = create_user(req.username, req.password, req.role)
    if not success:
        raise HTTPException(400, "Kullanıcı zaten mevcut")
    return {"message": f"Kullanıcı oluşturuldu: {req.username}"}
