"""
VENGAM — Enterprise Router
GET  /api/enterprise/orgs            → organizasyon listesi (admin)
POST /api/enterprise/orgs            → organizasyon oluştur (admin)
GET  /api/enterprise/orgs/{id}       → org detayı
POST /api/enterprise/orgs/{id}/members → üye ekle
GET  /api/enterprise/audit           → audit log (admin)
GET  /api/enterprise/stats           → platform istatistikleri
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Security
from pydantic import BaseModel
from auth.jwt_auth import verify_access_token, TokenData

router = APIRouter()
bearer = HTTPBearer(auto_error=False)


async def get_admin_user(
    credentials: HTTPAuthorizationCredentials = Security(bearer),
) -> TokenData:
    if not credentials:
        raise HTTPException(401, "Authentication required")
    data = verify_access_token(credentials.credentials)
    if not data:
        raise HTTPException(401, "Invalid token")
    if data.role != "admin":
        raise HTTPException(403, "Admin required")
    return data


async def get_any_user(
    credentials: HTTPAuthorizationCredentials = Security(bearer),
) -> TokenData:
    if not credentials:
        raise HTTPException(401, "Authentication required")
    data = verify_access_token(credentials.credentials)
    if not data:
        raise HTTPException(401, "Invalid token")
    return data


# ── Request modelleri ─────────────────────────────────────────────

class CreateOrgRequest(BaseModel):
    name: str
    slug: str
    plan: str = "pro"

class AddMemberRequest(BaseModel):
    username: str


# ── Endpoints ─────────────────────────────────────────────────────

@router.get("/orgs")
async def list_orgs(_admin: TokenData = Depends(get_admin_user)):
    from vengam.enterprise.multi_tenant import list_organizations
    orgs = list_organizations()
    return JSONResponse([{
        "id":       o.id,   "name":     o.name,
        "slug":     o.slug, "plan":     o.plan,
        "members":  len(o.members),
        "created_at": o.created_at,
    } for o in orgs])


@router.post("/orgs")
async def create_org(
    req: CreateOrgRequest,
    _admin: TokenData = Depends(get_admin_user),
):
    from vengam.enterprise.multi_tenant import create_organization
    from vengam.enterprise.audit_log import write_audit
    try:
        org = create_organization(req.name, req.slug, req.plan)
        write_audit(_admin.username, "CONFIG_CHANGE",
                    resource=org.id, detail=f"Created org: {req.name}")
        return JSONResponse({"id": org.id, "name": org.name,
                             "api_key": org.api_key})
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/orgs/{org_id}")
async def get_org(
    org_id: str,
    user:   TokenData = Depends(get_any_user),
):
    from vengam.enterprise.multi_tenant import get_organization, is_member
    org = get_organization(org_id)
    if not org:
        raise HTTPException(404, "Organization not found")
    if user.role != "admin" and not is_member(org_id, user.username):
        raise HTTPException(403, "Access denied")
    return JSONResponse({
        "id": org.id, "name": org.name, "slug": org.slug,
        "plan": org.plan, "members": org.members,
        "max_scans_pm": org.max_scans_pm,
    })


@router.post("/orgs/{org_id}/members")
async def add_member(
    org_id: str,
    req: AddMemberRequest,
    _admin: TokenData = Depends(get_admin_user),
):
    from vengam.enterprise.multi_tenant import add_member
    from vengam.enterprise.audit_log import write_audit
    success = add_member(org_id, req.username)
    if not success:
        raise HTTPException(404, "Organization not found")
    write_audit(_admin.username, "CONFIG_CHANGE",
                resource=org_id, detail=f"Added member: {req.username}")
    return JSONResponse({"message": f"{req.username} added to org"})


@router.get("/audit")
async def get_audit_log(
    actor:  str | None = None,
    action: str | None = None,
    limit:  int = 100,
    _admin: TokenData = Depends(get_admin_user),
):
    from vengam.enterprise.audit_log import read_audit
    entries = read_audit(actor=actor, action=action, limit=limit)
    return JSONResponse(entries)


@router.get("/stats")
async def get_stats(
    _admin: TokenData = Depends(get_admin_user),
):
    """Platform geneli istatistikler."""
    import os
    from pathlib import Path
    from vengam.enterprise.multi_tenant import list_organizations

    reports_dir = Path(os.environ.get("VENGAM_REPORTS_DIR", "vengam_reports"))
    scan_count  = len(list(reports_dir.glob("*/")) ) if reports_dir.exists() else 0
    orgs        = list_organizations()

    return JSONResponse({
        "total_scans":    scan_count,
        "total_orgs":     len(orgs),
        "total_members":  sum(len(o.members) for o in orgs),
        "plans": {
            "free":       sum(1 for o in orgs if o.plan == "free"),
            "pro":        sum(1 for o in orgs if o.plan == "pro"),
            "enterprise": sum(1 for o in orgs if o.plan == "enterprise"),
        },
    })
