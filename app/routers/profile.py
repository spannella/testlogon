from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, File, Request, UploadFile

from app.models import ProfilePatchReq, ProfilePutReq
from app.services.alerts import audit_event
from app.services.profile import apply_profile_update, get_audit_log, get_profile, store_profile_photo
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/profile", tags=["profile"])

try:  # pragma: no cover - optional dependency for file uploads
    import multipart  # type: ignore  # noqa: F401
    _MULTIPART_AVAILABLE = True
except Exception:  # pragma: no cover
    _MULTIPART_AVAILABLE = False

@router.get("")
async def ui_get_profile(ctx=Depends(require_ui_session)):
    return {"profile": get_profile(ctx["user_sub"])}

@router.get("/audit")
async def ui_get_profile_audit(ctx=Depends(require_ui_session)):
    return {"audit": get_audit_log(ctx["user_sub"])}

@router.patch("")
async def ui_patch_profile(req: Request, body: ProfilePatchReq, ctx=Depends(require_ui_session)):
    updates = body.model_dump(exclude_unset=True)
    profile = apply_profile_update(ctx["user_sub"], updates, replace=False)
    audit_event("profile_update", ctx["user_sub"], req, outcome="success", mode="patch")
    return {"profile": profile}

@router.put("")
async def ui_put_profile(req: Request, body: ProfilePutReq, ctx=Depends(require_ui_session)):
    updates = body.model_dump()
    profile = apply_profile_update(ctx["user_sub"], updates, replace=True)
    audit_event("profile_update", ctx["user_sub"], req, outcome="success", mode="replace")
    return {"profile": profile}

if _MULTIPART_AVAILABLE:
    @router.post("/photos/{kind}/upload")
    async def ui_upload_profile_photo(
        req: Request,
        kind: str,
        file: UploadFile = File(...),
        ctx=Depends(require_ui_session),
    ):
        content = await file.read()
        url = store_profile_photo(ctx["user_sub"], kind, file.filename or "upload.bin", content)
        updates = {"profile_photo_url": url} if kind == "profile" else {"cover_photo_url": url}
        profile = apply_profile_update(ctx["user_sub"], updates, replace=False)
        audit_event("profile_photo_upload", ctx["user_sub"], req, outcome="success", kind=kind)
        return {"profile": profile, "url": url}
else:
    @router.post("/photos/{kind}/upload")
    async def ui_upload_profile_photo_unavailable(ctx=Depends(require_ui_session)):
        raise HTTPException(501, "python-multipart is required for uploads")
