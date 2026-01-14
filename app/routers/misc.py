from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.crypto import mint_ws_token
from app.services.sessions import require_ui_session

router = APIRouter(tags=["misc"])

@router.get("/ui/ws_token")
async def ui_ws_token(ctx=Depends(require_ui_session)):
    return {"token": mint_ws_token(ctx["user_sub"], ttl_seconds=120)}

@router.get("/api/ping")
async def ping():
    return {"ok": True}
