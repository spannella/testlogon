"""SSH Key Manager API router (INFRA-002).

Prefix: /ui/remote/ssh-keys
All endpoints use cookie-based session auth (require_ui_session).
"""

from __future__ import annotations

import logging
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException

from app.auth.deps import require_ui_session
from app.models import (
    AssociateKeyIn,
    GenerateSshKeyIn,
    PublicKeyOut,
    SshKeyListOut,
    SshKeyOut,
    UploadSshKeyIn,
)
from app.services.ssh_key_manager import (
    KeyLimitExceeded,
    associate_key_with_host,
    delete_key,
    disassociate_key_from_host,
    generate_key,
    get_key_metadata,
    list_keys,
    upload_key,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/remote/ssh-keys", tags=["ssh-key-manager"])


def _key_out(data: dict) -> SshKeyOut:
    return SshKeyOut(**data)


# ─── Upload existing private key ──────────────────────────────────

@router.post("", status_code=201, response_model=SshKeyOut)
async def upload_ssh_key(
    body: UploadSshKeyIn,
    session: Dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        result = upload_key(
            user_sub,
            label=body.label,
            private_key_pem=body.private_key_pem,
            passphrase=body.passphrase,
        )
    except KeyLimitExceeded as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _key_out(result)


# ─── Generate new key pair ────────────────────────────────────────

@router.post("/generate", status_code=201, response_model=SshKeyOut)
async def generate_ssh_key(
    body: GenerateSshKeyIn,
    session: Dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        result = generate_key(
            user_sub,
            label=body.label,
            key_type=body.key_type,
            key_bits=body.key_bits,
        )
    except KeyLimitExceeded as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _key_out(result)


# ─── List all keys ────────────────────────────────────────────────

@router.get("", response_model=SshKeyListOut)
async def list_ssh_keys(session: Dict = Depends(require_ui_session)):
    user_sub = session["user_sub"]
    keys = list_keys(user_sub)
    return SshKeyListOut(keys=[_key_out(k) for k in keys], count=len(keys))


# ─── Get single key ──────────────────────────────────────────────

@router.get("/{key_id}", response_model=SshKeyOut)
async def get_ssh_key(key_id: str, session: Dict = Depends(require_ui_session)):
    user_sub = session["user_sub"]
    meta = get_key_metadata(user_sub, key_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Key not found")
    return _key_out(meta)


# ─── Delete key ───────────────────────────────────────────────────

@router.delete("/{key_id}")
async def delete_ssh_key(key_id: str, session: Dict = Depends(require_ui_session)):
    user_sub = session["user_sub"]
    deleted = delete_key(user_sub, key_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Key not found")
    return {"ok": True}


# ─── Export public key ────────────────────────────────────────────

@router.get("/{key_id}/public", response_model=PublicKeyOut)
async def get_public_key(key_id: str, session: Dict = Depends(require_ui_session)):
    user_sub = session["user_sub"]
    meta = get_key_metadata(user_sub, key_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Key not found")
    return PublicKeyOut(
        key_id=meta["key_id"],
        public_key_openssh=meta["public_key_openssh"],
        public_key_fingerprint=meta["public_key_fingerprint"],
    )


# ─── Associate key with host ─────────────────────────────────────

@router.post("/{key_id}/associate")
async def associate_key(
    key_id: str,
    body: AssociateKeyIn,
    session: Dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    ok = associate_key_with_host(user_sub, key_id, body.host_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Key not found")
    return {"ok": True}


# ─── Disassociate key from host ──────────────────────────────────

@router.delete("/{key_id}/associate/{host_id}")
async def disassociate_key(
    key_id: str,
    host_id: str,
    session: Dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    ok = disassociate_key_from_host(user_sub, key_id, host_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Key not found")
    return {"ok": True}
