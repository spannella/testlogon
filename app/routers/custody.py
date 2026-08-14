"""Crypto-custody proxy router (CUSTODY).

Session-authed ``/ui/custody/*`` endpoints that sit between the frontends and
the external MPC custody gateway. Clients never see the gateway, its HMAC
secret, officer keys, or a raw intent/digest — the withdrawal intent wire is
built SERVER-side from validated fields.

Officer/audit endpoints are role-gated (admin/root).
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.policy import require_admin_or_root
from app.core.settings import S
from app.services.sessions import require_ui_session
from app.services.custody_gateway import (
    ASSET_REGISTRY,
    get_custody_gateway,
    is_mock,
    registry_entry,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/custody", tags=["custody"])


# ---------------------------------------------------------------------------
# user -> wallet / vault mapping helpers.
#   - one tenant wallet (name from config, default "main"): "<tenant>-<name>"
#   - per-user deposit addresses via the gateway address endpoint (user=<uid>)
#   - per-user vault/sub-account id for balances: "<tenant>-u-<uid>"
# ---------------------------------------------------------------------------
def _tenant() -> str:
    return S.custody_tenant


def _wallet_id() -> str:
    return f"{S.custody_tenant}-{S.custody_wallet_name}"


def _user_vault_id(user_sub: str) -> str:
    return f"{S.custody_tenant}-u-{user_sub}"


def _gw():
    return get_custody_gateway()


def _ensure_user_state(gw, user_sub: str) -> None:
    """Make sure the tenant wallet + per-user vault exist (+ seed demo balances on mock)."""
    try:
        gw.create_wallet(S.custody_wallet_name)
    except Exception:
        pass
    if is_mock(gw):
        gw.seed_user_vault(_user_vault_id(user_sub), user_sub)


# ---------------------------------------------------------------------------
# destination validation (basic, per chain family).
# ---------------------------------------------------------------------------
_EVM_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_SOL_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
_XRP_RE = re.compile(r"^r[1-9A-HJ-NP-Za-km-z]{24,34}$")
_TRON_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
_BTC_RE = re.compile(r"^(bc1[0-9a-z]{20,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,39})$")


def _valid_destination(family: str, dest: str) -> bool:
    if family == "evm":
        return bool(_EVM_RE.match(dest))
    if family == "solana":
        return bool(_SOL_RE.match(dest))
    if family == "xrp":
        return bool(_XRP_RE.match(dest))
    if family == "tron":
        return bool(_TRON_RE.match(dest))
    if family == "btc":
        return bool(_BTC_RE.match(dest))
    return len(dest) >= 8


# ===========================================================================
# request models
# ===========================================================================
class WithdrawalIn(BaseModel):
    asset: str = Field(..., min_length=1)
    chain: str = Field(..., min_length=1)
    amount: float = Field(..., gt=0)
    destination: str = Field(..., min_length=4)
    memo: Optional[str] = None


class ApproveIn(BaseModel):
    approver: Optional[str] = None


# ===========================================================================
# user endpoints
# ===========================================================================
@router.get("/assets")
def list_assets(session=Depends(require_ui_session)) -> List[Dict[str, Any]]:
    """Supported-asset registry merged with the user's vault balances."""
    user_sub = session["user_sub"]
    gw = _gw()
    _ensure_user_state(gw, user_sub)
    balances: Dict[str, float] = {}
    if is_mock(gw):
        v = gw.get_vault(_user_vault_id(user_sub))
        balances = dict(v.get("balances", {})) if v else {}
    else:
        try:
            v = gw.get_vault(_user_vault_id(user_sub))
            balances = dict((v or {}).get("balances", {}))
        except Exception:
            balances = {}
    out: List[Dict[str, Any]] = []
    for r in ASSET_REGISTRY:
        out.append({
            "asset": r["asset"],
            "chain": r["chain"],
            "name": r["name"],
            "symbol": r["symbol"],
            "decimals": r["decimals"],
            "network": r["network"],
            "balance": float(balances.get(r["asset"], 0.0)),
            "address_available": True,
        })
    return out


@router.get("/deposit-address")
def deposit_address(
    asset: str = Query(...),
    chain: str = Query(...),
    session=Depends(require_ui_session),
) -> Dict[str, Any]:
    user_sub = session["user_sub"]
    entry = registry_entry(asset, chain)
    if not entry:
        raise HTTPException(400, "unsupported asset/chain")
    gw = _gw()
    _ensure_user_state(gw, user_sub)
    try:
        res = gw.get_address(_wallet_id(), user_sub, entry["chain_ref"])
    except Exception:
        raise HTTPException(502, "custody gateway unavailable")
    address = res.get("address") if isinstance(res, dict) else None
    if not address:
        raise HTTPException(502, "no address returned")
    out = {
        "asset": entry["asset"],
        "chain": entry["chain"],
        "network": entry["network"],
        "address": address,
    }
    # XRP-family assets often require a destination tag/memo; expose slot for clients.
    if entry["family"] in ("xrp",):
        out["memo"] = None
    return out


@router.get("/deposits")
def list_deposits(session=Depends(require_ui_session)) -> List[Dict[str, Any]]:
    """Recent credited deposits for the user (derived from vault balances / audit)."""
    user_sub = session["user_sub"]
    gw = _gw()
    _ensure_user_state(gw, user_sub)
    deposits: List[Dict[str, Any]] = []
    if is_mock(gw):
        v = gw.get_vault(_user_vault_id(user_sub))
        balances = dict(v.get("balances", {})) if v else {}
        # Present seeded balances as prior "credited" deposits for demo rendering.
        idx = 0
        for asset, amount in balances.items():
            if amount <= 0:
                continue
            entry = next((r for r in ASSET_REGISTRY if r["asset"] == asset), None)
            deposits.append({
                "id": f"dep-{user_sub[:8]}-{idx}",
                "asset": asset,
                "chain": entry["chain"] if entry else None,
                "amount": float(amount),
                "status": "credited",
                "confirmations": 32,
            })
            idx += 1
    return deposits


@router.post("/withdrawals")
def create_withdrawal(body: WithdrawalIn, session=Depends(require_ui_session)) -> Dict[str, Any]:
    user_sub = session["user_sub"]
    entry = registry_entry(body.asset, body.chain)
    if not entry:
        raise HTTPException(400, "unsupported asset/chain")
    if body.amount <= 0:
        raise HTTPException(400, "amount must be positive")
    if not _valid_destination(entry["family"], body.destination.strip()):
        raise HTTPException(400, "invalid destination address for chain")

    gw = _gw()
    _ensure_user_state(gw, user_sub)

    # Sufficient-balance check against the user's vault.
    vault_id = _user_vault_id(user_sub)
    if is_mock(gw):
        bal = gw.balance(vault_id, entry["asset"])
        if body.amount > bal:
            raise HTTPException(400, "insufficient balance")

    # Build the intent wire SERVER-side (never trust a client-supplied intent/digest).
    ts_ms = uuid_ts()
    nonce = f"wd-{uuid.uuid4().hex[:12]}"
    intent = "|".join([
        entry["asset"],
        entry["chain_ref"],
        entry["network"],
        body.destination.strip(),
        _fmt_amount(body.amount),
        str(ts_ms),
        nonce,
    ])
    idem_key = f"{user_sub}:{nonce}"

    try:
        status_code, payload = gw.create_withdrawal(_wallet_id(), intent, idem_key)
    except Exception:
        raise HTTPException(502, "custody gateway unavailable")

    # On mock, debit the vault when signed immediately (below threshold).
    if is_mock(gw) and status_code == 200 and payload.get("status") == "signed":
        gw.debit_vault(vault_id, entry["asset"], body.amount)

    out = {
        "id": payload.get("withdrawal_id"),
        "status": payload.get("status"),
        "asset": entry["asset"],
        "chain": entry["chain"],
        "amount": body.amount,
        "destination": body.destination.strip(),
    }
    for k in ("approvals_required", "approvals", "signature", "digest", "error", "category", "source", "detail"):
        if k in payload:
            out[k] = payload[k]
    return out


@router.get("/withdrawals")
def list_withdrawals(session=Depends(require_ui_session)) -> List[Dict[str, Any]]:
    user_sub = session["user_sub"]
    gw = _gw()
    if not is_mock(gw):
        # Real gateway: no per-user list endpoint in the contract; return empty
        # (frontends track ids they created). Deferred: server-side index.
        return []
    all_w = gw.list_withdrawals()
    mine = [w for w in all_w if _owns(gw, w.get("withdrawal_id"), user_sub)]
    return [_shape_withdrawal(w) for w in mine]


@router.get("/withdrawals/{withdrawal_id}")
def get_withdrawal(withdrawal_id: str, session=Depends(require_ui_session)) -> Dict[str, Any]:
    user_sub = session["user_sub"]
    gw = _gw()
    if is_mock(gw) and not _owns(gw, withdrawal_id, user_sub):
        raise HTTPException(404, "not found")
    try:
        w = gw.get_withdrawal(withdrawal_id)
    except Exception:
        raise HTTPException(502, "custody gateway unavailable")
    if not w:
        raise HTTPException(404, "not found")
    return _shape_withdrawal(w)


# ===========================================================================
# officer / admin endpoints (role-gated)
# ===========================================================================
@router.get("/approvals")
def approvals_queue(user: AuthenticatedUser = Depends(require_admin_or_root)) -> List[Dict[str, Any]]:
    gw = _gw()
    if not is_mock(gw):
        return []
    pending = [w for w in gw.list_withdrawals() if w.get("status") == "pending_approval"]
    return [_shape_withdrawal(w) for w in pending]


@router.post("/withdrawals/{withdrawal_id}/approve")
def approve_withdrawal(
    withdrawal_id: str,
    body: ApproveIn = ApproveIn(),
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    gw = _gw()
    approver = (body.approver or "").strip() or f"officer:{user.sub}"
    try:
        code, payload = gw.approve_withdrawal(withdrawal_id, approver)
    except Exception:
        raise HTTPException(502, "custody gateway unavailable")
    if code >= 400:
        raise HTTPException(code if code in (404, 409) else 400, payload.get("detail", "approve failed"))
    return payload


@router.post("/withdrawals/{withdrawal_id}/release")
def release_withdrawal(
    withdrawal_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    gw = _gw()
    try:
        code, payload = gw.release_withdrawal(withdrawal_id)
    except Exception:
        raise HTTPException(502, "custody gateway unavailable")
    if code == 425:
        raise HTTPException(425, "timelock not elapsed")
    if code >= 400:
        raise HTTPException(code if code in (404, 409) else 400, payload.get("detail", "release failed"))
    # Debit the owner's vault on mock release (settlement of a large withdrawal).
    if is_mock(gw) and payload.get("status") == "signed":
        w = gw.get_withdrawal(withdrawal_id)
        owner = _owner_of(gw, withdrawal_id)
        if owner and w.get("asset"):
            gw.debit_vault(_user_vault_id(owner), w["asset"], float(w.get("amount", 0)))
    return payload


@router.get("/audit")
def audit(user: AuthenticatedUser = Depends(require_admin_or_root)) -> Dict[str, Any]:
    try:
        return _gw().audit()
    except Exception:
        raise HTTPException(502, "custody gateway unavailable")


@router.get("/audit/verify")
def audit_verify(user: AuthenticatedUser = Depends(require_admin_or_root)) -> Dict[str, Any]:
    try:
        return _gw().audit_verify()
    except Exception:
        raise HTTPException(502, "custody gateway unavailable")


# ===========================================================================
# helpers
# ===========================================================================
def uuid_ts() -> int:
    import time
    return int(time.time() * 1000)


def _fmt_amount(amount: float) -> str:
    # Compact, deterministic amount string for the intent wire.
    if amount == int(amount):
        return str(int(amount))
    return repr(float(amount))


def _shape_withdrawal(w: Dict[str, Any]) -> Dict[str, Any]:
    approvals = w.get("approvals", []) or []
    return {
        "id": w.get("withdrawal_id"),
        "asset": w.get("asset"),
        "chain_ref": w.get("chain_ref"),
        "network": w.get("network"),
        "recipient": w.get("recipient"),
        "amount": w.get("amount"),
        "status": w.get("status"),
        "approvals": approvals,
        "approvals_count": len(approvals),
        "approvals_required": w.get("approvals_required"),
        "signature": w.get("signature"),
        "digest": w.get("digest"),
        "error": w.get("error"),
        "category": w.get("category"),
        "source": w.get("source"),
        "timelock_until_ms": w.get("timelock_until_ms"),
        "created_ms": w.get("created_ms"),
    }


def _owns(gw, withdrawal_id: Optional[str], user_sub: str) -> bool:
    return _owner_of(gw, withdrawal_id) == user_sub


def _owner_of(gw, withdrawal_id: Optional[str]) -> Optional[str]:
    """Derive the owning user from the mock idempotency map (key is '<uid>:<nonce>')."""
    if not withdrawal_id or not is_mock(gw):
        return None
    for idem_key, wid in gw._idem.items():  # noqa: SLF001 (mock-internal, same package)
        if wid == withdrawal_id:
            return idem_key.split(":", 1)[0]
    return None
