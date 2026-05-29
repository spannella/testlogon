"""LLM Provider Key Management router (AGENT-001)."""

from __future__ import annotations

from typing import Dict

from fastapi import APIRouter, Depends, HTTPException

from app.models import (
    LlmKeyAssignIn,
    LlmKeyCreateIn,
    LlmKeyListOut,
    LlmKeyOut,
    LlmKeyRotateIn,
    LlmKeyTestOut,
    LlmKeyUsageOut,
    LlmProviderInfo,
    LlmProviderListOut,
)
from app.services import llm_provider_keys as svc
from app.services.sessions import require_ui_session
from app.auth.policy import require_admin_or_root

router = APIRouter(tags=["agent-llm-keys"])


# ---------------------------------------------------------------------------
# User endpoints (require_ui_session)
# ---------------------------------------------------------------------------


@router.get("/ui/agent/llm-providers", response_model=LlmProviderListOut)
async def list_providers(_: Dict = Depends(require_ui_session)):
    """List supported LLM providers with metadata."""
    providers = []
    for key, info in svc.PROVIDER_REGISTRY.items():
        providers.append(
            LlmProviderInfo(
                provider=key,
                display_name=info["display_name"],
                base_url=info["base_url"],
                models=info.get("models", []),
                supports_usage_api=info.get("supports_usage_api", False),
            )
        )
    return LlmProviderListOut(providers=providers)


@router.post("/ui/agent/llm-keys", response_model=LlmKeyOut, status_code=201)
async def add_key(body: LlmKeyCreateIn, ctx: Dict = Depends(require_ui_session)):
    """Add a new LLM provider key (encrypted at rest)."""
    try:
        result = svc.add_key(
            user_id=ctx["user_sub"],
            provider=body.provider,
            label=body.label,
            api_key=body.api_key,
            base_url=body.base_url,
            model_preference=body.model_preference,
            rate_limit_rpm=body.rate_limit_rpm,
            monthly_budget_cents=body.monthly_budget_cents,
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/ui/agent/llm-keys", response_model=LlmKeyListOut)
async def list_keys(ctx: Dict = Depends(require_ui_session)):
    """List all LLM keys for the current user."""
    keys = svc.list_keys(ctx["user_sub"])
    return LlmKeyListOut(keys=keys, count=len(keys))


@router.get("/ui/agent/llm-keys/{key_id}", response_model=LlmKeyOut)
async def get_key(key_id: str, ctx: Dict = Depends(require_ui_session)):
    """Get a single LLM key by ID."""
    result = svc.get_key(ctx["user_sub"], key_id)
    if not result:
        raise HTTPException(status_code=404, detail="LLM key not found")
    return result


@router.post("/ui/agent/llm-keys/{key_id}/test", response_model=LlmKeyTestOut)
async def test_key(key_id: str, ctx: Dict = Depends(require_ui_session)):
    """Test an LLM key by probing the provider API."""
    result = svc.test_key(ctx["user_sub"], key_id)
    return result


@router.post("/ui/agent/llm-keys/{key_id}/rotate", response_model=LlmKeyOut)
async def rotate_key(key_id: str, body: LlmKeyRotateIn, ctx: Dict = Depends(require_ui_session)):
    """Rotate an API key in-place (re-encrypt, same key_id)."""
    result = svc.rotate_key(ctx["user_sub"], key_id, body.new_api_key)
    if not result:
        raise HTTPException(status_code=404, detail="LLM key not found")
    return result


@router.delete("/ui/agent/llm-keys/{key_id}")
async def delete_key(key_id: str, ctx: Dict = Depends(require_ui_session)):
    """Delete an LLM provider key permanently."""
    existing = svc.get_key(ctx["user_sub"], key_id)
    if not existing:
        raise HTTPException(status_code=404, detail="LLM key not found")
    svc.delete_key(ctx["user_sub"], key_id)
    return {"ok": True}


@router.get("/ui/agent/llm-keys/{key_id}/usage", response_model=LlmKeyUsageOut)
async def get_usage(key_id: str, ctx: Dict = Depends(require_ui_session)):
    """Check usage/balance for an LLM key."""
    result = svc.check_usage(ctx["user_sub"], key_id)
    return result


@router.post("/ui/agent/llm-keys/{key_id}/assign", response_model=LlmKeyOut)
async def assign_key(key_id: str, body: LlmKeyAssignIn, ctx: Dict = Depends(require_ui_session)):
    """Assign an LLM key to a worker agent."""
    result = svc.assign_key_to_worker(ctx["user_sub"], key_id, body.worker_id)
    if not result:
        raise HTTPException(status_code=404, detail="LLM key not found")
    return result


@router.delete("/ui/agent/llm-keys/{key_id}/assign/{worker_id}", response_model=LlmKeyOut)
async def unassign_key(key_id: str, worker_id: str, ctx: Dict = Depends(require_ui_session)):
    """Unassign an LLM key from a worker agent."""
    result = svc.unassign_key_from_worker(ctx["user_sub"], key_id, worker_id)
    if not result:
        raise HTTPException(status_code=404, detail="LLM key not found")
    return result


# ---------------------------------------------------------------------------
# Admin endpoint
# ---------------------------------------------------------------------------


@router.get("/ui/admin/agent/llm-keys", response_model=LlmKeyListOut)
async def admin_list_keys(_=Depends(require_admin_or_root)):
    """Admin: list all LLM keys across users for audit."""
    keys = svc.list_all_keys_admin()
    return LlmKeyListOut(keys=keys, count=len(keys))
