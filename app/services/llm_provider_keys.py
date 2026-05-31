"""LLM Provider Key Management service (AGENT-001).

Secure storage, testing, rotation, and assignment of third-party
LLM API keys for use by autonomous agent workers.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4

from app.core.crypto import kms_encrypt, kms_decrypt
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Provider registry
# ---------------------------------------------------------------------------

PROVIDER_REGISTRY: Dict[str, Dict[str, Any]] = {
    "openai": {
        "display_name": "OpenAI",
        "base_url": "https://api.openai.com/v1",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "test_endpoint": "/models",
        "test_method": "GET",
        "models": ["gpt-4o", "gpt-4o-mini", "o3", "o4-mini", "codex-mini-latest"],
        "supports_usage_api": True,
    },
    "anthropic": {
        "display_name": "Anthropic (Claude)",
        "base_url": "https://api.anthropic.com/v1",
        "auth_header": "x-api-key",
        "auth_prefix": "",
        "test_endpoint": "/models",
        "test_method": "GET",
        "extra_headers": {"anthropic-version": "2023-06-01"},
        "models": [
            "claude-sonnet-4-20250514",
            "claude-opus-4-20250514",
            "claude-haiku-3-5-20241022",
        ],
        "supports_usage_api": False,
    },
    "custom": {
        "display_name": "Custom (OpenAI-compatible)",
        "base_url": "",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "test_endpoint": "/models",
        "test_method": "GET",
        "models": [],
        "supports_usage_api": False,
    },
}


def _safe_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Strip encrypted_api_key from an item for external consumption."""
    out = dict(item)
    out.pop("encrypted_api_key", None)
    return out


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


def add_key(
    *,
    user_id: str,
    provider: str,
    label: str,
    api_key: str,
    base_url: str = "",
    model_preference: str = "",
    rate_limit_rpm: int = 60,
    monthly_budget_cents: int = 0,
) -> Dict[str, Any]:
    """Add a new LLM provider key, encrypting it at rest via KMS."""
    if provider not in PROVIDER_REGISTRY:
        raise ValueError(f"Unknown provider: {provider}")
    if provider == "custom" and not base_url:
        raise ValueError("base_url is required for custom provider")

    key_id = uuid4().hex
    encrypted = kms_encrypt(api_key)
    key_suffix = api_key[-4:] if len(api_key) >= 4 else "****"
    ts = now_ts()

    item: Dict[str, Any] = {
        "pk": f"USER#{user_id}",
        "sk": f"KEY#{key_id}",
        "key_id": key_id,
        "user_id": user_id,
        "provider": provider,
        "label": label,
        "encrypted_api_key": encrypted,
        "key_suffix": key_suffix,
        "base_url": base_url or PROVIDER_REGISTRY[provider]["base_url"],
        "model_preference": model_preference,
        "available_models": [],
        "rate_limit_rpm": rate_limit_rpm,
        "monthly_budget_cents": monthly_budget_cents,
        "current_month_usage_cents": 0,
        "usage_reset_at": 0,
        "total_requests": 0,
        "total_tokens_used": 0,
        "status": "active",
        "last_tested_at": 0,
        "last_used_at": 0,
        "created_at": ts,
        "updated_at": ts,
        "assigned_worker_ids": [],
    }
    T.llm_provider_keys.put_item(Item=item)
    logger.info("llm_key_added user_id=%s key_id=%s provider=%s label=%s", user_id, key_id, provider, label)
    return _safe_out(item)


def list_keys(user_id: str) -> List[Dict[str, Any]]:
    """List all LLM keys for a user. Never returns the encrypted key."""
    resp = T.llm_provider_keys.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues={":pk": f"USER#{user_id}", ":prefix": "KEY#"},
    )
    return [_safe_out(item) for item in resp.get("Items", [])]


def get_key(user_id: str, key_id: str) -> Optional[Dict[str, Any]]:
    """Get a single key by ID. Never returns the encrypted key."""
    resp = T.llm_provider_keys.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"KEY#{key_id}"}
    )
    item = resp.get("Item")
    return _safe_out(item) if item else None


def get_decrypted_api_key(user_id: str, key_id: str) -> str:
    """Decrypt and return the raw API key. Internal use only (agent provisioning)."""
    resp = T.llm_provider_keys.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"KEY#{key_id}"}
    )
    item = resp.get("Item")
    if not item:
        raise ValueError("Key not found")
    if item.get("status") != "active":
        raise ValueError(f"Key is not active (status: {item['status']})")
    logger.debug("llm_key_decrypted user_id=%s key_id=%s", user_id, key_id)
    return kms_decrypt(item["encrypted_api_key"]).decode("utf-8")
