"""LLM Provider Key Management service (AGENT-001).

Secure storage, testing, rotation, and assignment of third-party
LLM API keys for use by autonomous agent workers.
"""

from __future__ import annotations

import logging
import time
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
    "deepseek": {
        "display_name": "DeepSeek",
        "base_url": "https://api.deepseek.com/v1",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "test_endpoint": "/models",
        "test_method": "GET",
        "models": ["deepseek-chat", "deepseek-coder", "deepseek-reasoner"],
        "supports_usage_api": False,
    },
    "gemini": {
        "display_name": "Google Gemini",
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "auth_header": "x-goog-api-key",
        "auth_prefix": "",
        "test_endpoint": "/models",
        "test_method": "GET",
        "models": ["gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.0-flash"],
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


def test_key(user_id: str, key_id: str) -> Dict[str, Any]:
    """Test an LLM key by probing the provider.

    In dev mode or when testing is disabled, returns a mock success response
    using the provider's default model list.
    """
    item_resp = T.llm_provider_keys.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"KEY#{key_id}"}
    )
    item = item_resp.get("Item")
    if not item:
        return {"ok": False, "models": [], "error": "Key not found", "latency_ms": 0}

    provider = item.get("provider", "")
    registry = PROVIDER_REGISTRY.get(provider, PROVIDER_REGISTRY.get("custom", {}))

    # In dev mode, return mock success with provider default models
    if S.dev_mode or not S.agent_llm_key_testing_enabled:
        models = list(registry.get("models", []))
        ts = now_ts()
        T.llm_provider_keys.update_item(
            Key={"pk": f"USER#{user_id}", "sk": f"KEY#{key_id}"},
            UpdateExpression="SET last_tested_at = :ts, available_models = :m, updated_at = :ts",
            ExpressionAttributeValues={":ts": ts, ":m": models},
        )
        logger.info("llm_key_tested user_id=%s key_id=%s provider=%s ok=true latency_ms=1", user_id, key_id, provider)
        return {"ok": True, "models": models, "error": "", "latency_ms": 1}

    # Production: make a real probe call
    try:
        import httpx  # noqa: local import to avoid hard dependency in dev

        api_key_raw = kms_decrypt(item["encrypted_api_key"]).decode("utf-8")
        base_url = item.get("base_url") or registry.get("base_url", "")
        endpoint = registry.get("test_endpoint", "/models")
        url = f"{base_url.rstrip('/')}{endpoint}"
        headers: Dict[str, str] = {}
        auth_header = registry.get("auth_header", "Authorization")
        auth_prefix = registry.get("auth_prefix", "Bearer ")
        headers[auth_header] = f"{auth_prefix}{api_key_raw}"
        for k, v in registry.get("extra_headers", {}).items():
            headers[k] = v

        start = time.monotonic()
        with httpx.Client(timeout=10) as client:
            resp = client.get(url, headers=headers)
        latency_ms = int((time.monotonic() - start) * 1000)

        if resp.status_code == 200:
            data = resp.json()
            models = [m.get("id", "") for m in data.get("data", [])] if isinstance(data, dict) else []
            ts = now_ts()
            T.llm_provider_keys.update_item(
                Key={"pk": f"USER#{user_id}", "sk": f"KEY#{key_id}"},
                UpdateExpression="SET last_tested_at = :ts, available_models = :m, #st = :active, updated_at = :ts",
                ExpressionAttributeNames={"#st": "status"},
                ExpressionAttributeValues={":ts": ts, ":m": models, ":active": "active"},
            )
            logger.info("llm_key_tested user_id=%s key_id=%s provider=%s ok=true latency_ms=%d", user_id, key_id, provider, latency_ms)
            return {"ok": True, "models": models, "error": "", "latency_ms": latency_ms}
        else:
            error_msg = f"HTTP {resp.status_code}: {resp.text[:200]}"
            ts = now_ts()
            T.llm_provider_keys.update_item(
                Key={"pk": f"USER#{user_id}", "sk": f"KEY#{key_id}"},
                UpdateExpression="SET #st = :invalid, updated_at = :ts",
                ExpressionAttributeNames={"#st": "status"},
                ExpressionAttributeValues={":invalid": "invalid", ":ts": ts},
            )
            logger.info("llm_key_tested user_id=%s key_id=%s provider=%s ok=false error=%s", user_id, key_id, provider, error_msg)
            return {"ok": False, "models": [], "error": error_msg, "latency_ms": latency_ms}
    except Exception as exc:
        logger.warning("llm_key_test_error user_id=%s key_id=%s error=%s", user_id, key_id, str(exc))
        return {"ok": False, "models": [], "error": str(exc), "latency_ms": 0}


def rotate_key(user_id: str, key_id: str, new_api_key: str) -> Optional[Dict[str, Any]]:
    """Rotate an API key in-place. Encrypts new key, keeps same key_id."""
    encrypted = kms_encrypt(new_api_key)
    key_suffix = new_api_key[-4:] if len(new_api_key) >= 4 else "****"
    ts = now_ts()

    T.llm_provider_keys.update_item(
        Key={"pk": f"USER#{user_id}", "sk": f"KEY#{key_id}"},
        UpdateExpression="SET encrypted_api_key = :ek, key_suffix = :ks, updated_at = :ts, #st = :active",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":ek": encrypted,
            ":ks": key_suffix,
            ":ts": ts,
            ":active": "active",
        },
    )
    logger.info("llm_key_rotated user_id=%s key_id=%s", user_id, key_id)
    return get_key(user_id, key_id)


def delete_key(user_id: str, key_id: str) -> None:
    """Delete an LLM provider key permanently."""
    T.llm_provider_keys.delete_item(
        Key={"pk": f"USER#{user_id}", "sk": f"KEY#{key_id}"}
    )
    logger.info("llm_key_deleted user_id=%s key_id=%s", user_id, key_id)


def check_usage(user_id: str, key_id: str) -> Dict[str, Any]:
    """Return usage stats for a key."""
    item_resp = T.llm_provider_keys.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"KEY#{key_id}"}
    )
    item = item_resp.get("Item")
    if not item:
        return {
            "key_id": key_id,
            "provider": "",
            "local_usage_cents": 0,
            "local_total_requests": 0,
            "local_total_tokens": 0,
            "provider_balance_cents": None,
            "provider_usage_cents": None,
            "budget_remaining_cents": None,
        }
    budget = int(item.get("monthly_budget_cents", 0) or 0)
    usage = int(item.get("current_month_usage_cents", 0) or 0)
    remaining = (budget - usage) if budget > 0 else None
    return {
        "key_id": key_id,
        "provider": item.get("provider", ""),
        "local_usage_cents": usage,
        "local_total_requests": int(item.get("total_requests", 0) or 0),
        "local_total_tokens": int(item.get("total_tokens_used", 0) or 0),
        "provider_balance_cents": None,
        "provider_usage_cents": None,
        "budget_remaining_cents": remaining,
    }


def record_usage(
    user_id: str,
    key_id: str,
    *,
    tokens: int,
    cost_cents: int,
) -> None:
    """Record token usage and cost from an agent session.

    Called by AGENT-003 after each LLM API call. Enforces budget.
    """
    ts = now_ts()
    T.llm_provider_keys.update_item(
        Key={"pk": f"USER#{user_id}", "sk": f"KEY#{key_id}"},
        UpdateExpression=(
            "ADD total_requests :one, total_tokens_used :tok, "
            "current_month_usage_cents :cost "
            "SET last_used_at = :ts, updated_at = :ts"
        ),
        ExpressionAttributeValues={
            ":one": 1,
            ":tok": tokens,
            ":cost": cost_cents,
            ":ts": ts,
        },
    )
    # Check budget and update status if exceeded
    item_resp = T.llm_provider_keys.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"KEY#{key_id}"}
    )
    item = item_resp.get("Item")
    if item:
        budget = int(item.get("monthly_budget_cents", 0) or 0)
        current = int(item.get("current_month_usage_cents", 0) or 0)
        if budget > 0 and current >= budget and item.get("status") == "active":
            T.llm_provider_keys.update_item(
                Key={"pk": f"USER#{user_id}", "sk": f"KEY#{key_id}"},
                UpdateExpression="SET #st = :exceeded",
                ExpressionAttributeNames={"#st": "status"},
                ExpressionAttributeValues={":exceeded": "budget_exceeded"},
            )
            logger.warning(
                "llm_key_budget_exceeded user_id=%s key_id=%s budget_cents=%d usage_cents=%d",
                user_id,
                key_id,
                budget,
                current,
            )


def assign_key_to_worker(user_id: str, key_id: str, worker_id: str) -> Optional[Dict[str, Any]]:
    """Associate an LLM key with a worker agent."""
    item = get_key(user_id, key_id)
    if not item:
        return None
    workers = list(item.get("assigned_worker_ids", []))
    if worker_id not in workers:
        workers.append(worker_id)
    ts = now_ts()
    T.llm_provider_keys.update_item(
        Key={"pk": f"USER#{user_id}", "sk": f"KEY#{key_id}"},
        UpdateExpression="SET assigned_worker_ids = :w, updated_at = :ts",
        ExpressionAttributeValues={":w": workers, ":ts": ts},
    )
    return get_key(user_id, key_id)


def unassign_key_from_worker(user_id: str, key_id: str, worker_id: str) -> Optional[Dict[str, Any]]:
    """Remove worker association from an LLM key."""
    item = get_key(user_id, key_id)
    if not item:
        return None
    workers = [w for w in item.get("assigned_worker_ids", []) if w != worker_id]
    ts = now_ts()
    T.llm_provider_keys.update_item(
        Key={"pk": f"USER#{user_id}", "sk": f"KEY#{key_id}"},
        UpdateExpression="SET assigned_worker_ids = :w, updated_at = :ts",
        ExpressionAttributeValues={":w": workers, ":ts": ts},
    )
    return get_key(user_id, key_id)


def list_all_keys_admin() -> List[Dict[str, Any]]:
    """Admin: list all keys across all users (for audit). Never exposes encrypted keys."""
    resp = T.llm_provider_keys.scan()
    items = resp.get("Items", [])
    # Paginate through all results
    while resp.get("LastEvaluatedKey"):
        resp = T.llm_provider_keys.scan(ExclusiveStartKey=resp["LastEvaluatedKey"])
        items.extend(resp.get("Items", []))
    return [_safe_out(item) for item in items if item.get("sk", "").startswith("KEY#")]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Strip encrypted_api_key and DDB key fields from output."""
    out = {k: v for k, v in item.items() if k not in ("encrypted_api_key", "pk", "sk")}
    # Coerce DynamoDB Decimal to int for numeric fields
    for field in (
        "rate_limit_rpm",
        "monthly_budget_cents",
        "current_month_usage_cents",
        "total_requests",
        "total_tokens_used",
        "last_tested_at",
        "last_used_at",
        "created_at",
        "updated_at",
        "usage_reset_at",
    ):
        if field in out:
            try:
                out[field] = int(out[field])
            except (TypeError, ValueError):
                pass
    return out
