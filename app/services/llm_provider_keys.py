"""LLM Provider Key Management service (AGENT-001).

Secure storage, testing, rotation, and assignment of third-party
LLM API keys for use by autonomous agent workers.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
import time
from typing import Any, Dict, List, Optional
from uuid import uuid4

from app.core.crypto import kms_encrypt, kms_decrypt
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def _next_reset_at(from_ts: int) -> int:
    """Return the Unix timestamp of the first second of the next calendar month.

    Used to schedule the monthly budget reset (GAP-0077). A key whose
    ``usage_reset_at`` has passed is eligible for a monthly counter reset.
    """
    dt = datetime.datetime.fromtimestamp(from_ts, datetime.timezone.utc)
    if dt.month == 12:
        next_month = datetime.datetime(dt.year + 1, 1, 1, tzinfo=datetime.timezone.utc)
    else:
        next_month = datetime.datetime(dt.year, dt.month + 1, 1, tzinfo=datetime.timezone.utc)
    return int(next_month.timestamp())


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
    "elevenlabs": {
        "display_name": "ElevenLabs",
        "base_url": "https://api.elevenlabs.io/v1",
        "auth_header": "xi-api-key",
        "auth_prefix": "",
        "test_endpoint": "/voices",
        "test_method": "GET",
        # TTS model IDs.
        "models": ["eleven_multilingual_v2", "eleven_turbo_v2_5"],
        # STT model id used by transcribe_audio.
        "stt_model": "scribe_v1",
        # Default voice for synthesize_speech when no voice_preference set.
        "default_voice_id": "21m00Tcm4TlvDq8ikWAM",
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
    voice_preference: str = "",
    rate_limit_rpm: int = 60,
    monthly_budget_cents: int = 0,
) -> Dict[str, Any]:
    """Add a new LLM provider key, encrypting it at rest via KMS."""
    if provider not in PROVIDER_REGISTRY:
        raise ValueError(f"Unknown provider: {provider}")
    if provider == "custom" and not base_url:
        raise ValueError("base_url is required for custom provider")
    # MVA-001: default voice for TTS providers (ElevenLabs) when unset.
    if not voice_preference:
        voice_preference = PROVIDER_REGISTRY[provider].get("default_voice_id", "")

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
        "voice_preference": voice_preference,
        "available_models": [],
        "rate_limit_rpm": rate_limit_rpm,
        "monthly_budget_cents": monthly_budget_cents,
        "current_month_usage_cents": 0,
        # GAP-0077: schedule the first monthly reset so budget-exceeded keys
        # automatically renew. Unlimited keys (budget == 0) need no reset.
        "usage_reset_at": _next_reset_at(ts) if monthly_budget_cents > 0 else 0,
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
    # GAP-0076 defense-in-depth: refuse to hand out the decrypted key for any
    # non-active key. This blocks budget_exceeded keys at agent-provisioning
    # time, not just during usage recording, closing the race window where a
    # caller might have read the key before record_usage flipped the status.
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
        # SSRF protection (GAP-0009): re-validate the stored base_url before
        # issuing the outbound request, in case a malicious value was persisted
        # before this validation existed or by a path bypassing the model.
        from app.services.webhook_ssrf import validate_webhook_url

        if base_url:
            validate_webhook_url(base_url)
        endpoint = registry.get("test_endpoint", "/models")
        url = f"{base_url.rstrip('/')}{endpoint}"
        headers: Dict[str, str] = {}
        auth_header = registry.get("auth_header", "Authorization")
        auth_prefix = registry.get("auth_prefix", "Bearer ")
        headers[auth_header] = f"{auth_prefix}{api_key_raw}"
        for k, v in registry.get("extra_headers", {}).items():
            headers[k] = v

        start = time.monotonic()
        with httpx.Client(timeout=10, follow_redirects=False) as client:
            resp = client.get(url, headers=headers)
        latency_ms = int((time.monotonic() - start) * 1000)

        if resp.status_code == 200:
            data = resp.json()
            if provider == "elevenlabs":
                # MVA-001: ElevenLabs /voices returns {"voices": [{"voice_id", "name"}]}.
                voices = data.get("voices", []) if isinstance(data, dict) else []
                models = [v.get("voice_id", "") for v in voices if isinstance(v, dict)]
            else:
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
            # SSRF protection (GAP-0009): never echo the raw provider response
            # body back to the user — it may contain internal/SSRF-leaked data.
            # Log the full body server-side for diagnostics only.
            logger.debug(
                "llm_key_test_http_error user_id=%s key_id=%s status=%d body=%s",
                user_id, key_id, resp.status_code, resp.text[:500],
            )
            error_msg = f"HTTP {resp.status_code}: provider returned an error"
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
            # GAP-0076: the status flip must be atomic. Without a
            # ConditionExpression, concurrent record_usage callers can each
            # observe status == "active" after the budget is already crossed
            # and let further LLM requests through. Guarding the SET with
            # "#st = :active" makes exactly one concurrent caller win the
            # transition; all others get ConditionalCheckFailedException and
            # silently skip (the status is already budget_exceeded).
            try:
                T.llm_provider_keys.update_item(
                    Key={"pk": f"USER#{user_id}", "sk": f"KEY#{key_id}"},
                    UpdateExpression="SET #st = :exceeded",
                    ConditionExpression="#st = :active",
                    ExpressionAttributeNames={"#st": "status"},
                    ExpressionAttributeValues={
                        ":exceeded": "budget_exceeded",
                        ":active": "active",
                    },
                )
                logger.warning(
                    "llm_key_budget_exceeded user_id=%s key_id=%s budget_cents=%d usage_cents=%d",
                    user_id,
                    key_id,
                    budget,
                    current,
                )
            except T.llm_provider_keys.meta.client.exceptions.ConditionalCheckFailedException:
                # Another concurrent caller already flipped the status to
                # budget_exceeded — nothing more to do.
                logger.debug(
                    "llm_key_budget_exceeded_already_set user_id=%s key_id=%s",
                    user_id,
                    key_id,
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
# Monthly usage reset (GAP-0077)
# ---------------------------------------------------------------------------

# Run hourly; a reset only fires when a key's usage_reset_at is due, so the
# loop interval just bounds how soon after the month boundary the reset lands.
_RESET_INTERVAL_SECONDS = 3600


def _run_reset_pass() -> int:
    """Scan keys whose ``usage_reset_at`` is due and reset monthly counters.

    For each due key with a positive budget, zero ``current_month_usage_cents``,
    advance ``usage_reset_at`` to the next month boundary, and reactivate keys in
    ``budget_exceeded`` status. The update is guarded by a ConditionExpression
    so concurrent passes are idempotent and so suspended/revoked/invalid keys are
    never silently reactivated. Returns the number of keys reset.
    """
    now = now_ts()
    reset_count = 0

    scan_kwargs: Dict[str, Any] = {
        "FilterExpression": "usage_reset_at > :zero AND usage_reset_at <= :now",
        "ExpressionAttributeValues": {":zero": 0, ":now": now},
    }
    resp = T.llm_provider_keys.scan(**scan_kwargs)

    while True:
        for item in resp.get("Items", []):
            sk = item.get("sk", "")
            if not sk.startswith("KEY#"):
                continue
            budget = int(item.get("monthly_budget_cents", 0) or 0)
            if budget <= 0:
                continue  # no budget set — nothing to reset

            pk = item["pk"]
            new_reset_at = _next_reset_at(now)
            try:
                T.llm_provider_keys.update_item(
                    Key={"pk": pk, "sk": sk},
                    UpdateExpression=(
                        "SET current_month_usage_cents = :zero, "
                        "#st = :active, "
                        "usage_reset_at = :next_reset, "
                        "updated_at = :now"
                    ),
                    # Only reset keys that are still due AND budget_exceeded —
                    # leaves suspended/revoked/invalid keys untouched and makes
                    # concurrent passes idempotent.
                    ConditionExpression="usage_reset_at <= :now AND #st = :exceeded",
                    ExpressionAttributeNames={"#st": "status"},
                    ExpressionAttributeValues={
                        ":zero": 0,
                        ":active": "active",
                        ":exceeded": "budget_exceeded",
                        ":now": now,
                        ":next_reset": new_reset_at,
                    },
                )
                reset_count += 1
                logger.info(
                    "llm_key_monthly_reset pk=%s sk=%s next_reset_at=%d",
                    pk, sk, new_reset_at,
                )
            except T.llm_provider_keys.meta.client.exceptions.ConditionalCheckFailedException:
                # Already reset by a concurrent pass, or the key is not in
                # budget_exceeded status (e.g. an active key that simply
                # rolled past its reset date). Advance usage_reset_at for
                # active keys so they don't get re-scanned every pass.
                if item.get("status") == "active":
                    try:
                        T.llm_provider_keys.update_item(
                            Key={"pk": pk, "sk": sk},
                            UpdateExpression=(
                                "SET current_month_usage_cents = :zero, "
                                "usage_reset_at = :next_reset, updated_at = :now"
                            ),
                            ConditionExpression="usage_reset_at <= :now AND #st = :active",
                            ExpressionAttributeNames={"#st": "status"},
                            ExpressionAttributeValues={
                                ":zero": 0,
                                ":active": "active",
                                ":now": now,
                                ":next_reset": new_reset_at,
                            },
                        )
                        reset_count += 1
                        logger.info(
                            "llm_key_monthly_reset_active pk=%s sk=%s next_reset_at=%d",
                            pk, sk, new_reset_at,
                        )
                    except T.llm_provider_keys.meta.client.exceptions.ConditionalCheckFailedException:
                        pass

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        resp = T.llm_provider_keys.scan(ExclusiveStartKey=last_key, **scan_kwargs)

    if reset_count:
        logger.info("llm_usage_reset_pass reset_count=%d", reset_count)
    return reset_count


async def _reset_loop() -> None:
    while True:
        try:
            _run_reset_pass()
        except Exception:
            logger.exception("llm_usage_reset loop error")
        await asyncio.sleep(_RESET_INTERVAL_SECONDS)


def start_llm_usage_reset_task() -> None:
    """Register the monthly LLM usage reset loop as a startup background task.

    Mirrors the other periodic startup tasks (e.g. start_billing_dunning_task).
    Uses ``T.llm_provider_keys`` which resolves to DynamoDB Local in dev and
    real DynamoDB in prod — no new AWS services, dev/prod parity (SECOPS-007).
    """
    asyncio.create_task(_reset_loop())
    logger.info("llm_usage_reset_task started")


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
