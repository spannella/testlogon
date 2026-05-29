# DELEGATE-005: Delegation API

**Ticket**: DELEGATE-005
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 8-10 days

---

## 1. Overview & Motivation

### 1.1 Purpose

DELEGATE-005 provides a REST API that external tools (social media dashboards, CRM systems, chatbots, scheduling platforms) can use to perform delegated actions programmatically on behalf of creators. The API extends the existing API key system (`app/services/api_keys.py`) with a new `delegation_scope` field that binds keys to specific creators and permission sets. It includes stricter rate limiting, webhook support for event-driven integrations, and a self-describing documentation endpoint.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Developer | As a developer building a social media dashboard, I want to send messages on behalf of a creator via API so that my tool can automate chat responses. | POST with delegation-scoped API key; message created with correct creator attribution and delegate metadata. |
| Developer | As a developer, I want to create API keys scoped to specific creators and permissions so that each integration has least-privilege access. | POST API key with `delegation_scope`; key can only access specified creator with specified permissions. |
| Developer | As a developer, I want to receive webhooks when new messages arrive so that my tool can respond in real-time. | Register webhook URL; receive POST with event payload on new message; retry on failure. |
| Creator | As a creator, I want to approve which external tools have delegation API access so that I control third-party integrations. | Creator sees pending API key requests; can approve or reject; approved keys become active. |
| Creator | As a creator, I want to revoke API key access to external tools so that I can cut off a misbehaving integration. | DELETE API key; all subsequent requests with that key return 401. |
| Developer | As a developer, I want to query the API to see what actions my key is authorized to perform so that my tool adapts to its permissions. | GET scope endpoint returns available actions, creators, and permissions for the authenticated key. |
| Admin | As a platform admin, I want to see all delegation API keys and their usage so that I can monitor third-party access. | Admin endpoint returns all delegation-scoped keys with usage metrics. |
| Developer | As a developer, I want rate limit headers on API responses so that my tool can implement proper backoff. | Every response includes `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` headers. |

### 1.3 Why This Is Needed

Creators use external tools to manage their online presence -- social media schedulers (Buffer, Hootsuite), CRM systems (HubSpot), chatbots (ManyChat), and analytics platforms. These tools need programmatic access to the creator's messaging, newsfeed, and broadcast features. Without a delegation API, external tools cannot integrate with the platform, forcing creators to manually duplicate actions across systems. The delegation API enables a platform ecosystem where third-party tools enhance creator productivity.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| API key service | `app/services/api_keys.py` (~412 lines) | Key creation, hashing, capabilities, IP rules, rate limits; foundation for delegation API keys |
| API key router | `app/routers/api_keys.py` | Key management endpoints; will be extended with delegation scope |
| Auth deps | `app/auth/deps.py` | Bearer token auth via `extract_bearer_token`; delegation API uses same mechanism |
| Delegate chat service | `app/services/delegate_chat.py` (DELEGATE-002) | Chat delegation logic; API wraps same service |
<!-- NOTE: app/services/delegate_chat.py does not exist yet — depends on DELEGATE-002 -->
| Delegate feed service | `app/services/delegate_feed.py` (DELEGATE-003) | Feed delegation logic; API wraps same service |
<!-- NOTE: app/services/delegate_feed.py does not exist yet — depends on DELEGATE-003 -->
| Delegate broadcast service | `app/services/delegate_broadcast.py` (DELEGATE-004) | Broadcast delegation logic; API wraps same service |
<!-- NOTE: app/services/delegate_broadcast.py does not exist yet — depends on DELEGATE-004 -->
| Delegates service | `app/services/delegates.py` (DELEGATE-001) | Permission checks, delegation records |
<!-- NOTE: app/services/delegates.py does not exist yet — depends on DELEGATE-001 -->
| Rate limiter | In-memory rate limiter in various routers | Per-user rate limiting; delegation API needs per-key limits |
| Settings | `app/core/settings.py` | Configuration for rate limits, webhook settings |

### 2.2 Gaps

1. **No `delegation_scope` on API keys** -- existing API keys have `capabilities` (e.g., `messaging_read`, `messaging_write`) but no concept of acting on behalf of a specific creator.
2. **No creator-approval flow for API keys** -- API keys are self-service; there is no mechanism for a creator to approve an external tool's access request.
3. **No webhook system** -- the platform has no outbound webhook infrastructure for notifying external tools of events.
4. **No per-key rate limiting** -- rate limits are per-user, not per-API-key. Multiple keys for the same user share a single rate limit bucket.
5. **No delegation API routes** -- the existing `/api/` routes are user-centric, not delegation-centric.
6. **No scope discovery endpoint** -- API clients cannot programmatically determine what actions their key allows.
7. **No rate limit response headers** -- API responses do not include standard rate limit headers.

---

## 3. Technical Design

### 3.1 DynamoDB Schema Changes

#### 3.1.1 API Key Extensions

Add fields to API key items in the `api_keys` table:

| Field | Type | Purpose |
|-------|------|---------|
| `delegation_scope` | M (map) | `{creator_id: str, permissions: List[str], preset: str}` -- binds key to a specific creator and permission set |
| `delegation_status` | S | `pending` / `active` / `rejected` -- creator approval status |
| `delegation_approved_at` | N | Timestamp when creator approved the key |
| `webhook_url` | S | URL to receive webhook events |
| `webhook_secret` | S | HMAC secret for webhook signature verification |
| `webhook_events` | L (list) | List of event types the webhook should receive |
| `rate_limit_rpm` | N | Per-key rate limit (requests per minute), overrides default |
| `last_used_at` | N | Timestamp of last API call with this key |
| `total_calls` | N | Total number of API calls made with this key |

#### 3.1.2 Webhook Delivery Log

Add a new item pattern to the `api_keys` table:

| PK Pattern | SK Pattern | Purpose | Key Fields |
|------------|------------|---------|------------|
| `WEBHOOK#{key_id}` | `DELIVERY#{ts}#{delivery_id}` | Webhook delivery attempt | `delivery_id`, `event_type`, `payload_hash`, `status` (pending/delivered/failed), `response_status`, `attempt_count`, `last_attempt_at` |

#### 3.1.3 GSI for Delegation API Keys by Creator

**GSI: ByDelegationCreator**
- `GSI_DEL_PK`: `DELEGATION_CREATOR#{creator_id}` (set only when `delegation_scope` is present)
- `GSI_DEL_SK`: `created_at` (N)

```python
# Add to existing api_keys TableDef GSIs
{"name": "ByDelegationCreator", "pk": "GSI_DEL_PK", "sk": "GSI_DEL_SK"},
# Add to attr_types
"GSI_DEL_SK": "N",
```

### 3.2 Backend Service

**New file**: `app/services/delegation_api.py` (~400 lines)

```python
"""Delegation API service (DELEGATE-005).

Extends the API key system with delegation scope, webhook delivery,
and per-key rate limiting for external tool integrations.
"""

from __future__ import annotations
import hashlib
import hmac
import logging
import time
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional
from uuid import uuid4
from app.core.tables import T
from app.core.time import now_ts
from app.services.api_keys import (
    create_api_key,
    api_key_hash,
    get_api_key_item,
    revoke_api_key,
)
from app.services.delegates import (
    get_delegate,
    require_delegate_permission,
    check_delegate_permission,
)
from app.services.profile import get_profile

logger = logging.getLogger(__name__)

# Per-key rate limit tracking (in-memory)
_key_rate_buckets: Dict[str, deque] = defaultdict(deque)

DEFAULT_RATE_LIMIT_RPM = 60
MAX_RATE_LIMIT_RPM = 300
WEBHOOK_MAX_RETRIES = 5
WEBHOOK_RETRY_BACKOFF_BASE = 2.0


def create_delegation_api_key(
    *,
    owner_sub: str,
    label: str,
    creator_id: str,
    permissions: List[str],
    preset: Optional[str] = None,
    webhook_url: Optional[str] = None,
    webhook_events: Optional[List[str]] = None,
    rate_limit_rpm: int = DEFAULT_RATE_LIMIT_RPM,
    expires_in_days: Optional[int] = None,
) -> Dict[str, Any]:
    """Create an API key with delegation scope.
    
    The key is created in 'pending' status until the creator
    approves the delegation request.
    """
    # Validate the owner is an active delegate for the creator
    require_delegate_permission(
        creator_id=creator_id,
        delegate_id=owner_sub,
        required_permission=permissions[0],  # Must have at least one delegated permission
    )
    
    # Validate rate limit
    if rate_limit_rpm > MAX_RATE_LIMIT_RPM:
        raise ValueError(f"Rate limit cannot exceed {MAX_RATE_LIMIT_RPM} RPM")
    
    # Create the base API key
    key_item = create_api_key(
        owner_sub,
        label,
        expires_in_days=expires_in_days,
        capabilities=[f"delegate:{p}" for p in permissions],
    )
    
    ts = now_ts()
    delegation_scope = {
        "creator_id": creator_id,
        "permissions": permissions,
        "preset": preset,
    }
    
    # Update key with delegation fields
    T.api_keys.update_item(
        Key={"pk": key_item["pk"], "sk": key_item["sk"]},
        UpdateExpression="SET delegation_scope = :ds, delegation_status = :st, "
                        "rate_limit_rpm = :rl, webhook_url = :wu, webhook_events = :we, "
                        "webhook_secret = :ws, GSI_DEL_PK = :dp, GSI_DEL_SK = :dk, "
                        "total_calls = :tc, last_used_at = :lu",
        ExpressionAttributeValues={
            ":ds": delegation_scope,
            ":st": "pending",
            ":rl": rate_limit_rpm,
            ":wu": webhook_url or "",
            ":we": webhook_events or [],
            ":ws": _generate_webhook_secret() if webhook_url else "",
            ":dp": f"DELEGATION_CREATOR#{creator_id}",
            ":dk": ts,
            ":tc": 0,
            ":lu": 0,
        },
    )
    
    key_item["delegation_scope"] = delegation_scope
    key_item["delegation_status"] = "pending"
    return key_item


def approve_delegation_key(
    *,
    creator_id: str,
    key_id: str,
) -> Dict[str, Any]:
    """Creator approves a delegation API key request."""
    key_item = get_api_key_item(key_id)
    scope = key_item.get("delegation_scope", {})
    
    if scope.get("creator_id") != creator_id:
        raise HTTPException(403, "Key is not scoped to this creator")
    if key_item.get("delegation_status") != "pending":
        raise HTTPException(400, "Key is not in pending status")
    
    ts = now_ts()
    T.api_keys.update_item(
        Key={"pk": key_item["pk"], "sk": key_item["sk"]},
        UpdateExpression="SET delegation_status = :st, delegation_approved_at = :at",
        ExpressionAttributeValues={
            ":st": "active",
            ":at": ts,
        },
    )
    return {**key_item, "delegation_status": "active", "delegation_approved_at": ts}


def reject_delegation_key(
    *,
    creator_id: str,
    key_id: str,
) -> None:
    """Creator rejects a delegation API key request."""
    key_item = get_api_key_item(key_id)
    scope = key_item.get("delegation_scope", {})
    
    if scope.get("creator_id") != creator_id:
        raise HTTPException(403, "Key is not scoped to this creator")
    
    T.api_keys.update_item(
        Key={"pk": key_item["pk"], "sk": key_item["sk"]},
        UpdateExpression="SET delegation_status = :st",
        ExpressionAttributeValues={":st": "rejected"},
    )


def revoke_delegation_key(
    *,
    creator_id: str,
    key_id: str,
) -> None:
    """Creator revokes a delegation API key."""
    key_item = get_api_key_item(key_id)
    scope = key_item.get("delegation_scope", {})
    
    if scope.get("creator_id") != creator_id:
        raise HTTPException(403, "Key is not scoped to this creator")
    
    revoke_api_key(key_item["user_sub"], key_id)


def list_delegation_keys_for_creator(
    creator_id: str,
    *,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """List all delegation API keys scoped to a creator."""
    # GSI query: GSI_DEL_PK = DELEGATION_CREATOR#{creator_id}


def validate_delegation_api_key(
    *,
    key_id: str,
    key_secret: str,
    client_ip: str,
    required_permission: str,
) -> Dict[str, Any]:
    """Validate a delegation API key for an API call.
    
    Checks: key exists, not revoked, delegation_status=active,
    IP rules, rate limits, permission scope.
    Returns the key item with delegation context.
    """
    from app.services.api_keys import check_api_key_allowed
    
    key_item = check_api_key_allowed(key_id, key_secret, client_ip)
    
    if not key_item.get("delegation_scope"):
        raise HTTPException(403, "Key does not have delegation scope")
    if key_item.get("delegation_status") != "active":
        raise HTTPException(403, "Delegation key is not active (status: {})".format(
            key_item.get("delegation_status", "unknown")))
    
    scope = key_item["delegation_scope"]
    if required_permission not in scope.get("permissions", []):
        raise HTTPException(403, f"Key does not have permission: {required_permission}")
    
    # Enforce per-key rate limit
    _enforce_key_rate_limit(key_id, key_item.get("rate_limit_rpm", DEFAULT_RATE_LIMIT_RPM))
    
    # Update usage counters
    _record_key_usage(key_item)
    
    return key_item


def get_key_scope(key_id: str) -> Dict[str, Any]:
    """Return the scope and available actions for an API key."""
    key_item = get_api_key_item(key_id)
    scope = key_item.get("delegation_scope", {})
    
    creator_id = scope.get("creator_id", "")
    permissions = scope.get("permissions", [])
    
    # Build available actions list from permissions
    actions = _build_available_actions(permissions)
    
    creator_profile = get_profile(creator_id) or {}
    
    return {
        "key_id": key_id,
        "creator_id": creator_id,
        "creator_display_name": creator_profile.get("display_name", ""),
        "permissions": permissions,
        "preset": scope.get("preset"),
        "available_actions": actions,
        "rate_limit_rpm": key_item.get("rate_limit_rpm", DEFAULT_RATE_LIMIT_RPM),
        "total_calls": key_item.get("total_calls", 0),
        "webhook_url": key_item.get("webhook_url", ""),
        "webhook_events": key_item.get("webhook_events", []),
    }


# --- Webhook delivery ---

def register_webhook(
    *,
    key_id: str,
    owner_sub: str,
    url: str,
    events: List[str],
) -> Dict[str, Any]:
    """Register or update a webhook for an API key."""
    key_item = get_api_key_item(key_id)
    if key_item.get("user_sub") != owner_sub:
        raise HTTPException(403, "Not the key owner")
    
    _validate_webhook_url(url)
    _validate_webhook_events(events)
    
    secret = _generate_webhook_secret()
    
    T.api_keys.update_item(
        Key={"pk": key_item["pk"], "sk": key_item["sk"]},
        UpdateExpression="SET webhook_url = :u, webhook_events = :e, webhook_secret = :s",
        ExpressionAttributeValues={":u": url, ":e": events, ":s": secret},
    )
    
    return {"webhook_url": url, "webhook_events": events, "webhook_secret": secret}


def deliver_webhook(
    *,
    key_id: str,
    event_type: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    """Deliver a webhook event to the registered URL.
    
    Signs the payload with HMAC-SHA256 using the webhook secret.
    Retries with exponential backoff on failure.
    """
    key_item = get_api_key_item(key_id)
    webhook_url = key_item.get("webhook_url")
    webhook_secret = key_item.get("webhook_secret")
    webhook_events = key_item.get("webhook_events", [])
    
    if not webhook_url or event_type not in webhook_events:
        return {"skipped": True}
    
    delivery_id = f"dlv_{uuid4().hex}"
    ts = now_ts()
    
    # Compute HMAC signature
    payload_json = json.dumps(payload, sort_keys=True)
    signature = hmac.new(
        webhook_secret.encode(),
        payload_json.encode(),
        hashlib.sha256,
    ).hexdigest()
    
    # Store delivery attempt
    delivery = {
        "pk": f"WEBHOOK#{key_id}",
        "sk": f"DELIVERY#{ts}#{delivery_id}",
        "delivery_id": delivery_id,
        "event_type": event_type,
        "payload_hash": hashlib.sha256(payload_json.encode()).hexdigest(),
        "status": "pending",
        "response_status": 0,
        "attempt_count": 0,
        "last_attempt_at": ts,
    }
    T.api_keys.put_item(Item=delivery)
    
    # Attempt delivery (fire-and-forget in background)
    # _attempt_webhook_delivery(delivery_id, webhook_url, payload_json, signature)
    return delivery


def list_webhook_deliveries(
    key_id: str,
    *,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """List recent webhook delivery attempts for an API key."""
    # Query WEBHOOK#{key_id} with sk begins_with "DELIVERY#"
    # ScanIndexForward=False for newest first


# --- Rate limiting ---

def _enforce_key_rate_limit(key_id: str, rpm: int) -> None:
    """Enforce per-key rate limit. Raises 429 if exceeded."""
    now = time.time()
    window = 60.0
    bucket = _key_rate_buckets[key_id]
    
    # Trim old entries
    while bucket and bucket[0] < now - window:
        bucket.popleft()
    
    if len(bucket) >= rpm:
        retry_after = int(bucket[0] + window - now) + 1
        raise HTTPException(
            429,
            detail=f"Rate limit exceeded ({rpm} requests/minute)",
            headers={
                "Retry-After": str(retry_after),
                "X-RateLimit-Limit": str(rpm),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(bucket[0] + window)),
            },
        )
    
    bucket.append(now)


def _record_key_usage(key_item: Dict[str, Any]) -> None:
    """Update usage counters on the API key item."""
    ts = now_ts()
    T.api_keys.update_item(
        Key={"pk": key_item["pk"], "sk": key_item["sk"]},
        UpdateExpression="SET last_used_at = :lu ADD total_calls :one",
        ExpressionAttributeValues={":lu": ts, ":one": 1},
    )


def get_rate_limit_headers(key_id: str, rpm: int) -> Dict[str, str]:
    """Generate rate limit response headers."""
    now = time.time()
    bucket = _key_rate_buckets.get(key_id, deque())
    remaining = max(0, rpm - len(bucket))
    reset = int(now + 60) if not bucket else int(bucket[0] + 60)
    
    return {
        "X-RateLimit-Limit": str(rpm),
        "X-RateLimit-Remaining": str(remaining),
        "X-RateLimit-Reset": str(reset),
    }


# --- Internal helpers ---

def _generate_webhook_secret() -> str:
    """Generate a random webhook signing secret."""
    return f"whsec_{uuid4().hex}"

def _validate_webhook_url(url: str) -> None:
    """Validate webhook URL is HTTPS."""
    if not url.startswith("https://"):
        raise ValueError("Webhook URL must use HTTPS")

def _validate_webhook_events(events: List[str]) -> None:
    """Validate webhook event types."""
    valid_events = {
        "message.created", "message.updated", "message.deleted",
        "post.created", "post.updated", "post.deleted",
        "comment.created", "comment.deleted",
        "broadcast.started", "broadcast.ended",
        "broadcast.chat.message", "broadcast.chat.moderation",
    }
    invalid = set(events) - valid_events
    if invalid:
        raise ValueError(f"Invalid webhook events: {invalid}")

def _build_available_actions(permissions: List[str]) -> List[Dict[str, str]]:
    """Build a list of available API actions from permissions."""
    actions = []
    action_map = {
        "chat_read": [
            {"method": "GET", "path": "/api/delegate/conversations", "description": "List creator's conversations"},
            {"method": "GET", "path": "/api/delegate/conversations/{id}/messages", "description": "List messages"},
        ],
        "chat_respond": [
            {"method": "POST", "path": "/api/delegate/conversations/{id}/messages", "description": "Send message as creator"},
        ],
        "feed_read": [
            {"method": "GET", "path": "/api/delegate/posts", "description": "List creator's posts"},
            {"method": "GET", "path": "/api/delegate/analytics", "description": "Get feed analytics"},
        ],
        "feed_post": [
            {"method": "POST", "path": "/api/delegate/posts", "description": "Create post as creator"},
            {"method": "PUT", "path": "/api/delegate/posts/{id}", "description": "Edit post"},
            {"method": "DELETE", "path": "/api/delegate/posts/{id}", "description": "Delete post"},
        ],
        "feed_moderate": [
            {"method": "POST", "path": "/api/delegate/posts/{id}/comments/{cid}/moderate", "description": "Moderate comment"},
        ],
        "broadcast_moderate": [
            {"method": "POST", "path": "/api/delegate/broadcast/{sid}/chat/{mid}/pin", "description": "Pin chat message"},
            {"method": "DELETE", "path": "/api/delegate/broadcast/{sid}/chat/{mid}", "description": "Delete chat message"},
            {"method": "POST", "path": "/api/delegate/broadcast/{sid}/mute", "description": "Mute viewer"},
            {"method": "POST", "path": "/api/delegate/broadcast/{sid}/ban", "description": "Ban viewer"},
            {"method": "POST", "path": "/api/delegate/broadcast/{sid}/announcement", "description": "Post announcement"},
        ],
        "broadcast_control": [
            {"method": "POST", "path": "/api/delegate/broadcast/{sid}/start", "description": "Start broadcast"},
            {"method": "POST", "path": "/api/delegate/broadcast/{sid}/stop", "description": "Stop broadcast"},
            {"method": "POST", "path": "/api/delegate/broadcast/schedule", "description": "Schedule broadcast"},
        ],
    }
    for perm in permissions:
        actions.extend(action_map.get(perm, []))
    return actions
```

### 3.3 Backend Router

**New file**: `app/routers/delegation_api.py` (~350 lines)

```python
"""Delegation API router (DELEGATE-005).

External-facing API for third-party tools to perform
delegated actions on behalf of creators.
"""

from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from app.services.sessions import require_ui_session  # actual location of require_ui_session
from app.services import delegation_api as svc
from app.services import delegate_chat, delegate_feed, delegate_broadcast

# UI routes for managing delegation API keys
ui_router = APIRouter(prefix="/ui/delegation-api", tags=["delegation-api-management"])

# External API routes for third-party integrations
api_router = APIRouter(prefix="/api/delegate", tags=["delegation-api"])
```

### 3.4 Router Endpoints

#### 3.4.1 UI Management Endpoints (Cookie Auth)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/ui/delegation-api/keys` | `require_ui_session` | Create delegation API key |
| `GET` | `/ui/delegation-api/keys` | `require_ui_session` | List user's delegation API keys |
| `DELETE` | `/ui/delegation-api/keys/{key_id}` | `require_ui_session` | Revoke delegation API key |
| `GET` | `/ui/delegation-api/keys/{key_id}/scope` | `require_ui_session` | Get key scope and available actions |
| `POST` | `/ui/delegation-api/keys/{key_id}/webhook` | `require_ui_session` | Register/update webhook |
| `GET` | `/ui/delegation-api/keys/{key_id}/webhook/deliveries` | `require_ui_session` | List webhook deliveries |
| `GET` | `/ui/delegation-api/pending` | `require_ui_session` | List pending delegation key requests (creator view) |
| `POST` | `/ui/delegation-api/pending/{key_id}/approve` | `require_ui_session` | Approve delegation key (creator) |
| `POST` | `/ui/delegation-api/pending/{key_id}/reject` | `require_ui_session` | Reject delegation key (creator) |
| `DELETE` | `/ui/delegation-api/creator-keys/{key_id}` | `require_ui_session` | Creator revokes a delegation key |

#### 3.4.2 External API Endpoints (API Key Auth)

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| `GET` | `/api/delegate/scope` | API key | any | Get key scope and available actions |
| `GET` | `/api/delegate/conversations` | API key | `chat_read` | List creator's conversations |
| `GET` | `/api/delegate/conversations/{cid}/messages` | API key | `chat_read` | List messages |
| `POST` | `/api/delegate/conversations/{cid}/messages` | API key | `chat_respond` | Send message as creator |
| `GET` | `/api/delegate/posts` | API key | `feed_read` | List creator's posts |
| `POST` | `/api/delegate/posts` | API key | `feed_post` | Create post as creator |
| `PUT` | `/api/delegate/posts/{pid}` | API key | `feed_post` | Edit post |
| `DELETE` | `/api/delegate/posts/{pid}` | API key | `feed_post` | Delete post |
| `POST` | `/api/delegate/posts/{pid}/comments/{cid}/moderate` | API key | `feed_moderate` | Moderate comment |
| `GET` | `/api/delegate/analytics` | API key | `feed_read` | Get feed analytics |
| `POST` | `/api/delegate/broadcast/{sid}/chat/{mid}/pin` | API key | `broadcast_moderate` | Pin chat message |
| `DELETE` | `/api/delegate/broadcast/{sid}/chat/{mid}` | API key | `broadcast_moderate` | Delete chat message |
| `POST` | `/api/delegate/broadcast/{sid}/mute` | API key | `broadcast_moderate` | Mute viewer |
| `POST` | `/api/delegate/broadcast/{sid}/ban` | API key | `broadcast_moderate` | Ban viewer |
| `POST` | `/api/delegate/broadcast/{sid}/announcement` | API key | `broadcast_moderate` | Post announcement |
| `POST` | `/api/delegate/broadcast/{sid}/start` | API key | `broadcast_control` | Start broadcast |
| `POST` | `/api/delegate/broadcast/{sid}/stop` | API key | `broadcast_control` | Stop broadcast |
| `POST` | `/api/delegate/broadcast/schedule` | API key | `broadcast_control` | Schedule broadcast |

### 3.5 API Key Authentication

The delegation API uses the existing API key mechanism (`Authorization: Bearer <api_key>`) but adds delegation-specific validation:

```python
async def require_delegation_api_key(
    request: Request,
    required_permission: str,
) -> Dict[str, Any]:
    """FastAPI dependency that validates a delegation API key.
    
    1. Extracts API key from Authorization header
    2. Validates key hash, expiry, revocation
    3. Checks delegation_status == "active"
    4. Checks required permission is in delegation_scope.permissions
    5. Enforces per-key rate limit
    6. Adds rate limit headers to response
    """
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(401, "Missing or invalid Authorization header")
    
    api_key = auth_header[7:]
    parsed = parse_api_key(api_key)
    
    key_item = validate_delegation_api_key(
        key_id=parsed["key_id"],
        key_secret=parsed["secret"],
        client_ip=request.client.host,
        required_permission=required_permission,
    )
    
    return key_item
```

### 3.6 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Delegation API (DELEGATE-005) --

class DelegationApiKeyCreateIn(BaseModel):
    label: str = Field(min_length=1, max_length=200)
    creator_id: str = Field(min_length=1)
    permissions: List[str] = Field(min_length=1)
    preset: Optional[str] = None
    webhook_url: Optional[str] = Field(None, max_length=500)
    webhook_events: Optional[List[str]] = None
    rate_limit_rpm: int = Field(default=60, ge=1, le=300)
    expires_in_days: Optional[int] = Field(None, ge=1, le=365)

class WebhookRegisterIn(BaseModel):
    url: str = Field(min_length=1, max_length=500)
    events: List[str] = Field(min_length=1)

class DelegationApiKeyOut(BaseModel):
    key_id: str
    label: str
    api_key: Optional[str] = None  # Only returned on creation
    creator_id: str = ""
    creator_display_name: str = ""
    permissions: List[str] = Field(default_factory=list)
    preset: Optional[str] = None
    delegation_status: str  # "pending" | "active" | "rejected"
    rate_limit_rpm: int = 60
    webhook_url: str = ""
    webhook_events: List[str] = Field(default_factory=list)
    total_calls: int = 0
    last_used_at: int = 0
    created_at: int = 0
    delegation_approved_at: Optional[int] = None
    expires_at: Optional[int] = None

class KeyScopeOut(BaseModel):
    key_id: str
    creator_id: str
    creator_display_name: str = ""
    permissions: List[str] = Field(default_factory=list)
    preset: Optional[str] = None
    available_actions: List[Dict[str, str]] = Field(default_factory=list)
    rate_limit_rpm: int = 60
    total_calls: int = 0
    webhook_url: str = ""
    webhook_events: List[str] = Field(default_factory=list)

class WebhookDeliveryOut(BaseModel):
    delivery_id: str
    event_type: str
    status: str  # "pending" | "delivered" | "failed"
    response_status: int = 0
    attempt_count: int = 0
    last_attempt_at: int = 0
    ts: int = 0

class WebhookOut(BaseModel):
    webhook_url: str
    webhook_events: List[str]
    webhook_secret: str  # Only returned on registration
```

### 3.7 Webhook Architecture

#### 3.7.1 Event Types

| Event Type | Trigger | Payload |
|------------|---------|---------|
| `message.created` | New message in creator's conversation | `{conversation_id, message_id, sender_id, text_preview, created_at}` |
| `message.updated` | Message edited | `{conversation_id, message_id, updated_fields}` |
| `message.deleted` | Message deleted | `{conversation_id, message_id}` |
| `post.created` | New post on creator's feed | `{post_id, text_preview, author_id, created_at}` |
| `post.updated` | Post edited | `{post_id, updated_fields}` |
| `post.deleted` | Post deleted | `{post_id}` |
| `comment.created` | New comment on creator's post | `{post_id, comment_id, author_id, text_preview}` |
| `comment.deleted` | Comment deleted/moderated | `{post_id, comment_id}` |
| `broadcast.started` | Broadcast goes live | `{session_id, title, started_at}` |
| `broadcast.ended` | Broadcast ends | `{session_id, ended_at, viewer_count}` |
| `broadcast.chat.message` | New broadcast chat message | `{session_id, message_id, sender_id, text_preview}` |
| `broadcast.chat.moderation` | Moderation action in broadcast chat | `{session_id, action, moderator_id, target}` |

#### 3.7.2 Webhook Delivery

1. **Signing**: Every webhook payload is signed with HMAC-SHA256 using the key's `webhook_secret`. The signature is sent in the `X-Webhook-Signature` header.
2. **Delivery**: POST to the registered URL with `Content-Type: application/json`.
3. **Retries**: On non-2xx response, retry up to 5 times with exponential backoff (2s, 4s, 8s, 16s, 32s).
4. **Delivery log**: Each attempt is recorded in the `WEBHOOK#` items for debugging.
5. **Timeout**: 10-second timeout per delivery attempt.
6. **Deactivation**: After 100 consecutive failures, the webhook is deactivated and the key owner is notified.

#### 3.7.3 Webhook Payload Format

```json
{
  "event": "message.created",
  "timestamp": 1748520400,
  "key_id": "key_abc123",
  "creator_id": "alice@test.local",
  "data": {
    "conversation_id": "conv_xyz",
    "message_id": "m_abc",
    "sender_id": "fan@test.local",
    "text_preview": "Hey! Love your content...",
    "created_at": 1748520400
  }
}
```

### 3.8 Frontend Components

**New files**:

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/delegates/DelegationApiKeysPage.tsx` | API key management page | ~250 |
| `frontend/src/pages/delegates/CreateApiKeyDialog.tsx` | Dialog for creating a delegation API key | ~150 |
| `frontend/src/pages/delegates/ApiKeyScopeView.tsx` | Key scope and available actions view | ~100 |
| `frontend/src/pages/delegates/WebhookConfig.tsx` | Webhook URL and event configuration | ~80 |
| `frontend/src/pages/delegates/WebhookDeliveryLog.tsx` | Webhook delivery log | ~80 |
| `frontend/src/pages/delegates/PendingApiKeys.tsx` | Creator view of pending delegation key requests | ~100 |
| `frontend/src/api/endpoints/delegation-api.ts` | API client wrappers | ~120 |

**Component tree**:

```
DelegationApiKeysPage
├── Tabs
│   ├── "My API Keys" Tab (delegate/developer view)
│   │   ├── CreateApiKeyDialog (Button: "Create API Key")
│   │   │   ├── Label input
│   │   │   ├── Creator selector (from managed creators)
│   │   │   ├── Permission checkboxes (or preset dropdown)
│   │   │   ├── Rate limit RPM input
│   │   │   ├── Expiry selector
│   │   │   └── Webhook URL + events config
│   │   └── For each key:
│   │       ├── Label, status badge (pending/active/rejected)
│   │       ├── Creator name, permissions
│   │       ├── Usage: total calls, last used
│   │       ├── ApiKeyScopeView (expandable)
│   │       ├── WebhookConfig (expandable)
│   │       ├── WebhookDeliveryLog (expandable)
│   │       └── "Revoke" button
│   ├── "Pending Approvals" Tab (creator view)
│   │   └── PendingApiKeys
│   │       └── For each pending key:
│   │           ├── Key owner name, label
│   │           ├── Requested permissions
│   │           ├── "Approve" / "Reject" buttons
│   └── "Active Keys" Tab (creator view)
│       └── Keys approved by this creator
│           ├── Owner, label, permissions
│           ├── Usage stats
│           └── "Revoke" button
```

### 3.9 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/delegation_api.py` | Delegation API service | ~400 |
| `app/routers/delegation_api.py` | REST API endpoints (UI + external) | ~350 |
| `frontend/src/pages/delegates/DelegationApiKeysPage.tsx` | API key management page | ~250 |
| `frontend/src/pages/delegates/CreateApiKeyDialog.tsx` | Create key dialog | ~150 |
| `frontend/src/pages/delegates/ApiKeyScopeView.tsx` | Scope viewer | ~100 |
| `frontend/src/pages/delegates/WebhookConfig.tsx` | Webhook configuration | ~80 |
| `frontend/src/pages/delegates/WebhookDeliveryLog.tsx` | Delivery log | ~80 |
| `frontend/src/pages/delegates/PendingApiKeys.tsx` | Pending approvals | ~100 |
| `frontend/src/api/endpoints/delegation-api.ts` | API wrappers | ~120 |
| `frontend/e2e/delegates-api.spec.ts` | E2E tests | ~500 |

### 3.10 Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register `delegation_api_ui_router` and `delegation_api_router` |
| `app/models.py` | Add DelegationApiKey*, KeyScope*, Webhook* models |
| `app/services/api_keys.py` | Add `delegation_scope` field handling to `create_api_key`; add `parse_api_key` export |
| `scripts/local-ddb-init.py` | Add `ByDelegationCreator` GSI and `GSI_DEL_SK` to api_keys table attr_types |
| `frontend/src/api/types.ts` | Add DelegationApiKey, KeyScope, WebhookDelivery types |
| `frontend/src/App.tsx` | Add delegation API key management route |
| `frontend/src/pages/delegates/DelegatesPage.tsx` | Add "API Keys" tab linking to DelegationApiKeysPage |

---

## 4. Rate Limiting Design

### 4.1 Per-Key Rate Limits

Each delegation API key has its own rate limit bucket:

| Tier | RPM | Use Case |
|------|-----|----------|
| Default | 60 | Standard integrations |
| Custom | 1-300 | Set per-key at creation |
| Burst | 2x RPM for 10s | Allow short bursts for batch operations |

### 4.2 Response Headers

Every delegation API response includes:

```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1748520460
```

### 4.3 Rate Limit Exceeded Response

```json
{
  "detail": "Rate limit exceeded (60 requests/minute)",
  "retry_after": 15
}
```

With headers:
```
Retry-After: 15
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1748520460
```

### 4.4 Global vs Per-Key

- **Per-key**: tracked in-memory via `_key_rate_buckets`. Each key has its own sliding window.
- **Global**: the global rate limiter still applies. If the global limit is hit, all keys for that user are affected.
- **Delegation stricter**: delegation API rate limits are separate from and stricter than UI rate limits, preventing external tools from competing with the creator's own UI usage.

---

## 5. E2E Test Plan

**File**: `frontend/e2e/delegates-api.spec.ts`

### Section 503: Delegation API Key CRUD (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 503.1 | Create delegation API key | POST `/ui/delegation-api/keys`; 200; response has `key_id`, `api_key` (shown once), `delegation_status=pending` |
| 503.2 | List delegation API keys | GET `/ui/delegation-api/keys`; response includes created key with correct scope |
| 503.3 | Creator approves delegation key | POST `.../pending/{key_id}/approve`; 200; key `delegation_status=active` |
| 503.4 | Creator revokes delegation key | DELETE `.../creator-keys/{key_id}`; 200; key no longer usable |

### Section 504: Delegation API External Endpoints (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 504.1 | API key scope endpoint returns available actions | GET `/api/delegate/scope` with valid key; 200; `available_actions` list matches key permissions |
| 504.2 | Send message via delegation API | POST `/api/delegate/conversations/{cid}/messages`; 200; message created with creator attribution |
| 504.3 | Create post via delegation API | POST `/api/delegate/posts`; 200; post created on creator's feed |
| 504.4 | Permission check rejects unauthorized action | Key with only `chat_read`; POST message returns 403 |
| 504.5 | Inactive key returns 403 | Use key before creator approval; all endpoints return 403 with delegation status |

### Section 505: Webhook Registration & Delivery API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 505.1 | Register webhook for API key | POST `.../keys/{key_id}/webhook`; 200; response has `webhook_secret` |
| 505.2 | Webhook URL must be HTTPS | POST with `http://` URL; 400 response |
| 505.3 | Webhook delivery log returns entries | Trigger event; GET `.../webhook/deliveries`; response includes delivery with `event_type` and `status` |
| 505.4 | Invalid webhook events rejected | POST with invalid event type; 400 response |

### Section 506: Rate Limiting & Usage API (3 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 506.1 | Rate limit headers present in response | Any API call; response headers include `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` |
| 506.2 | Rate limit enforced per key | Set `rate_limit_rpm=2`; make 3 calls; third call returns 429 with `Retry-After` header |
| 506.3 | Usage counter incremented | Make 5 API calls; GET key scope; `total_calls=5` |

**Total E2E tests: 16**

---

## 6. Security Considerations

### 6.1 Auth Requirements

| Endpoint Group | Auth | Authorization |
|----------------|------|---------------|
| UI key management (`/ui/delegation-api/*`) | `require_ui_session` | Key owner or creator (depending on endpoint) |
| External API (`/api/delegate/*`) | API key (Bearer token) | Per-key permission scope |
| Creator approval/revocation | `require_ui_session` | Must be the creator in delegation scope |

### 6.2 API Key Security

- API keys are hashed with HMAC before storage (existing `api_key_hash` function). The raw key is only returned once at creation time.
- Keys inherit the existing IP allowlist/denylist mechanism from `api_keys.py`.
- Keys with delegation scope require creator approval before activation -- preventing unauthorized delegation API access.
- Keys can be revoked by either the owner (delegate) or the creator.

### 6.3 Webhook Security

- Webhook URLs must use HTTPS.
- Every payload is signed with HMAC-SHA256 using a per-key `webhook_secret`.
- The secret is only returned once at registration time.
- Webhook delivery is fire-and-forget -- failures do not block API responses.
- After 100 consecutive failures, webhooks are automatically deactivated.

### 6.4 Rate Limiting

- Per-key rate limits prevent any single integration from overwhelming the platform.
- Rate limits are strictly enforced server-side -- the in-memory bucket is the source of truth.
- Rate limit headers enable well-behaved clients to implement proper backoff.
- Global rate limits still apply as a second layer of protection.

### 6.5 Data Privacy

- API keys are scoped to a single creator -- a key cannot access another creator's data even if the delegate manages multiple creators.
- Webhook payloads include text previews (first 100 characters), not full content, to minimize data exposure.
- Encrypted messages are never included in webhook payloads.

---

## 7. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| DELEGATE-001 | Required | Delegation infrastructure, permission checks |
| DELEGATE-002 | Required | Chat delegation service (API wraps same service) |
| DELEGATE-003 | Required | Feed delegation service (API wraps same service) |
| DELEGATE-004 | Required | Broadcast delegation service (API wraps same service) |
| `app/services/api_keys.py` | Exists (modify) | Base API key functionality, key hashing, IP rules |
| `app/auth/deps.py` | Exists | Bearer token extraction for API key auth |
| `scripts/local-ddb-init.py` | Exists (modify) | Add GSI to api_keys table |

---

## 8. Acceptance Criteria

1. Delegation API keys can be created with a specific creator scope and permission set.
2. Keys require creator approval before activation.
3. Creators can approve, reject, and revoke delegation API keys.
4. All external API endpoints correctly enforce the key's permission scope.
5. Scope discovery endpoint returns available actions for the authenticated key.
6. Webhooks can be registered with HTTPS URLs and specific event types.
7. Webhook payloads are signed with HMAC-SHA256.
8. Per-key rate limiting is enforced with proper response headers.
9. Rate limit exceeded returns 429 with Retry-After header.
10. Usage counters (total_calls, last_used_at) are updated on each API call.
11. All 16 E2E tests pass.

---

## Codebase References

| File | Line(s) | What | Status |
|------|---------|------|--------|
| `app/services/api_keys.py` | all (412 lines) | API key creation, hashing, capabilities | EXISTS (modify) |
| `app/routers/api_keys.py` | all (168 lines) | API key management endpoints | EXISTS (modify) |
| `app/auth/deps.py` | all (308 lines) | Bearer token extraction | EXISTS |
| `app/services/sessions.py` | 283 | `require_ui_session` (NOT in app/auth/deps.py) | EXISTS |
| `app/services/delegates.py` | — | Delegate management (DELEGATE-001) | NOT YET CREATED |
| `app/services/delegate_chat.py` | — | Chat delegation (DELEGATE-002) | NOT YET CREATED |
| `app/services/delegate_feed.py` | — | Feed delegation (DELEGATE-003) | NOT YET CREATED |
| `app/services/delegate_broadcast.py` | — | Broadcast delegation (DELEGATE-004) | NOT YET CREATED |
| `app/core/settings.py` | all | Configuration for rate limits, webhook settings | EXISTS (modify) |
| `scripts/local-ddb-init.py` | all | Needs GSI additions for api_keys table | EXISTS (modify) |

---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_delegation_api.py`

| # | Test Function | Description | Mocks |
|---|--------------|-------------|-------|
| 1 | `test_create_delegation_api_key` | Key created with delegation_scope and pending status | moto DDB |
| 2 | `test_approve_delegation_key` | Status transitions to active | moto DDB |
| 3 | `test_validate_key_permission_scope` | 403 when key lacks required permission | moto DDB |
| 4 | `test_per_key_rate_limit` | 429 after exceeding rate_limit_rpm | moto DDB |
| 5 | `test_webhook_url_must_be_https` | ValueError for http:// URL | moto DDB |
| 6 | `test_webhook_delivery_signed` | HMAC-SHA256 signature on payload | moto DDB |
| 7 | `test_rate_limit_headers` | X-RateLimit-* headers present in response | moto DDB |

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | Full API key lifecycle: create, approve, use, revoke | delegation_api, api_keys, delegates |
| 2 | Webhook delivery: register, trigger event, verify delivery log | delegation_api |
| 3 | Cross-service: API key used for chat, feed, and broadcast | delegation_api, delegate_chat/feed/broadcast |

### E2E Tests (Playwright)

**File**: `frontend/e2e/delegates-api.spec.ts`

Tests use `injectAuth(page, identity)` for cookie-based auth and include CSRF headers (`x-csrf-token`) on all POST/PUT/DELETE requests. Negative tests cover 401 (unauthenticated), 403 (wrong role/user), 404 (not found), 409 (conflict), and 422 (validation) responses. Edge cases include duplicate operations (idempotency), concurrent access, and feature-flag-disabled behavior.

**Total E2E tests**: 16

### Test Data Requirements

- DDB seeds: required tables created via `scripts/local-ddb-init.py`
- Test users: Alice, Bob, Root, Charlie via `e2e_session_setup.py` / `e2e_admin_session_setup.py`
- Feature flag: `DELEGATION_API_ENABLED` in `.env.local`

### CI/Pipeline

- Feature flag: `DELEGATION_API_ENABLED` must be enabled for tests to run
- Serial execution: run with `--workers 1` to avoid shared state conflicts
- Retry safety: tests use unique timestamps/UUIDs per run; safe to retry on failure

---

## Dependencies & Merge Safety

### Depends On

| Ticket | Status | What It Provides |
|--------|--------|-----------------|
| DELEGATE-001 | Required | Delegation infrastructure, permission checks |
| DELEGATE-002 | Required | Chat delegation service |
| DELEGATE-003 | Required | Feed delegation service |
| DELEGATE-004 | Required | Broadcast delegation service |

### Depended On By

| Ticket | What It Needs |
|--------|--------------|
| (none currently) | -- |

### Merge Strategy

**Sequential (after DELEGATE-001 through 004)** -- Changes are additive (new service files, new router, new frontend pages). Shared infrastructure files (`main.py`, `settings.py`, `tables.py`, `local-ddb-init.py`) receive only additive modifications.

### Merge Checklist

- [ ] `app/services/delegation_api.py` created
- [ ] `app/routers/delegation_api.py` with UI + API routers registered in `main.py`
- [ ] `ByDelegationCreator` GSI added to api_keys table
- [ ] Rate limit headers on all `/api/delegate/*` responses
- [ ] All 16 E2E tests pass
- [ ] Feature flag `DELEGATION_API_ENABLED` added to `.env.local.example`
- [ ] All E2E tests pass
- [ ] No regressions in existing test suite
