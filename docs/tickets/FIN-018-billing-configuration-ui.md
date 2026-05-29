# FIN-018: Billing Configuration UI

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: Medium  
**Estimated effort**: 7-9 days  
**Dependencies**: Billing ledger (`billing_shared.py`), creator payouts (`creator_payouts.py`), admin auth (`auth/deps.py`)

---

## 1. Overview & Motivation

### The Gap

Billing parameters — platform fee percentages, minimum payout thresholds, minimum deposit amounts, currency settings, and tax rates — are currently configured via environment variables in `.env.local`. Changing any billing parameter requires:

1. Editing the env file
2. Restarting the backend
3. Waiting for the process to reload

There is no admin UI to adjust these values at runtime, no audit log of who changed what, and no way to preview the impact of a change before applying it.

### Why This Is Needed

1. **Runtime configuration**: Business conditions change. A promotional "zero fee" weekend should not require an engineer to edit env vars and restart production servers.

2. **Audit trail**: SOX compliance and investor due diligence require knowing who changed billing parameters, when, and what the previous values were. Env var changes leave no audit trail.

3. **Impact preview**: Changing the platform fee from 20% to 25% affects all future transactions. Admins need to see projected revenue impact before committing.

4. **Multi-parameter coordination**: Changing fee percentage and minimum payout threshold together must be atomic — not two separate env var edits with a restart between them.

5. **Separation of concerns**: Engineers should not be in the loop for business configuration changes. Admins should self-serve through a dedicated UI.

### User Stories

- As a **platform admin**, I want to adjust platform fee percentages through a UI so I can run promotions without engineering involvement.
- As a **platform admin**, I want to change the minimum payout threshold so I can lower it for new creators.
- As a **platform admin**, I want to see an audit log of all billing configuration changes so I can answer compliance questions.
- As a **platform admin**, I want to preview the impact of a fee change before applying it so I can avoid costly mistakes.
- As a **platform admin**, I want changes to take effect immediately without restarting the backend.

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                         BILLING CONFIGURATION SYSTEM                                │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌──────────────┐    ┌─────────────────────────┐    ┌──────────────────────────┐   │
│  │  Frontend     │    │  FastAPI Router          │    │  Billing Config Service  │   │
│  │  BillingConf  │───>│  admin_billing_config.py │───>│  billing_config.py       │   │
│  │  Page.tsx     │    │  4 endpoints             │    │                         │   │
│  │              │<───│                         │<───│                         │   │
│  └──────────────┘    └──────────┬──────────────┘    └──────────┬──────────────┘   │
│                                 │                               │                  │
│                    ┌────────────┼────────────────┐              │                  │
│                    v            v                v              v                  │
│          ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌───────────────┐    │
│          │ billing_conf  │ │ In-Memory    │ │   billing    │ │  billing      │    │
│          │  DDB Table    │ │ Cache (60s)  │ │  _shared.py  │ │  _shared.py   │    │
│          │ (config +     │ │              │ │  (reads fee  │ │  (reads min   │    │
│          │  audit log)   │ │              │ │   via cache) │ │   payout etc) │    │
│          └──────────────┘ └──────────────┘ └──────────────┘ └───────────────┘    │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘

Data Flow: Config Update with Impact Preview
═════════════════════════════════════════════

  Admin clicks "Preview Impact" with proposed changes
       │
       v
  ┌──────────────────────────────────────────────────────────────────────┐
  │  POST /v1/admin/billing-config/preview                               │
  │    1. Read proposed changes (e.g., fee_tips_bps: 1500 → 2500)        │
  │    2. Query billing ledger: last 7 days of transactions              │
  │       ├── Count transactions by entry_type                           │
  │       ├── Sum amounts by entry_type                                  │
  │       └── Calculate average daily volume                             │
  │    3. Compute impact:                                                │
  │       ├── For each changed fee:                                      │
  │       │     daily_delta = avg_daily_amount * (new_bps - old_bps)/10000│
  │       ├── Aggregate across all changed fee types                     │
  │       └── Build sample before/after for a typical transaction        │
  │    4. Return preview:                                                │
  │       {affected_tx_types, projected_daily_delta_cents,               │
  │        sample_before: {amount: 1000, fee: 200, net: 800},           │
  │        sample_after:  {amount: 1000, fee: 250, net: 750}}           │
  └──────────────────────────────────────────────────────────────────────┘
       │
       v  Admin reviews impact → clicks "Save Changes"
  ┌──────────────────────────────────────────────────────────────────────┐
  │  PATCH /v1/admin/billing-config                                      │
  │    1. Read current config from DDB                                   │
  │    2. Compute diff: {field: {old: X, new: Y}} for each changed field │
  │    3. Write updated config to DDB (BILLING_CONFIG / CURRENT)         │
  │    4. Write audit entry (BILLING_CONFIG / AUDIT#{ts}#{id})           │
  │    5. Invalidate in-memory cache (_config_cache = None)              │
  │    6. Return updated config                                          │
  └──────────────────────────────────────────────────────────────────────┘

Data Flow: Runtime Fee Lookup
═════════════════════════════

  User sends tip → billing_shared.new_ledger_entry()
       │
       v
  ┌──────────────────────────────────────────────────────────────────────┐
  │  billing_config.get_fee_bps("tip_debit")                             │
  │    1. Check _config_cache:                                           │
  │       ├── If cache exists AND (now - _cache_ts) < 60s:               │
  │       │     Return cached value (no DDB call)                        │
  │       └── Else:                                                      │
  │             Query DDB: billing_config(BILLING_CONFIG, CURRENT)        │
  │             If item exists: cache it, return fee_tips_bps             │
  │             If not: fall back to env var S.platform_fee_bps           │
  │    2. Map entry_type to fee field:                                   │
  │       tip_debit       → fee_tips_bps                                 │
  │       unlock_debit    → fee_unlocks_bps                              │
  │       subscription    → fee_subscriptions_bps                        │
  │       catalog_purchase → fee_catalog_bps                             │
  │    3. Return basis points value                                      │
  └──────────────────────────────────────────────────────────────────────┘
```

### Architecture After This Change

```
Billing Configuration (/admin/billing-config)
│
├── Fee Configuration
│   ├── Platform fee % (per transaction type)
│   │   ├── Tips: 20%
│   │   ├── Unlocks: 20%
│   │   ├── Subscriptions: 15%
│   │   ├── Catalog purchases: 10%
│   │   └── Ad revenue share: 20%
│   ├── Payment processor markup %: 2.9% + $0.30
│   └── Preview impact button
│
├── Payout Configuration
│   ├── Minimum payout threshold: $50.00
│   ├── Payout processing fee: $0.00
│   ├── Payout schedule: weekly
│   └── Auto-payout enabled: true
│
├── Deposit Configuration
│   ├── Minimum deposit amount: $5.00
│   ├── Maximum deposit amount: $10,000.00
│   └── Deposit fee %: 0%
│
├── Currency Settings
│   ├── Default currency: USD
│   ├── Supported currencies: [USD, EUR, GBP]
│   └── Exchange rate source: manual / API
│
├── Tax Settings
│   ├── Tax collection enabled: false
│   ├── Default tax rate %: 0
│   └── Tax-exempt transaction types: []
│
├── Impact Preview
│   ├── Projected daily revenue change
│   ├── Affected transaction count
│   └── Sample transaction before/after comparison
│
└── Audit Log
    ├── All configuration changes
    ├── Who changed, when, old value → new value
    └── Searchable by field name and date
```

---

## 2. Current State Analysis

### 2.1 Current Configuration Source

Billing parameters live in `app/core/settings.py` as fields on the `Settings` dataclass, populated from environment variables:

```python
class Settings:
    platform_fee_bps: int = int(os.environ.get("PLATFORM_FEE_BPS", "2000"))  # 20%
    min_payout_cents: int = int(os.environ.get("MIN_PAYOUT_CENTS", "5000"))   # $50
    min_deposit_cents: int = int(os.environ.get("MIN_DEPOSIT_CENTS", "500"))   # $5
    ...
```

These values are read at startup and remain constant until the process is restarted.

### 2.2 Where Fees Are Applied

- `app/services/billing_shared.py`: `new_ledger_entry` uses fee rates for commission calculation
- `app/services/creator_payouts.py`: `request_payout` checks minimum payout threshold
- `app/routers/billing.py`: Deposit endpoints check minimum deposit amount

### 2.3 Gaps

1. No DynamoDB storage for billing configuration (only env vars)
2. No runtime update mechanism (requires restart)
3. No audit log of configuration changes
4. No impact preview for proposed changes
5. No admin UI for billing configuration
6. No per-transaction-type fee configuration

---

## 3. Technical Design

### 3.1 Billing Config Table: `billing_config`

**Table definition** in `scripts/local-ddb-init.py`:

```python
TableDef(
    name="billing_config",
    pk="pk", sk="sk",
    gsis=[],
)
```

**Current configuration row** (single item, always overwritten):

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `BILLING_CONFIG` |
| `sk` | S | `CURRENT` |
| `fee_tips_bps` | N | Fee for tips in basis points (2000 = 20%) |
| `fee_unlocks_bps` | N | Fee for unlock purchases |
| `fee_subscriptions_bps` | N | Fee for subscription charges |
| `fee_catalog_bps` | N | Fee for catalog purchases |
| `fee_ad_revenue_bps` | N | Fee for ad revenue share |
| `min_payout_cents` | N | Minimum payout threshold |
| `payout_fee_cents` | N | Per-payout processing fee |
| `payout_schedule` | S | `"daily"`, `"weekly"`, `"monthly"` |
| `auto_payout_enabled` | BOOL | Auto-payout on schedule |
| `min_deposit_cents` | N | Minimum deposit amount |
| `max_deposit_cents` | N | Maximum deposit amount |
| `deposit_fee_bps` | N | Deposit fee percentage |
| `default_currency` | S | Default currency code |
| `supported_currencies` | L | List of supported currency codes |
| `tax_enabled` | BOOL | Whether tax collection is enabled |
| `default_tax_rate_bps` | N | Default tax rate in basis points |
| `updated_at` | N | Last update timestamp |
| `updated_by` | S | Admin who last updated |

**Audit log rows** (one per change):

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `BILLING_CONFIG` |
| `sk` | S | `AUDIT#{timestamp}#{event_id}` |
| `admin_sub` | S | Admin who made the change |
| `changes` | L | List of {field, old_value, new_value} |
| `created_at` | N | Unix timestamp |

### 3.2 DynamoDB Access Patterns

| Access Pattern | Table/GSI | PK | SK / Filter | Example |
|---|---|---|---|---|
| Get current config | Main table | `BILLING_CONFIG` | `sk = "CURRENT"` | Read all current settings |
| Update current config | Main table | `BILLING_CONFIG` | `sk = "CURRENT"` | Overwrite with new values |
| List audit log (newest first) | Main table | `BILLING_CONFIG` | `begins_with(sk, "AUDIT#")`, ScanIndexForward=False | Last N config changes |
| Audit log in date range | Main table | `BILLING_CONFIG` | `sk BETWEEN "AUDIT#:start" AND "AUDIT#:end"` | Changes in time window |

**Example DynamoDB Items (JSON)**:

Current config:
```json
{
  "pk": {"S": "BILLING_CONFIG"},
  "sk": {"S": "CURRENT"},
  "fee_tips_bps": {"N": "2000"},
  "fee_unlocks_bps": {"N": "2000"},
  "fee_subscriptions_bps": {"N": "1500"},
  "fee_catalog_bps": {"N": "1000"},
  "fee_ad_revenue_bps": {"N": "2000"},
  "min_payout_cents": {"N": "5000"},
  "payout_fee_cents": {"N": "0"},
  "payout_schedule": {"S": "weekly"},
  "auto_payout_enabled": {"BOOL": true},
  "min_deposit_cents": {"N": "500"},
  "max_deposit_cents": {"N": "1000000"},
  "deposit_fee_bps": {"N": "0"},
  "default_currency": {"S": "USD"},
  "supported_currencies": {"L": [{"S": "USD"}, {"S": "EUR"}, {"S": "GBP"}]},
  "tax_enabled": {"BOOL": false},
  "default_tax_rate_bps": {"N": "0"},
  "updated_at": {"N": "1748520600"},
  "updated_by": {"S": "root.admin@testdev.local"}
}
```

Audit log entry:
```json
{
  "pk": {"S": "BILLING_CONFIG"},
  "sk": {"S": "AUDIT#1748520600#evt_a1b2c3d4"},
  "admin_sub": {"S": "root.admin@testdev.local"},
  "changes": {"L": [
    {"M": {
      "field": {"S": "fee_tips_bps"},
      "old_value": {"N": "2000"},
      "new_value": {"N": "1500"}
    }},
    {"M": {
      "field": {"S": "min_payout_cents"},
      "old_value": {"N": "5000"},
      "new_value": {"N": "2500"}
    }}
  ]},
  "created_at": {"N": "1748520600"}
}
```

### 3.3 Billing Config Service: `app/services/billing_config.py`

```python
"""Billing configuration management (FIN-018).

Stores and retrieves billing parameters from DynamoDB,
replacing env-var-based configuration for runtime updates.
"""

from __future__ import annotations
import logging
import uuid
from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from app.core.tables import T
from app.core.time import now_ts
from app.core.settings import S
from app.core.cursor import encode_cursor, decode_cursor

logger = logging.getLogger("billing_config")

# In-memory cache with TTL
_config_cache: Optional[Dict[str, Any]] = None
_cache_ts: int = 0
CACHE_TTL_SECONDS = 60

# Default values (from env vars as fallback)
_DEFAULTS = {
    "fee_tips_bps": 2000,
    "fee_unlocks_bps": 2000,
    "fee_subscriptions_bps": 1500,
    "fee_catalog_bps": 1000,
    "fee_ad_revenue_bps": 2000,
    "min_payout_cents": 5000,
    "payout_fee_cents": 0,
    "payout_schedule": "weekly",
    "auto_payout_enabled": True,
    "min_deposit_cents": 500,
    "max_deposit_cents": 1000000,
    "deposit_fee_bps": 0,
    "default_currency": "USD",
    "supported_currencies": ["USD", "EUR", "GBP"],
    "tax_enabled": False,
    "default_tax_rate_bps": 0,
}


def get_billing_config() -> Dict[str, Any]:
    """Get current billing configuration.

    Uses in-memory cache with 60-second TTL to avoid DDB reads
    on every transaction. Falls back to defaults if no DDB config exists.
    """
    global _config_cache, _cache_ts
    now = now_ts()

    if _config_cache is not None and (now - _cache_ts) < CACHE_TTL_SECONDS:
        return _config_cache

    resp = T.billing_config.get_item(
        Key={"pk": "BILLING_CONFIG", "sk": "CURRENT"},
    )
    item = resp.get("Item")

    if not item:
        _config_cache = dict(_DEFAULTS)
        _cache_ts = now
        return _config_cache

    config = {}
    for key, default in _DEFAULTS.items():
        val = item.get(key, default)
        if isinstance(val, Decimal):
            config[key] = int(val)
        elif isinstance(val, bool):
            config[key] = val
        elif isinstance(val, list):
            config[key] = [str(v) for v in val]
        else:
            config[key] = val

    config["updated_at"] = int(item["updated_at"]) if item.get("updated_at") else None
    config["updated_by"] = item.get("updated_by")

    _config_cache = config
    _cache_ts = now
    return config


def update_billing_config(*, admin_sub: str, **updates) -> Dict[str, Any]:
    """Update billing configuration.

    Writes new values to DDB, logs audit entry with old/new values,
    invalidates in-memory cache.
    """
    global _config_cache, _cache_ts
    now = now_ts()

    current = get_billing_config()
    changes = []

    for field, new_value in updates.items():
        if new_value is None:
            continue
        old_value = current.get(field)
        if old_value != new_value:
            changes.append({
                "field": field,
                "old_value": old_value,
                "new_value": new_value,
            })
            current[field] = new_value

    if not changes:
        return current  # No actual changes

    current["updated_at"] = now
    current["updated_by"] = admin_sub

    # Write updated config
    ddb_item = {"pk": "BILLING_CONFIG", "sk": "CURRENT"}
    for k, v in current.items():
        if isinstance(v, (int, float)):
            ddb_item[k] = Decimal(str(v))
        elif isinstance(v, bool):
            ddb_item[k] = v
        elif isinstance(v, list):
            ddb_item[k] = v
        elif v is not None:
            ddb_item[k] = str(v)

    T.billing_config.put_item(Item=ddb_item)

    # Write audit entry
    event_id = f"evt_{uuid.uuid4().hex[:8]}"
    audit_changes = []
    for c in changes:
        change_map = {"field": c["field"]}
        old_v = c["old_value"]
        new_v = c["new_value"]
        change_map["old_value"] = Decimal(str(old_v)) if isinstance(old_v, (int, float)) else str(old_v) if old_v is not None else "null"
        change_map["new_value"] = Decimal(str(new_v)) if isinstance(new_v, (int, float)) else str(new_v) if new_v is not None else "null"
        audit_changes.append(change_map)

    T.billing_config.put_item(Item={
        "pk": "BILLING_CONFIG",
        "sk": f"AUDIT#{now}#{event_id}",
        "admin_sub": admin_sub,
        "changes": audit_changes,
        "created_at": Decimal(str(now)),
    })

    # Invalidate cache
    _config_cache = None
    _cache_ts = 0

    logger.info("billing_config_updated", extra={
        "admin": admin_sub,
        "changes": [{"field": c["field"], "old": c["old_value"], "new": c["new_value"]} for c in changes],
    })

    return current


def get_fee_bps(entry_type: str) -> int:
    """Get platform fee in basis points for a transaction type.

    Used by billing_shared.py to compute commission.
    """
    config = get_billing_config()
    fee_map = {
        "tip_debit": config.get("fee_tips_bps", 2000),
        "tip_credit": config.get("fee_tips_bps", 2000),
        "unlock_debit": config.get("fee_unlocks_bps", 2000),
        "subscription_charge": config.get("fee_subscriptions_bps", 1500),
        "catalog_purchase": config.get("fee_catalog_bps", 1000),
        "ad_revenue": config.get("fee_ad_revenue_bps", 2000),
    }
    return fee_map.get(entry_type, 2000)


def get_min_payout_cents() -> int:
    """Get minimum payout threshold."""
    return get_billing_config().get("min_payout_cents", 5000)


def get_min_deposit_cents() -> int:
    """Get minimum deposit amount."""
    return get_billing_config().get("min_deposit_cents", 500)


def get_max_deposit_cents() -> int:
    """Get maximum deposit amount."""
    return get_billing_config().get("max_deposit_cents", 1000000)


def get_audit_log(*, limit: int = 50, cursor: str = None) -> Dict[str, Any]:
    """Get billing configuration change audit log."""
    kwargs = {
        "KeyConditionExpression": Key("pk").eq("BILLING_CONFIG")
        & Key("sk").begins_with("AUDIT#"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    resp = T.billing_config.query(**kwargs)
    items = resp.get("Items", [])
    next_cursor = None
    if "LastEvaluatedKey" in resp:
        next_cursor = encode_cursor(resp["LastEvaluatedKey"])

    entries = []
    for item in items:
        changes_raw = item.get("changes", [])
        changes = []
        for c in changes_raw:
            changes.append({
                "field": c.get("field", ""),
                "old_value": _deserialize_value(c.get("old_value")),
                "new_value": _deserialize_value(c.get("new_value")),
            })
        entries.append({
            "admin_sub": item.get("admin_sub", ""),
            "changes": changes,
            "created_at": int(item.get("created_at", 0)),
        })

    return {"entries": entries, "count": len(entries), "cursor": next_cursor}


def preview_impact(*, proposed_changes: Dict[str, Any]) -> Dict[str, Any]:
    """Preview impact of proposed configuration changes.

    Computes projected daily revenue delta based on recent
    transaction volume and proposed fee changes.
    """
    current = get_billing_config()

    # Determine which fee fields changed
    fee_fields = {
        "fee_tips_bps": "tip_debit",
        "fee_unlocks_bps": "unlock_debit",
        "fee_subscriptions_bps": "subscription_charge",
        "fee_catalog_bps": "catalog_purchase",
        "fee_ad_revenue_bps": "ad_revenue",
    }

    affected_types = []
    daily_delta_cents = 0

    for field, tx_type in fee_fields.items():
        new_val = proposed_changes.get(field)
        if new_val is None:
            continue
        old_val = current.get(field, 2000)
        if new_val == old_val:
            continue

        affected_types.append(tx_type)
        # Query recent daily average for this tx type
        avg_daily_amount = _get_avg_daily_amount(tx_type, days=7)
        delta_bps = new_val - old_val
        daily_delta_cents += int(avg_daily_amount * delta_bps / 10000)

    # Build sample before/after
    sample_amount = 1000  # $10.00 tip
    old_fee = int(sample_amount * current.get("fee_tips_bps", 2000) / 10000)
    new_fee_bps = proposed_changes.get("fee_tips_bps", current.get("fee_tips_bps", 2000))
    new_fee = int(sample_amount * new_fee_bps / 10000)

    return {
        "affected_tx_types": affected_types,
        "projected_daily_delta_cents": daily_delta_cents,
        "sample_before": {
            "amount_cents": sample_amount,
            "fee_cents": old_fee,
            "net_cents": sample_amount - old_fee,
        },
        "sample_after": {
            "amount_cents": sample_amount,
            "fee_cents": new_fee,
            "net_cents": sample_amount - new_fee,
        },
    }


def _get_avg_daily_amount(tx_type: str, days: int = 7) -> int:
    """Get average daily transaction amount for a type over last N days."""
    # Query billing ledger for recent volume
    # Implementation queries GSI_LEDGER_DATE for last 7 days, sums amounts
    # Returns daily average
    return 0  # Stub — production computes from billing ledger


def _deserialize_value(val):
    if isinstance(val, Decimal):
        return int(val)
    return val
```

### 3.4 Integration with Billing System

Replace hardcoded fee lookups with `billing_config.get_fee_bps(entry_type)`:

```python
# Before (in billing_shared.py or equivalent):
commission_bps = S.platform_fee_bps  # from env var

# After:
from app.services.billing_config import get_fee_bps
commission_bps = get_fee_bps(entry_type)
```

Similarly for `get_min_payout_cents()`, `get_min_deposit_cents()`, etc.

### 3.5 Router: `app/routers/admin_billing_config.py`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/admin/billing-config` | `require_admin_session` | Get current config |
| PATCH | `/v1/admin/billing-config` | `require_root_session` | Update config |
| GET | `/v1/admin/billing-config/audit` | `require_admin_session` | Audit log |
| POST | `/v1/admin/billing-config/preview` | `require_admin_session` | Preview impact |

### 3.6 API Request/Response Examples

**GET /v1/admin/billing-config**

```bash
curl -s -X GET "http://localhost:8000/v1/admin/billing-config" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..."
```

Response `200 OK`:
```json
{
  "fee_tips_bps": 2000,
  "fee_unlocks_bps": 2000,
  "fee_subscriptions_bps": 1500,
  "fee_catalog_bps": 1000,
  "fee_ad_revenue_bps": 2000,
  "min_payout_cents": 5000,
  "payout_fee_cents": 0,
  "payout_schedule": "weekly",
  "auto_payout_enabled": true,
  "min_deposit_cents": 500,
  "max_deposit_cents": 1000000,
  "deposit_fee_bps": 0,
  "default_currency": "USD",
  "supported_currencies": ["USD", "EUR", "GBP"],
  "tax_enabled": false,
  "default_tax_rate_bps": 0,
  "updated_at": 1748520600,
  "updated_by": "root.admin@testdev.local"
}
```

**PATCH /v1/admin/billing-config**

```bash
curl -s -X PATCH "http://localhost:8000/v1/admin/billing-config" \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root_123" \
  -d '{
    "fee_tips_bps": 1500,
    "min_payout_cents": 2500,
    "auto_payout_enabled": false
  }'
```

Response `200 OK`:
```json
{
  "fee_tips_bps": 1500,
  "fee_unlocks_bps": 2000,
  "fee_subscriptions_bps": 1500,
  "fee_catalog_bps": 1000,
  "fee_ad_revenue_bps": 2000,
  "min_payout_cents": 2500,
  "payout_fee_cents": 0,
  "payout_schedule": "weekly",
  "auto_payout_enabled": false,
  "min_deposit_cents": 500,
  "max_deposit_cents": 1000000,
  "deposit_fee_bps": 0,
  "default_currency": "USD",
  "supported_currencies": ["USD", "EUR", "GBP"],
  "tax_enabled": false,
  "default_tax_rate_bps": 0,
  "updated_at": 1748520900,
  "updated_by": "root.admin@testdev.local"
}
```

**GET /v1/admin/billing-config/audit?limit=5**

```bash
curl -s -X GET "http://localhost:8000/v1/admin/billing-config/audit?limit=5" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..."
```

Response `200 OK`:
```json
{
  "entries": [
    {
      "admin_sub": "root.admin@testdev.local",
      "changes": [
        {"field": "fee_tips_bps", "old_value": 2000, "new_value": 1500},
        {"field": "min_payout_cents", "old_value": 5000, "new_value": 2500},
        {"field": "auto_payout_enabled", "old_value": "True", "new_value": "False"}
      ],
      "created_at": 1748520900
    }
  ],
  "count": 1,
  "cursor": null
}
```

**POST /v1/admin/billing-config/preview**

```bash
curl -s -X POST "http://localhost:8000/v1/admin/billing-config/preview" \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root_123" \
  -d '{"fee_tips_bps": 2500}'
```

Response `200 OK`:
```json
{
  "affected_tx_types": ["tip_debit"],
  "projected_daily_delta_cents": 1250,
  "sample_before": {
    "amount_cents": 1000,
    "fee_cents": 200,
    "net_cents": 800
  },
  "sample_after": {
    "amount_cents": 1000,
    "fee_cents": 250,
    "net_cents": 750
  }
}
```

### 3.7 Error Handling Matrix

| Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|---|---|---|---|
| Non-admin requests config | 403 | `forbidden` | "Admin role required" | Use admin session |
| Non-root updates config | 403 | `forbidden` | "Root role required" | Use root session |
| Negative fee value | 422 | `validation_error` | "fee_tips_bps must be >= 0" | Correct value |
| Fee exceeds 50% (5000 bps) | 422 | `validation_error` | "fee_tips_bps must be <= 5000" | Lower fee value |
| Invalid payout schedule | 422 | `validation_error` | "payout_schedule must be daily, weekly, or monthly" | Use valid schedule |
| Invalid currency code | 422 | `validation_error` | "default_currency must match ^[A-Z]{3}$" | Use 3-letter ISO currency |
| Tax rate exceeds 100% | 422 | `validation_error` | "default_tax_rate_bps must be <= 10000" | Lower tax rate |
| min_deposit > max_deposit | 400 | `invalid_range` | "min_deposit_cents cannot exceed max_deposit_cents" | Correct range |
| No config exists (first read) | 200 | N/A | Returns defaults from code | Normal on fresh system |
| DDB write fails | 500 | `internal_error` | "Configuration update failed" | Retry; check DDB |
| Audit log empty | 200 | N/A | Returns empty entries list | Normal if no changes made yet |
| No changes in update | 200 | N/A | Returns current config (no audit entry written) | By design |
| Preview with no fee changes | 200 | N/A | Returns empty affected_tx_types, zero delta | Informational |
| Cache stale after update | N/A | N/A | Cache invalidated on update; other workers refresh in 60s | Automatic |

### 3.8 Pydantic Models (`app/models.py`)

```python
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional


class BillingConfigOut(BaseModel):
    """Current billing configuration."""
    fee_tips_bps: int = Field(..., ge=0, le=5000, description="Platform fee for tips in basis points")
    fee_unlocks_bps: int = Field(..., ge=0, le=5000, description="Platform fee for unlocks")
    fee_subscriptions_bps: int = Field(..., ge=0, le=5000, description="Platform fee for subscriptions")
    fee_catalog_bps: int = Field(..., ge=0, le=5000, description="Platform fee for catalog purchases")
    fee_ad_revenue_bps: int = Field(..., ge=0, le=5000, description="Platform fee for ad revenue share")
    min_payout_cents: int = Field(..., ge=0, description="Minimum payout threshold in cents")
    payout_fee_cents: int = Field(..., ge=0, description="Per-payout processing fee in cents")
    payout_schedule: str = Field(..., description="Payout frequency: daily, weekly, or monthly")
    auto_payout_enabled: bool = Field(..., description="Whether auto-payout is enabled")
    min_deposit_cents: int = Field(..., ge=0, description="Minimum deposit amount in cents")
    max_deposit_cents: int = Field(..., ge=0, description="Maximum deposit amount in cents")
    deposit_fee_bps: int = Field(..., ge=0, le=5000, description="Deposit fee in basis points")
    default_currency: str = Field(..., description="Default currency (ISO 4217)")
    supported_currencies: List[str] = Field(..., description="List of supported currency codes")
    tax_enabled: bool = Field(..., description="Whether tax collection is active")
    default_tax_rate_bps: int = Field(..., ge=0, le=10000, description="Default tax rate in basis points")
    updated_at: Optional[int] = Field(None, description="Last update timestamp")
    updated_by: Optional[str] = Field(None, description="Admin who last updated")

    model_config = {"json_schema_extra": {"examples": [{
        "fee_tips_bps": 2000,
        "fee_unlocks_bps": 2000,
        "fee_subscriptions_bps": 1500,
        "fee_catalog_bps": 1000,
        "fee_ad_revenue_bps": 2000,
        "min_payout_cents": 5000,
        "payout_fee_cents": 0,
        "payout_schedule": "weekly",
        "auto_payout_enabled": True,
        "min_deposit_cents": 500,
        "max_deposit_cents": 1000000,
        "deposit_fee_bps": 0,
        "default_currency": "USD",
        "supported_currencies": ["USD", "EUR", "GBP"],
        "tax_enabled": False,
        "default_tax_rate_bps": 0,
    }]}}


class BillingConfigUpdate(BaseModel):
    """Partial update request for billing configuration."""
    fee_tips_bps: Optional[int] = Field(default=None, ge=0, le=5000)
    fee_unlocks_bps: Optional[int] = Field(default=None, ge=0, le=5000)
    fee_subscriptions_bps: Optional[int] = Field(default=None, ge=0, le=5000)
    fee_catalog_bps: Optional[int] = Field(default=None, ge=0, le=5000)
    fee_ad_revenue_bps: Optional[int] = Field(default=None, ge=0, le=5000)
    min_payout_cents: Optional[int] = Field(default=None, ge=0)
    payout_fee_cents: Optional[int] = Field(default=None, ge=0)
    payout_schedule: Optional[str] = Field(default=None, pattern=r"^(daily|weekly|monthly)$")
    auto_payout_enabled: Optional[bool] = None
    min_deposit_cents: Optional[int] = Field(default=None, ge=0)
    max_deposit_cents: Optional[int] = Field(default=None, ge=0)
    deposit_fee_bps: Optional[int] = Field(default=None, ge=0, le=5000)
    default_currency: Optional[str] = Field(default=None, pattern=r"^[A-Z]{3}$")
    supported_currencies: Optional[List[str]] = None
    tax_enabled: Optional[bool] = None
    default_tax_rate_bps: Optional[int] = Field(default=None, ge=0, le=10000)


class BillingConfigAuditEntry(BaseModel):
    """Single entry in the billing config audit log."""
    admin_sub: str = Field(..., description="Admin who made the change")
    changes: List[Dict[str, Any]] = Field(
        ..., description="List of field changes: [{field, old_value, new_value}]",
    )
    created_at: int = Field(..., description="Unix timestamp of the change")


class BillingConfigAuditLog(BaseModel):
    """Paginated audit log."""
    entries: List[BillingConfigAuditEntry]
    count: int
    cursor: Optional[str] = None


class BillingConfigPreview(BaseModel):
    """Impact preview for proposed config changes."""
    affected_tx_types: List[str] = Field(..., description="Transaction types affected by the changes")
    projected_daily_delta_cents: int = Field(
        ..., description="Projected daily revenue change in cents (positive = more revenue)",
    )
    sample_before: Dict[str, Any] = Field(
        ..., description="Sample $10 transaction with current fees",
    )
    sample_after: Dict[str, Any] = Field(
        ..., description="Same transaction with proposed fees",
    )
```

### 3.9 Frontend Component Tree

```
BillingConfigPage (route: /admin/billing-config)
├── PageHeader
│   ├── h1 "Billing Configuration"
│   ├── Badge ("Root Only — Changes are live immediately")
│   └── LastUpdatedInfo (props: { updatedAt: number, updatedBy: string })
├── Form (react-hook-form + zod, wraps all config sections)
│   ├── FeeConfigCard
│   │   ├── Card (shadcn)
│   │   ├── CardHeader ("Platform Fees")
│   │   ├── CardContent
│   │   │   └── Grid (2 columns)
│   │   │       ├── FeeInput (props: { label: string, field: string, value: number, suffix: "bps" })
│   │   │       │   ├── Label ("Tips")
│   │   │       │   ├── NumberInput (min=0, max=5000, step=100)
│   │   │       │   └── HelperText ("20.0%") — auto-computed from bps
│   │   │       ├── FeeInput ("Unlocks")
│   │   │       ├── FeeInput ("Subscriptions")
│   │   │       ├── FeeInput ("Catalog")
│   │   │       └── FeeInput ("Ad Revenue")
│   │   └── CardFooter — fee explanation text
│   ├── PayoutConfigCard
│   │   ├── Card (shadcn)
│   │   ├── CardHeader ("Payout Settings")
│   │   ├── CardContent
│   │   │   ├── CurrencyInput ("Min Payout", props: { cents: number })
│   │   │   │   └── Input with "$" prefix, converts cents to dollars
│   │   │   ├── CurrencyInput ("Payout Fee")
│   │   │   ├── Select ("Schedule", options: daily/weekly/monthly)
│   │   │   └── Switch ("Auto-payout Enabled")
│   │   └── CardFooter
│   ├── DepositConfigCard
│   │   ├── Card (shadcn)
│   │   ├── CardContent
│   │   │   ├── CurrencyInput ("Min Deposit")
│   │   │   ├── CurrencyInput ("Max Deposit")
│   │   │   └── FeeInput ("Deposit Fee")
│   │   └── CardFooter
│   ├── TaxConfigCard
│   │   ├── Card (shadcn)
│   │   ├── CardContent
│   │   │   ├── Switch ("Tax Collection Enabled")
│   │   │   └── FeeInput ("Default Tax Rate") — disabled if tax not enabled
│   │   └── CardFooter
│   └── ActionBar
│       ├── Button ("Preview Impact", variant="outline") → opens ImpactPreviewDialog
│       └── Button ("Save Changes", variant="default") — disabled if !isRoot or !isDirty
├── ImpactPreviewDialog (props: { open: boolean, preview: BillingConfigPreview | null, onConfirm: () => void })
│   ├── Dialog (shadcn)
│   ├── AffectedTypesList (badges for each affected tx type)
│   ├── DeltaIndicator (props: { deltaCents: number })
│   │   └── Arrow up/down + "$X.XX/day" + color (green for revenue increase, red for decrease)
│   ├── SampleComparison
│   │   ├── BeforeCard (amount, fee, net)
│   │   └── AfterCard (amount, fee, net) with diff highlighting
│   ├── Button ("Cancel")
│   └── Button ("Confirm & Save")
└── AuditLogSection
    ├── Card (shadcn)
    ├── CardHeader ("Change History")
    └── CardContent
        └── AuditLogTable (props: { entries: BillingConfigAuditEntry[], onLoadMore: () => void })
            ├── DataTable (shadcn)
            │   └── AuditRow
            │       ├── AdminBadge (admin_sub)
            │       ├── TimeAgo (created_at)
            │       └── ChangesList
            │           └── ChangeChip (field: "fee_tips_bps", old: "2000", new: "1500")
            │               ├── span.field-name ("Tips Fee")
            │               ├── span.old-value ("20.0%") — struck through
            │               └── span.new-value ("15.0%") — bold
            └── LoadMoreButton
```

### 3.10 Frontend API (`frontend/src/api/endpoints/adminBillingConfig.ts`)

```typescript
import client from "../client";
import type {
  BillingConfigOut,
  BillingConfigUpdate,
  BillingConfigAuditLog,
  BillingConfigPreview,
} from "../types";

export const getBillingConfig = () =>
  client.get<BillingConfigOut>("/v1/admin/billing-config");

export const updateBillingConfig = (data: BillingConfigUpdate) =>
  client.patch<BillingConfigOut>("/v1/admin/billing-config", data);

export const getBillingConfigAudit = (params?: { limit?: number; cursor?: string }) =>
  client.get<BillingConfigAuditLog>("/v1/admin/billing-config/audit", { params });

export const previewBillingConfigImpact = (data: BillingConfigUpdate) =>
  client.post<BillingConfigPreview>("/v1/admin/billing-config/preview", data);
```

---

## 4. Implementation Plan

### Phase 1: Backend Data Layer (Days 1-2)

1. **`scripts/local-ddb-init.py`**: Add `billing_config` table.
2. **`app/core/settings.py`**: Add `billing_config_table_name`.
3. **`app/core/tables.py`**: Add `billing_config` table handle.

### Phase 2: Backend Service (Days 2-4)

4. **`app/services/billing_config.py`**: New file. Config CRUD, caching, audit log, impact preview.
5. **Integration**: Replace env-var fee lookups in `billing_shared.py` and `creator_payouts.py` with `billing_config` calls.

### Phase 3: Backend Router (Days 4-5)

6. **`app/models.py`**: Add billing config Pydantic models.
7. **`app/routers/admin_billing_config.py`**: New router with 4 endpoints.
8. **`app/main.py`**: Register router with prefix `/v1/admin/billing-config`.

### Phase 4: Frontend (Days 5-7)

9. **`frontend/src/api/types.ts`**: Add TypeScript types.
10. **`frontend/src/api/endpoints/adminBillingConfig.ts`**: New file.
11. **`frontend/src/pages/admin/billingConfig/BillingConfigPage.tsx`**: New page.
12. **`frontend/src/App.tsx`**: Add `/admin/billing-config` route.
13. **`frontend/src/components/layout/Sidebar.tsx`**: Add "Billing Config" admin nav link.

### Phase 5: E2E Tests (Days 8-9)

14. **`frontend/e2e/admin-billing-config.spec.ts`**: 22 tests across 6 sections.

---

## 5. E2E Test Plan

**Test file**: `frontend/e2e/admin-billing-config.spec.ts`

**Setup (beforeAll)**:
- Inject auth for Root, Alice, Charlie (admin)
- Seed billing_config table with default configuration values

**Section 543: Config Read API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | `Admin retrieves billing config` | GET `/v1/admin/billing-config` as Root -> 200; has `fee_tips_bps`, `min_payout_cents`, `default_currency` |
| 2 | `Config has all expected fields` | Response includes all fee fields, payout fields, deposit fields, tax fields |
| 3 | `Config returns defaults if not yet set` | Delete config row, GET -> 200; returns code-level defaults |
| 4 | `Non-admin cannot read config` | GET as Alice -> 403 |

**Section 544: Config Update API (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 5 | `Root updates fee configuration` | PATCH `/v1/admin/billing-config` with `{fee_tips_bps: 1500}` as Root -> 200; re-GET shows `fee_tips_bps === 1500` |
| 6 | `Root updates payout threshold` | PATCH with `{min_payout_cents: 2500}` -> 200; re-GET confirms |
| 7 | `Root updates multiple fields atomically` | PATCH with `{fee_tips_bps: 1800, min_deposit_cents: 1000, tax_enabled: true}` -> 200; all three updated |
| 8 | `Non-root cannot update config` | PATCH as Charlie -> 403 |
| 9 | `Invalid fee value returns 422` | PATCH with `{fee_tips_bps: -100}` -> 422 |

**Section 545: Audit Log API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 10 | `Audit log records config change` | GET `/v1/admin/billing-config/audit` -> 200; array has entry with `admin_sub` matching Root |
| 11 | `Audit entry shows old and new values` | Entry's `changes[0]` has `field`, `old_value`, `new_value` |
| 12 | `Multiple changes logged separately` | After 2 updates, audit has >= 2 entries |
| 13 | `Audit log sorted by newest first` | First entry's `created_at >= second entry's created_at` |

**Section 546: Impact Preview API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 14 | `Preview shows affected transaction types` | POST `/v1/admin/billing-config/preview` with `{fee_tips_bps: 2500}` -> 200; `affected_tx_types` includes `"tip_debit"` |
| 15 | `Preview shows projected daily delta` | Response has `projected_daily_delta_cents` (integer) |
| 16 | `Preview shows before/after sample` | Response has `sample_before` and `sample_after` with `amount_cents`, `fee_cents`, `net_cents` |
| 17 | `Preview with no changes returns empty affected types` | POST with same values as current config -> 200; `affected_tx_types: []` |

**Section 547: Billing Config UI (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 18 | `Config page loads with fee cards` | Navigate to `/admin/billing-config` as Root; verify "Platform Fees" card with fee inputs |
| 19 | `Audit log section shows change history` | Verify "Change History" section with audit entries showing field changes |
| 20 | `Preview Impact button opens dialog` | Click "Preview Impact"; verify dialog with affected types and sample comparison |

**Section 548: Validation Edge Cases (2 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 21 | `Fee above 50% returns 422` | PATCH with `{fee_tips_bps: 6000}` -> 422 |
| 22 | `No-op update does not create audit entry` | PATCH with current values (no changes); GET audit; no new entry created |

---

## 6. Observability & Monitoring

### 6.1 Metrics

| Metric Name | Type | Labels | Description |
|---|---|---|---|
| `billing_config_read_total` | Counter | `source` (cache/ddb) | Config reads from cache vs DDB |
| `billing_config_update_total` | Counter | — | Configuration updates |
| `billing_config_cache_hit_ratio` | Gauge | — | Cache hit percentage (should be >95%) |
| `billing_config_preview_total` | Counter | — | Impact previews generated |
| `billing_config_fee_bps` | Gauge | `tx_type` | Current fee in basis points per type |
| `billing_config_audit_entries_total` | Counter | — | Audit log entries created |

### 6.2 Structured Log Events

```json
{
  "logger": "billing_config",
  "level": "INFO",
  "event": "billing_config_updated",
  "admin": "root.admin@testdev.local",
  "changes": [
    {"field": "fee_tips_bps", "old": 2000, "new": 1500},
    {"field": "min_payout_cents", "old": 5000, "new": 2500}
  ],
  "timestamp": 1748520900
}
```

```json
{
  "logger": "billing_config",
  "level": "DEBUG",
  "event": "config_cache_miss",
  "reason": "cache_expired",
  "cache_age_seconds": 65,
  "timestamp": 1748520965
}
```

### 6.3 Alerting Rules

| Alert | Condition | Severity | Action |
|---|---|---|---|
| Config change frequency | > 5 config changes in 1 hour | Warning | Unusual activity; verify admin intent |
| Cache miss rate elevated | Cache hit ratio < 80% for 5 minutes | Warning | Check DDB latency; consider increasing TTL |
| Fee set to zero | Any fee_*_bps updated to 0 | Info | Intentional (promo) or accidental? |
| Max fee applied | Any fee_*_bps set to 5000 (50%) | Warning | Extreme fee; verify admin intent |
| Config read failure | DDB read error in get_billing_config | Critical | Fallback to env vars; check DDB health |

---

## 7. Rollout Plan

### Phase 1: DDB Backend + Env Var Fallback (Week 1)

**Feature flag**: `BILLING_CONFIG_DDB_ENABLED=false`

- Deploy billing_config service with DDB table
- Service always returns env var defaults (DDB not read)
- Admin can read config via API (shows env var values)
- No updates allowed yet

### Phase 2: DDB Read + Write (Week 2)

**Feature flag**: `BILLING_CONFIG_DDB_ENABLED=true`

- Service reads from DDB; falls back to env vars if no DDB config
- ROOT can update config via API
- Audit logging active
- Fee lookups in billing_shared.py use `get_fee_bps()` instead of `S.platform_fee_bps`
- Monitor for any fee discrepancies

### Phase 3: Full UI + Impact Preview (Week 3)

- Frontend deployed with all sections
- Impact preview enabled
- Remove env var fallback documentation (DDB is source of truth)

### Feature Flags

| Flag | Default | Description |
|---|---|---|
| `BILLING_CONFIG_DDB_ENABLED` | `false` | Read config from DDB instead of env vars |
| `BILLING_CONFIG_CACHE_TTL` | `60` | In-memory cache TTL in seconds |
| `BILLING_CONFIG_IMPACT_PREVIEW_DAYS` | `7` | Days of transaction data for impact preview |

### Rollback Procedure

1. Set `BILLING_CONFIG_DDB_ENABLED=false` — immediately reverts to env var values
2. Fee lookups return `S.platform_fee_bps` from env vars
3. DDB config and audit log retained for analysis
4. Revert code if needed

---

## 8. Performance Considerations

### 8.1 Latency Targets

| Operation | Target | Notes |
|---|---|---|
| `get_billing_config()` (cache hit) | < 1ms | In-memory dict access |
| `get_billing_config()` (cache miss) | < 50ms | Single DDB get |
| `get_fee_bps()` | < 1ms | Cache hit + dict lookup |
| GET /billing-config | < 50ms | Single DDB get (or cache) |
| PATCH /billing-config | < 200ms | Read + write + audit entry |
| GET /billing-config/audit | < 200ms | Range query on single PK |
| POST /billing-config/preview | < 2s | Requires querying 7 days of billing ledger |

### 8.2 Cache Strategy

- **Primary cache**: Module-level `_config_cache` dict with `_cache_ts` timestamp.
- **TTL**: 60 seconds (configurable). After 60 seconds, next `get_billing_config()` call re-fetches from DDB.
- **Invalidation**: `update_billing_config()` sets `_config_cache = None` immediately. Other backend workers (if any) refresh within 60 seconds.
- **Cache miss cost**: Single DDB `get_item` call (~50ms). Acceptable since it happens at most once per 60 seconds per worker.
- **Hot path impact**: `get_fee_bps()` is called on every transaction. With cache hit, it adds <1ms overhead. Without caching, it would add ~50ms to every transaction — unacceptable.

### 8.3 DynamoDB Costs

| Operation | RCU/WCU | Notes |
|---|---|---|
| Read config (cache miss) | 0.5 RCU | Single item ~500 bytes |
| Write config update | 1 WCU | Overwrite single item |
| Write audit entry | 1 WCU | Single item |
| Read audit log (50 entries) | 2-5 RCU | Range query, ~200 bytes per entry |
| Impact preview (ledger query) | 10-100 RCU | Depends on 7-day transaction volume |

### 8.4 Single-Worker Constraint

In dev mode (single uvicorn worker), cache invalidation is instant — `update_billing_config()` clears the cache in the same process. In production with multiple workers, each worker independently refreshes its cache after TTL expiry. This means config changes may take up to 60 seconds to propagate to all workers. For critical changes (e.g., zero-fee promotions), consider lowering the TTL or implementing a pub/sub cache invalidation.

---

## 9. Security Considerations

### 9.1 Role-Based Access
- Read billing config and audit log: ADMIN role
- Update billing config: ROOT role (changes affect all transactions)
- Preview impact: ADMIN role (read-only projection)

### 9.2 Change Safety
- All changes recorded in immutable audit log with admin identity
- Impact preview required before saving (enforced in UI)
- In-memory cache ensures stale config cleared within 60 seconds
- Fee values capped at 50% (5000 bps) to prevent accidental extreme fees

### 9.3 Backward Compatibility
- If no DDB config exists, falls back to env var defaults
- New config values override env vars (DDB takes precedence)
- Config changes do not affect in-flight transactions (only new ones)

### 9.4 Cache Invalidation
- `update_billing_config` invalidates the in-memory cache immediately
- Other backend instances refresh cache within 60 seconds (cache TTL)
- For single-worker dev mode, invalidation is instant

---

## 10. Files to Create

| File | Purpose |
|------|---------|
| `app/services/billing_config.py` | Billing configuration service |
| `app/routers/admin_billing_config.py` | Admin billing config API (4 endpoints) |
| `frontend/src/api/endpoints/adminBillingConfig.ts` | API wrappers |
| `frontend/src/pages/admin/billingConfig/BillingConfigPage.tsx` | Config page |
| `frontend/e2e/admin-billing-config.spec.ts` | E2E tests (22 tests, sections 543-548) |

## 11. Files to Modify

| File | Change |
|------|--------|
| `app/models.py` | Add billing config Pydantic models |
| `app/main.py` | Register `admin_billing_config_router` |
| `app/core/settings.py` | Add `billing_config_table_name` |
| `app/core/tables.py` | Add `billing_config` table handle |
| `scripts/local-ddb-init.py` | Add `billing_config` table |
| `app/services/billing_shared.py` | Replace env var fee lookups with `billing_config.get_fee_bps()` |
| `app/services/creator_payouts.py` | Use `billing_config.get_min_payout_cents()` |
| `frontend/src/api/types.ts` | Add billing config TypeScript types |
| `frontend/src/App.tsx` | Add `/admin/billing-config` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Billing Config" admin nav link |

## 12. Acceptance Criteria

1. Billing config readable through admin API with all fee, payout, deposit, and tax fields
2. ROOT can update any config field; changes persisted to DDB and effective immediately
3. Non-root admins cannot update config (403)
4. Audit log records every change with admin identity, old value, and new value
5. Impact preview shows affected transaction types and projected revenue delta
6. Billing system uses DDB config values instead of env vars (with env var fallback)
7. In-memory cache invalidated on update with 60-second TTL for other instances
8. Invalid values rejected with 422 (negative fees, fees over 50%)
9. All 22 E2E tests pass in `frontend/e2e/admin-billing-config.spec.ts`
10. Config reads from cache add < 1ms overhead to transactions
11. Feature flags allow gradual migration from env vars to DDB config
