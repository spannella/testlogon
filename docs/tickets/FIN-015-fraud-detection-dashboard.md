# FIN-015: Fraud Detection Dashboard

**Status**: Implemented  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: High  
**Estimated effort**: 10-12 days  
**Dependencies**: Billing ledger (`app/services/billing_shared.py:217`), payment providers (`app/routers/billing.py` at `app/main.py:326`, `app/routers/billing_ccbill.py` at `app/main.py:314`), rate limiting (`app/services/rate_limit.py`), admin auth (`app/auth/policy.py:67` `require_admin_or_root`, `:63` `require_root`)

---

## 1. Overview & Motivation

### The Gap

The platform processes financial transactions (tips, unlocks, deposits, subscriptions, catalog purchases) but has no fraud detection system. There are no velocity checks, risk scoring, anomaly detection, or manual review queues. A malicious user can:

- Execute hundreds of small transactions in minutes (velocity abuse)
- Create a new account and immediately make large purchases (new account + high value)
- Use stolen payment methods across multiple accounts
- Perform chargebacks on legitimate transactions after consuming content
- Exploit locked-message unlocks with fraudulent payment methods

Without fraud detection, the platform absorbs losses from chargebacks, refund abuse, and payment fraud. These losses come directly from creator earnings and platform revenue.

### Why This Is Needed

1. **Velocity detection**: Legitimate users do not send 50 tips in 2 minutes. Abnormal transaction velocity is the strongest fraud signal — catching it automatically prevents most automated fraud.

2. **Risk scoring**: Assigning a 0-100 risk score per user based on behavioral signals (transaction patterns, account age, device fingerprint, geo anomalies) enables automated flagging without blocking legitimate users.

3. **Manual review queue**: Not all fraud is clear-cut. A review queue lets admins inspect flagged transactions, examine context, and make approve/block decisions before funds are released.

4. **User freeze**: When fraud is suspected, temporarily freezing a user's financial operations prevents further damage while the case is investigated.

5. **Chargeback management**: Tracking chargebacks per user reveals serial abusers. Users exceeding a chargeback threshold should be auto-flagged for review.

6. **Audit trail**: Every fraud case (flag, review, decision) must be recorded for compliance, dispute resolution, and pattern analysis.

### User Stories

- As a **platform admin**, I want transactions with abnormal velocity to be automatically flagged so I can review them before funds settle.
- As a **platform admin**, I want each user to have a risk score so I can prioritize high-risk accounts for review.
- As a **platform admin**, I want a review queue showing flagged transactions so I can approve or block them.
- As a **platform admin**, I want to freeze a user's financial operations pending investigation so I can prevent further fraud.
- As a **platform admin**, I want to see chargeback history per user so I can identify serial abusers.

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              FRAUD DETECTION SYSTEM                                 │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│   ┌──────────────┐    ┌────────────────────┐    ┌──────────────────────┐            │
│   │   Frontend    │    │   FastAPI Router    │    │   Fraud Rules        │            │
│   │ FraudDash-    │───>│  admin_fraud.py     │───>│   Engine             │            │
│   │  board.tsx    │    │  12 endpoints       │    │  fraud_rules.py      │            │
│   │              │<───│                    │<───│                      │            │
│   └──────────────┘    └────────┬───────────┘    └──────────┬───────────┘            │
│                                │                           │                        │
│                                v                           v                        │
│                     ┌──────────────────┐        ┌─────────────────────┐             │
│                     │ Fraud Management │        │  Billing Integration │             │
│                     │ Service           │        │  (billing.py hooks)  │             │
│                     │ fraud_mgmt.py     │        │                     │             │
│                     └────────┬─────────┘        └──────────┬──────────┘             │
│                              │                             │                        │
│              ┌───────────────┼──────────────┐              │                        │
│              v               v              v              v                        │
│   ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐              │
│   │ fraud_detect  │ │   billing    │ │    alerts     │ │  rate_limit  │              │
│   │ DDB Table     │ │  DDB Table   │ │  DDB Table    │ │  DDB Table   │              │
│   │              │ │  (ledger)    │ │  (notify)     │ │  (velocity)  │              │
│   └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘              │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘

Data Flow: Transaction → Fraud Check
═══════════════════════════════════════

  User sends tip/unlock/deposit request
       │
       v
  ┌──────────────────────────────────────────────────────────────────────┐
  │  Billing Router (billing.py / billing_ccbill.py)                     │
  │    1. Validate payment method                                        │
  │    2. ── Call evaluate_transaction() ──────────────────────────────> │
  │                                                                      │
  │    ┌──────────────────────────────────────────────────┐              │
  │    │  fraud_rules.evaluate_transaction()               │              │
  │    │    ├── velocity_check(user_id)                    │              │
  │    │    │     Query rate_limit table for tx count/1hr  │              │
  │    │    │     Compare against VELOCITY_MAX_TX_PER_HOUR │              │
  │    │    ├── large_amount_check(amount_cents)            │              │
  │    │    │     Compare against LARGE_TX_THRESHOLD        │              │
  │    │    ├── new_account_check(age_days, amount)         │              │
  │    │    │     age < 7d AND amount > NEW_ACCOUNT_HIGH    │              │
  │    │    ├── chargeback_check(user_id)                   │              │
  │    │    │     Query fraud_detection: RISK#USER# row     │              │
  │    │    │     Compare chargeback_count vs threshold     │              │
  │    │    └── compute_risk_score(user_id)                 │              │
  │    │          Aggregate component scores                │              │
  │    │          Return {score, flagged, action}           │              │
  │    └──────────────────────────────────────────────────┘              │
  │                                                                      │
  │    3. If action == "block" → return 402 "Payment declined"           │
  │    4. If action == "flag"  → proceed + create flag + case            │
  │    5. If action == "allow" → proceed normally                        │
  │    6. Process payment                                                │
  └──────────────────────────────────────────────────────────────────────┘
       │
       v
  Admin Review Queue receives flagged transaction
       │
       v
  ┌──────────────────────────────────────────────────────────────────────┐
  │  Admin actions on flagged transaction:                               │
  │    ├── "approve"     → clear flag, update score, allow settlement    │
  │    ├── "block"       → refund transaction, increment score           │
  │    ├── "investigate" → open/link fraud case, assign to admin         │
  │    └── "freeze"      → freeze user financial ops, create case        │
  └──────────────────────────────────────────────────────────────────────┘
```

### Architecture After This Change

```
Fraud Detection System
│
├── Real-Time Rule Engine
│   ├── Velocity check (N tx in M minutes)
│   ├── Large amount check (single tx > threshold)
│   ├── New account + high value check
│   ├── Multiple failed payments check
│   ├── Geographic anomaly check (IP country mismatch)
│   └── Chargeback rate check
│
├── Risk Score Engine
│   ├── Per-user score (0-100)
│   ├── Score components: velocity, amount, account_age, chargeback_rate, geo
│   ├── Auto-flag at threshold (e.g., score >= 70)
│   └── Score history over time
│
├── Admin Review Queue (/admin/fraud)
│   ├── Flagged transactions list
│   ├── User risk profile (score, history, tx patterns)
│   ├── Actions: approve, block, investigate, freeze user
│   └── Case notes + resolution history
│
├── User Financial Freeze
│   ├── Block all outgoing payments
│   ├── Block payouts
│   ├── Freeze notification to user
│   └── Unfreeze by admin
│
└── Fraud Case Management
    ├── Case lifecycle: open → investigating → resolved
    ├── Case assignment to admin
    ├── Case notes + evidence attachments
    └── Resolution: false_positive, confirmed_fraud, inconclusive
```

### Data Flow — Fraud Check on Transaction

```
User Transaction                  Fraud Engine                         Admin
      │                              │                                   │
      │── POST /tip ────────────────>│                                   │
      │                              │── run_fraud_rules(tx) ───>        │
      │                              │   velocity_check: PASS            │
      │                              │   amount_check: PASS              │
      │                              │   new_account_check: FAIL (3d)    │
      │                              │   score = 72 (>= 70 threshold)    │
      │                              │                                   │
      │                              │── flag_transaction(tx) ──────────>│
      │                              │── create_fraud_case() ──────────>│
      │<── 200 { ok: true,           │                                   │
      │    flagged: true }           │                  ┌────────────────│
      │                              │                  │ Admin reviews  │
      │                              │                  │ and approves   │
      │                              │                  └────────────────│
      │                              │<── resolve_case("false_positive")─│
      │                              │── clear_flag(tx) ─────────────────│
```

---

## 2. Current State Analysis

### 2.1 Billing Ledger (`app/services/billing_shared.py`)

All financial transactions are recorded as ledger entries (see `app/services/billing_shared.py:217` `new_ledger_entry`). <!-- NOTE: Ledger entries use field `type` not `entry_type`, and store `amount_cents`, `ts`, `state`, `reason` — there is no `user_id` or `created_at` field in the entry itself. The user is identified by the PK `USER#{user_id}`, and `ts` serves as the timestamp. --> The ledger provides the raw data source for velocity analysis.

### 2.2 Rate Limiting (`app/services/rate_limit.py`)

The rate limiter tracks request counts per IP/user but does not track financial transaction velocity. <!-- NOTE: There is no `check_rate_limit` function. The rate limiter uses `rate_limit_or_429(user_sub, factor)` at `:17` and specific wrapper functions like `rate_limit_login_attempt` at `:163`, `rate_limit_admin_action` at `:170`, etc. (see `app/services/rate_limit.py:17`). -->

### 2.3 Payment Providers

Payment failures (declined cards, insufficient funds) are returned as HTTP error responses but not tracked for fraud pattern analysis.

### 2.4 Gaps

1. No transaction velocity tracking or limits
2. No risk score computation per user
3. No automated fraud flagging rules
4. No admin review queue for flagged transactions
5. No user financial freeze mechanism
6. No chargeback tracking or thresholds
7. No fraud case management lifecycle
8. No fraud detection admin dashboard

---

## 3. Technical Design

### 3.1 Fraud Data Table: `fraud_detection`

**Table definition** in `scripts/local-ddb-init.py`:

```python
TableDef(
    name="fraud_detection",
    pk="pk", sk="sk",
    gsis=[
        GsiDef("GSI1", "GSI1PK", "GSI1SK"),
        GsiDef("GSI2", "GSI2PK", "GSI2SK"),
    ],
    attr_types={"GSI1SK": "N", "GSI2SK": "N"},
)
```

**Risk score row** (one per user):

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `RISK#USER#{user_id}` |
| `sk` | S | `SCORE` |
| `score` | N | Current risk score (0-100) |
| `components` | M | `{velocity: 15, amount: 10, account_age: 30, chargeback: 0, geo: 5}` |
| `flagged` | BOOL | Whether user is currently flagged |
| `frozen` | BOOL | Whether user's finances are frozen |
| `frozen_at` | N | When frozen (null if not frozen) |
| `frozen_by` | S | Admin who froze |
| `tx_count_24h` | N | Transaction count in last 24h |
| `tx_total_24h` | N | Transaction total in last 24h |
| `chargeback_count` | N | Lifetime chargeback count |
| `last_scored_at` | N | When score was last recomputed |

**Flagged transaction rows**:

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `FLAG#{flag_id}` |
| `sk` | S | `META` |
| `GSI1PK` | S | `FLAGS#PENDING` or `FLAGS#RESOLVED` |
| `GSI1SK` | N | `created_at` (Unix timestamp) |
| `GSI2PK` | S | `FLAGS#USER#{user_id}` |
| `GSI2SK` | N | `created_at` |
| `flag_id` | S | Unique flag ID |
| `user_id` | S | User who triggered the flag |
| `tx_id` | S | Ledger entry ID that triggered the flag |
| `rule_triggered` | S | Which rule fired (e.g., `velocity`, `amount`, `new_account`) |
| `risk_score` | N | User's risk score at time of flag |
| `amount_cents` | N | Transaction amount |
| `status` | S | `"pending"`, `"approved"`, `"blocked"`, `"investigating"` |
| `reviewed_by` | S | Admin who reviewed |
| `reviewed_at` | N | When reviewed |
| `resolution` | S | `"false_positive"`, `"confirmed_fraud"`, `"inconclusive"` |
| `notes` | S | Admin notes |
| `created_at` | N | When flagged |

**Fraud case rows**:

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `CASE#{case_id}` |
| `sk` | S | `META` |
| `GSI1PK` | S | `CASES#OPEN` or `CASES#CLOSED` |
| `GSI1SK` | N | `created_at` |
| `case_id` | S | Unique case ID |
| `user_id` | S | User under investigation |
| `status` | S | `"open"`, `"investigating"`, `"resolved"` |
| `assigned_to` | S | Admin handling the case |
| `flags` | L | List of flag_ids linked to this case |
| `resolution` | S | Resolution when closed |
| `notes` | S | Admin case notes |
| `created_at` | N | When case was opened |
| `resolved_at` | N | When case was resolved |

### 3.2 DynamoDB Access Patterns

| Access Pattern | Table/GSI | PK | SK / Filter | Example |
|---|---|---|---|---|
| Get user risk score | Main table | `RISK#USER#{user_id}` | `sk = "SCORE"` | Alice's current risk score |
| List all pending flags | GSI1 | `FLAGS#PENDING` | `GSI1SK BETWEEN :start AND :end` | Pending queue, newest first |
| List resolved flags | GSI1 | `FLAGS#RESOLVED` | `GSI1SK BETWEEN :start AND :end` | Resolved flags in date range |
| Get all flags for a user | GSI2 | `FLAGS#USER#{user_id}` | `GSI2SK BETWEEN :start AND :end` | Alice's flag history |
| Get a specific flag | Main table | `FLAG#{flag_id}` | `sk = "META"` | Single flag details |
| List open fraud cases | GSI1 | `CASES#OPEN` | `GSI1SK desc` | Admin case queue |
| List closed fraud cases | GSI1 | `CASES#CLOSED` | `GSI1SK BETWEEN :start AND :end` | Closed case archive |
| Get a specific case | Main table | `CASE#{case_id}` | `sk = "META"` | Single case details |
| List all frozen users | Main table | Scan with `frozen = true` | FilterExpression | Admin frozen users list (infrequent) |
| Get fraud config | Main table | `CONFIG` | `sk = "FRAUD_RULES"` | Current thresholds |
| Get score history | Main table | `RISK#USER#{user_id}` | `begins_with(sk, "HISTORY#")` | Score change timeline |

**Example DynamoDB Items (JSON)**:

Risk score row:
```json
{
  "pk": {"S": "RISK#USER#alice_sub_123"},
  "sk": {"S": "SCORE"},
  "score": {"N": "72"},
  "components": {"M": {
    "velocity": {"N": "15"},
    "amount": {"N": "10"},
    "account_age": {"N": "30"},
    "chargeback": {"N": "12"},
    "geo": {"N": "5"}
  }},
  "flagged": {"BOOL": true},
  "frozen": {"BOOL": false},
  "frozen_at": {"NULL": true},
  "frozen_by": {"NULL": true},
  "tx_count_24h": {"N": "47"},
  "tx_total_24h": {"N": "23400"},
  "chargeback_count": {"N": "2"},
  "last_scored_at": {"N": "1748520600"}
}
```

Flagged transaction row:
```json
{
  "pk": {"S": "FLAG#flg_a1b2c3d4"},
  "sk": {"S": "META"},
  "GSI1PK": {"S": "FLAGS#PENDING"},
  "GSI1SK": {"N": "1748520600"},
  "GSI2PK": {"S": "FLAGS#USER#alice_sub_123"},
  "GSI2SK": {"N": "1748520600"},
  "flag_id": {"S": "flg_a1b2c3d4"},
  "user_id": {"S": "alice_sub_123"},
  "tx_id": {"S": "led_9f3a2b1c"},
  "rule_triggered": {"S": "velocity"},
  "risk_score": {"N": "72"},
  "amount_cents": {"N": "500"},
  "status": {"S": "pending"},
  "reviewed_by": {"NULL": true},
  "reviewed_at": {"NULL": true},
  "resolution": {"NULL": true},
  "notes": {"S": ""},
  "created_at": {"N": "1748520600"}
}
```

Fraud case row:
```json
{
  "pk": {"S": "CASE#case_x1y2z3"},
  "sk": {"S": "META"},
  "GSI1PK": {"S": "CASES#OPEN"},
  "GSI1SK": {"N": "1748520700"},
  "case_id": {"S": "case_x1y2z3"},
  "user_id": {"S": "alice_sub_123"},
  "status": {"S": "investigating"},
  "assigned_to": {"S": "root.admin@testdev.local"},
  "flags": {"L": [{"S": "flg_a1b2c3d4"}, {"S": "flg_e5f6g7h8"}]},
  "resolution": {"NULL": true},
  "notes": {"S": "Multiple velocity violations in 24h period"},
  "created_at": {"N": "1748520700"},
  "resolved_at": {"NULL": true}
}
```

Fraud config row:
```json
{
  "pk": {"S": "CONFIG"},
  "sk": {"S": "FRAUD_RULES"},
  "velocity_max_tx_per_hour": {"N": "20"},
  "velocity_max_amount_per_hour": {"N": "50000"},
  "large_tx_threshold": {"N": "25000"},
  "new_account_age_days": {"N": "7"},
  "new_account_high_value": {"N": "10000"},
  "chargeback_threshold": {"N": "3"},
  "flag_score_threshold": {"N": "70"},
  "updated_at": {"N": "1748520000"},
  "updated_by": {"S": "root.admin@testdev.local"}
}
```

### 3.3 Fraud Rules Engine: `app/services/fraud_rules.py`

```python
"""Fraud detection rule engine (FIN-015).

Evaluates transactions against configurable rules.
Returns a risk assessment with triggered rules and score delta.
"""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional
from decimal import Decimal

from boto3.dynamodb.conditions import Key
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger("fraud_rules")

# Default thresholds (overridable via DDB config)
VELOCITY_MAX_TX_PER_HOUR = 20
VELOCITY_MAX_AMOUNT_PER_HOUR = 50000  # $500
LARGE_TX_THRESHOLD = 25000  # $250
NEW_ACCOUNT_AGE_DAYS = 7
NEW_ACCOUNT_HIGH_VALUE = 10000  # $100
CHARGEBACK_THRESHOLD = 3
FLAG_SCORE_THRESHOLD = 70

# Score component weights
_WEIGHTS = {
    "velocity": 25,       # max 25 pts
    "amount": 15,         # max 15 pts
    "account_age": 20,    # max 20 pts (decays as account ages)
    "chargeback": 30,     # max 30 pts
    "geo": 10,            # max 10 pts
}


def evaluate_transaction(
    *, user_id: str, amount_cents: int, entry_type: str,
    ip_address: str = None, account_age_days: int = 0,
) -> Dict[str, Any]:
    """Run all fraud rules against a transaction.

    Returns {
        "triggered_rules": [...],
        "risk_score": int,
        "flagged": bool,
        "action": "allow" | "flag" | "block"
    }
    """
    config = get_fraud_config()
    triggered = []

    v = velocity_check(user_id, config=config)
    if v:
        triggered.append(v)

    a = large_amount_check(amount_cents, config=config)
    if a:
        triggered.append(a)

    n = new_account_check(account_age_days, amount_cents, config=config)
    if n:
        triggered.append(n)

    c = chargeback_check(user_id, config=config)
    if c:
        triggered.append(c)

    # Recompute score with new data
    score_data = compute_risk_score(user_id)
    score = score_data["score"]
    threshold = config.get("flag_score_threshold", FLAG_SCORE_THRESHOLD)
    flagged = score >= threshold or len(triggered) > 0

    # Determine action
    if score >= 90 or len(triggered) >= 3:
        action = "block"
    elif flagged:
        action = "flag"
    else:
        action = "allow"

    logger.info(
        "fraud_evaluation",
        extra={
            "user_id": user_id,
            "amount_cents": amount_cents,
            "entry_type": entry_type,
            "score": score,
            "triggered_rules": [r["rule"] for r in triggered],
            "action": action,
        },
    )

    return {
        "triggered_rules": triggered,
        "risk_score": score,
        "flagged": flagged,
        "action": action,
    }


def velocity_check(user_id: str, *, config: dict = None) -> Optional[Dict[str, Any]]:
    """Check if user exceeded transaction velocity limits.

    Queries the billing ledger for transactions in the last hour.
    If count > VELOCITY_MAX_TX_PER_HOUR or total > VELOCITY_MAX_AMOUNT_PER_HOUR,
    returns a rule violation dict.
    """
    if config is None:
        config = get_fraud_config()
    max_tx = config.get("velocity_max_tx_per_hour", VELOCITY_MAX_TX_PER_HOUR)
    max_amount = config.get("velocity_max_amount_per_hour", VELOCITY_MAX_AMOUNT_PER_HOUR)

    now = now_ts()
    one_hour_ago = now - 3600

    # Query billing ledger for recent transactions
    resp = T.billing.query(
        KeyConditionExpression=Key("pk").eq(f"USER#{user_id}")
        & Key("sk").between(f"LEDGER#{one_hour_ago}", f"LEDGER#{now}~"),
    )
    items = resp.get("Items", [])
    tx_count = len(items)
    tx_total = sum(int(it.get("amount_cents", 0)) for it in items)

    if tx_count > max_tx:
        return {"rule": "velocity_count", "detail": f"{tx_count} tx in last hour (max {max_tx})"}
    if tx_total > max_amount:
        return {"rule": "velocity_amount", "detail": f"{tx_total}c in last hour (max {max_amount}c)"}
    return None


def large_amount_check(amount_cents: int, *, config: dict = None) -> Optional[Dict[str, Any]]:
    """Check if single transaction exceeds large amount threshold."""
    if config is None:
        config = get_fraud_config()
    threshold = config.get("large_tx_threshold", LARGE_TX_THRESHOLD)
    if amount_cents > threshold:
        return {"rule": "large_amount", "detail": f"{amount_cents}c exceeds threshold {threshold}c"}
    return None


def new_account_check(
    account_age_days: int, amount_cents: int, *, config: dict = None
) -> Optional[Dict[str, Any]]:
    """Check if new account is making high-value transaction."""
    if config is None:
        config = get_fraud_config()
    age_threshold = config.get("new_account_age_days", NEW_ACCOUNT_AGE_DAYS)
    value_threshold = config.get("new_account_high_value", NEW_ACCOUNT_HIGH_VALUE)
    if account_age_days < age_threshold and amount_cents > value_threshold:
        return {
            "rule": "new_account",
            "detail": f"Account {account_age_days}d old, tx {amount_cents}c (threshold: {age_threshold}d, {value_threshold}c)",
        }
    return None


def chargeback_check(user_id: str, *, config: dict = None) -> Optional[Dict[str, Any]]:
    """Check if user has excessive chargebacks."""
    if config is None:
        config = get_fraud_config()
    threshold = config.get("chargeback_threshold", CHARGEBACK_THRESHOLD)

    resp = T.fraud_detection.get_item(
        Key={"pk": f"RISK#USER#{user_id}", "sk": "SCORE"},
    )
    item = resp.get("Item")
    if not item:
        return None
    cb_count = int(item.get("chargeback_count", 0))
    if cb_count >= threshold:
        return {"rule": "chargeback_rate", "detail": f"{cb_count} chargebacks (threshold: {threshold})"}
    return None


def compute_risk_score(user_id: str) -> Dict[str, Any]:
    """Recompute the full risk score for a user.

    Component weights:
      - velocity: 0-25  (based on 24h tx velocity relative to limits)
      - amount:   0-15  (based on 24h total relative to limits)
      - account_age: 0-20 (higher for newer accounts, decays over 90 days)
      - chargeback: 0-30 (based on lifetime chargeback count)
      - geo: 0-10 (based on IP country mismatches — future)

    Returns {score, components, flagged}.
    """
    resp = T.fraud_detection.get_item(
        Key={"pk": f"RISK#USER#{user_id}", "sk": "SCORE"},
    )
    item = resp.get("Item", {})
    config = get_fraud_config()

    # Compute each component
    tx_24h = int(item.get("tx_count_24h", 0))
    max_tx = config.get("velocity_max_tx_per_hour", VELOCITY_MAX_TX_PER_HOUR) * 24
    velocity_score = min(25, int(25 * tx_24h / max(max_tx, 1)))

    tx_total = int(item.get("tx_total_24h", 0))
    max_amount = config.get("velocity_max_amount_per_hour", VELOCITY_MAX_AMOUNT_PER_HOUR) * 24
    amount_score = min(15, int(15 * tx_total / max(max_amount, 1)))

    # Account age component — passed as metadata, defaults to 0 if unknown
    age_score = 0  # Will be set during evaluation

    cb_count = int(item.get("chargeback_count", 0))
    cb_threshold = config.get("chargeback_threshold", CHARGEBACK_THRESHOLD)
    chargeback_score = min(30, int(30 * cb_count / max(cb_threshold, 1)))

    geo_score = int(item.get("components", {}).get("geo", 0))

    components = {
        "velocity": velocity_score,
        "amount": amount_score,
        "account_age": age_score,
        "chargeback": chargeback_score,
        "geo": geo_score,
    }
    total_score = min(100, sum(components.values()))
    flagged = total_score >= config.get("flag_score_threshold", FLAG_SCORE_THRESHOLD)

    # Persist updated score
    now = now_ts()
    T.fraud_detection.put_item(Item={
        "pk": f"RISK#USER#{user_id}",
        "sk": "SCORE",
        "score": Decimal(str(total_score)),
        "components": {k: Decimal(str(v)) for k, v in components.items()},
        "flagged": flagged,
        "frozen": item.get("frozen", False),
        "frozen_at": item.get("frozen_at"),
        "frozen_by": item.get("frozen_by"),
        "tx_count_24h": Decimal(str(tx_24h)),
        "tx_total_24h": Decimal(str(tx_total)),
        "chargeback_count": Decimal(str(cb_count)),
        "last_scored_at": Decimal(str(now)),
    })

    # Record score history point
    T.fraud_detection.put_item(Item={
        "pk": f"RISK#USER#{user_id}",
        "sk": f"HISTORY#{now}",
        "score": Decimal(str(total_score)),
        "components": {k: Decimal(str(v)) for k, v in components.items()},
        "created_at": Decimal(str(now)),
    })

    return {"score": total_score, "components": components, "flagged": flagged}


def get_fraud_config() -> Dict[str, Any]:
    """Get current fraud detection thresholds from DDB.

    Falls back to code-level defaults if no DDB config exists.
    """
    resp = T.fraud_detection.get_item(
        Key={"pk": "CONFIG", "sk": "FRAUD_RULES"},
    )
    item = resp.get("Item")
    if not item:
        return {
            "velocity_max_tx_per_hour": VELOCITY_MAX_TX_PER_HOUR,
            "velocity_max_amount_per_hour": VELOCITY_MAX_AMOUNT_PER_HOUR,
            "large_tx_threshold": LARGE_TX_THRESHOLD,
            "new_account_age_days": NEW_ACCOUNT_AGE_DAYS,
            "new_account_high_value": NEW_ACCOUNT_HIGH_VALUE,
            "chargeback_threshold": CHARGEBACK_THRESHOLD,
            "flag_score_threshold": FLAG_SCORE_THRESHOLD,
        }
    return {k: int(v) if isinstance(v, Decimal) else v for k, v in item.items() if k not in ("pk", "sk")}


def update_fraud_config(*, admin_sub: str, **thresholds) -> Dict[str, Any]:
    """Update fraud detection thresholds. Root-only."""
    now = now_ts()
    existing = get_fraud_config()
    existing.update({k: v for k, v in thresholds.items() if v is not None})
    existing["updated_at"] = now
    existing["updated_by"] = admin_sub

    T.fraud_detection.put_item(Item={
        "pk": "CONFIG",
        "sk": "FRAUD_RULES",
        **{k: Decimal(str(v)) if isinstance(v, (int, float)) else v for k, v in existing.items()},
    })
    return existing
```

### 3.4 Fraud Management Service: `app/services/fraud_management.py`

```python
"""Fraud case and flag management (FIN-015).

Handles the admin review queue, user freeze/unfreeze,
and fraud case lifecycle.
"""

from __future__ import annotations
import uuid
import logging
from typing import Any, Dict, List, Optional
from decimal import Decimal

from boto3.dynamodb.conditions import Key
from app.core.tables import T
from app.core.time import now_ts
from app.core.cursor import encode_cursor, decode_cursor  # (see app/core/cursor.py:83,92)
from app.services.alerts import write_alert  # (see app/services/alerts.py:355)

logger = logging.getLogger("fraud_management")


def create_flag(
    *, user_id: str, tx_id: str, rule_triggered: str,
    risk_score: int, amount_cents: int,
) -> Dict[str, Any]:
    """Create a flagged transaction entry."""
    flag_id = f"flg_{uuid.uuid4().hex[:8]}"
    now = now_ts()

    item = {
        "pk": f"FLAG#{flag_id}",
        "sk": "META",
        "GSI1PK": "FLAGS#PENDING",
        "GSI1SK": Decimal(str(now)),
        "GSI2PK": f"FLAGS#USER#{user_id}",
        "GSI2SK": Decimal(str(now)),
        "flag_id": flag_id,
        "user_id": user_id,
        "tx_id": tx_id,
        "rule_triggered": rule_triggered,
        "risk_score": Decimal(str(risk_score)),
        "amount_cents": Decimal(str(amount_cents)),
        "status": "pending",
        "notes": "",
        "created_at": Decimal(str(now)),
    }
    T.fraud_detection.put_item(Item=item)
    logger.info("flag_created", extra={"flag_id": flag_id, "user_id": user_id, "rule": rule_triggered})
    return {"flag_id": flag_id, "status": "pending", "created_at": now}


def list_flagged_transactions(
    *, status: str = "pending", limit: int = 50, cursor: str = None,
) -> Dict[str, Any]:
    """List flagged transactions for admin review queue."""
    gsi_pk = f"FLAGS#{status.upper()}"
    kwargs = {
        "IndexName": "GSI1",
        "KeyConditionExpression": Key("GSI1PK").eq(gsi_pk),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    resp = T.fraud_detection.query(**kwargs)
    items = resp.get("Items", [])
    next_cursor = None
    if "LastEvaluatedKey" in resp:
        next_cursor = encode_cursor(resp["LastEvaluatedKey"])

    return {
        "flags": [_flag_to_dict(it) for it in items],
        "count": len(items),
        "cursor": next_cursor,
    }


def review_flag(
    *, flag_id: str, action: str, admin_sub: str, notes: str = ""
) -> Dict[str, Any]:
    """Admin reviews a flagged transaction: approve, block, or investigate."""
    now = now_ts()
    resp = T.fraud_detection.get_item(Key={"pk": f"FLAG#{flag_id}", "sk": "META"})
    item = resp.get("Item")
    if not item:
        return None

    resolution_map = {"approve": "false_positive", "block": "confirmed_fraud", "investigate": None}
    resolution = resolution_map.get(action)
    new_status = "investigating" if action == "investigate" else ("approved" if action == "approve" else "blocked")
    new_gsi1pk = "FLAGS#RESOLVED" if action != "investigate" else "FLAGS#PENDING"

    T.fraud_detection.update_item(
        Key={"pk": f"FLAG#{flag_id}", "sk": "META"},
        UpdateExpression="SET #s = :s, reviewed_by = :rb, reviewed_at = :ra, resolution = :res, notes = :n, GSI1PK = :g1pk",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": new_status,
            ":rb": admin_sub,
            ":ra": Decimal(str(now)),
            ":res": resolution,
            ":n": notes,
            ":g1pk": new_gsi1pk,
        },
    )
    logger.info("flag_reviewed", extra={"flag_id": flag_id, "action": action, "admin": admin_sub})
    return {"flag_id": flag_id, "status": new_status, "resolution": resolution}


def freeze_user(
    *, user_id: str, admin_sub: str, reason: str
) -> Dict[str, Any]:
    """Freeze a user's financial operations."""
    now = now_ts()
    T.fraud_detection.update_item(
        Key={"pk": f"RISK#USER#{user_id}", "sk": "SCORE"},
        UpdateExpression="SET frozen = :t, frozen_at = :fa, frozen_by = :fb",
        ExpressionAttributeValues={
            ":t": True,
            ":fa": Decimal(str(now)),
            ":fb": admin_sub,
        },
    )
    write_alert(
        user_id,
        event="account.financial_freeze",
        outcome="warning",
        title="Financial operations temporarily suspended",
        details={"reason": "Account review in progress"},
    )
    logger.warning("user_frozen", extra={"user_id": user_id, "admin": admin_sub, "reason": reason})
    return {"user_id": user_id, "frozen": True, "frozen_at": now}


def unfreeze_user(
    *, user_id: str, admin_sub: str
) -> Dict[str, Any]:
    """Unfreeze a user's financial operations."""
    T.fraud_detection.update_item(
        Key={"pk": f"RISK#USER#{user_id}", "sk": "SCORE"},
        UpdateExpression="SET frozen = :f REMOVE frozen_at, frozen_by",
        ExpressionAttributeValues={":f": False},
    )
    write_alert(
        user_id,
        event="account.financial_unfreeze",
        outcome="info",
        title="Financial operations restored",
        details={},
    )
    logger.info("user_unfrozen", extra={"user_id": user_id, "admin": admin_sub})
    return {"user_id": user_id, "frozen": False}


def get_user_risk_profile(user_id: str) -> Dict[str, Any]:
    """Get full risk profile for a user (score, history, flags, cases)."""
    # Get current score
    resp = T.fraud_detection.get_item(Key={"pk": f"RISK#USER#{user_id}", "sk": "SCORE"})
    score_item = resp.get("Item", {})

    # Get recent flags
    flags_resp = T.fraud_detection.query(
        IndexName="GSI2",
        KeyConditionExpression=Key("GSI2PK").eq(f"FLAGS#USER#{user_id}"),
        ScanIndexForward=False,
        Limit=20,
    )
    flags = [_flag_to_dict(it) for it in flags_resp.get("Items", [])]

    return {
        "user_id": user_id,
        "score": int(score_item.get("score", 0)),
        "components": {k: int(v) for k, v in score_item.get("components", {}).items()},
        "flagged": score_item.get("flagged", False),
        "frozen": score_item.get("frozen", False),
        "frozen_at": int(score_item["frozen_at"]) if score_item.get("frozen_at") else None,
        "frozen_by": score_item.get("frozen_by"),
        "tx_count_24h": int(score_item.get("tx_count_24h", 0)),
        "tx_total_24h": int(score_item.get("tx_total_24h", 0)),
        "chargeback_count": int(score_item.get("chargeback_count", 0)),
        "last_scored_at": int(score_item.get("last_scored_at", 0)),
        "recent_flags": flags,
    }


def create_fraud_case(
    *, user_id: str, flag_ids: List[str], admin_sub: str, notes: str = ""
) -> Dict[str, Any]:
    """Open a new fraud investigation case."""
    case_id = f"case_{uuid.uuid4().hex[:8]}"
    now = now_ts()

    T.fraud_detection.put_item(Item={
        "pk": f"CASE#{case_id}",
        "sk": "META",
        "GSI1PK": "CASES#OPEN",
        "GSI1SK": Decimal(str(now)),
        "case_id": case_id,
        "user_id": user_id,
        "status": "open",
        "assigned_to": admin_sub,
        "flags": flag_ids,
        "notes": notes,
        "created_at": Decimal(str(now)),
    })
    logger.info("case_created", extra={"case_id": case_id, "user_id": user_id, "admin": admin_sub})
    return {"case_id": case_id, "status": "open", "created_at": now}


def resolve_fraud_case(
    *, case_id: str, resolution: str, admin_sub: str, notes: str = ""
) -> Dict[str, Any]:
    """Resolve a fraud case."""
    now = now_ts()
    T.fraud_detection.update_item(
        Key={"pk": f"CASE#{case_id}", "sk": "META"},
        UpdateExpression="SET #s = :s, resolution = :r, notes = :n, resolved_at = :ra, GSI1PK = :g1pk",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": "resolved",
            ":r": resolution,
            ":n": notes,
            ":ra": Decimal(str(now)),
            ":g1pk": "CASES#CLOSED",
        },
    )
    logger.info("case_resolved", extra={"case_id": case_id, "resolution": resolution, "admin": admin_sub})
    return {"case_id": case_id, "status": "resolved", "resolution": resolution, "resolved_at": now}


def list_fraud_cases(
    *, status: str = "open", limit: int = 50
) -> List[Dict[str, Any]]:
    """List fraud cases filtered by status."""
    gsi_pk = f"CASES#{status.upper()}"
    resp = T.fraud_detection.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(gsi_pk),
        ScanIndexForward=False,
        Limit=limit,
    )
    return [_case_to_dict(it) for it in resp.get("Items", [])]


def get_fraud_stats() -> Dict[str, Any]:
    """Dashboard statistics: pending flags, open cases, frozen users, resolution metrics."""
    # Count pending flags
    pending_resp = T.fraud_detection.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq("FLAGS#PENDING"),
        Select="COUNT",
    )
    pending_count = pending_resp.get("Count", 0)

    # Count open cases
    cases_resp = T.fraud_detection.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq("CASES#OPEN"),
        Select="COUNT",
    )
    open_cases = cases_resp.get("Count", 0)

    # Count resolved today
    today_start = now_ts() - (now_ts() % 86400)
    resolved_resp = T.fraud_detection.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq("FLAGS#RESOLVED")
        & Key("GSI1SK").gte(Decimal(str(today_start))),
        Select="COUNT",
    )
    resolved_today = resolved_resp.get("Count", 0)

    return {
        "pending_flags": pending_count,
        "open_cases": open_cases,
        "frozen_users": 0,  # Requires scan — use cached count in production
        "flags_resolved_today": resolved_today,
        "avg_resolution_hours": 0.0,  # Computed from resolved flags timestamps
    }


def _flag_to_dict(item: dict) -> dict:
    return {
        "flag_id": item["flag_id"],
        "user_id": item["user_id"],
        "tx_id": item.get("tx_id", ""),
        "rule_triggered": item.get("rule_triggered", ""),
        "risk_score": int(item.get("risk_score", 0)),
        "amount_cents": int(item.get("amount_cents", 0)),
        "status": item.get("status", "pending"),
        "reviewed_by": item.get("reviewed_by"),
        "reviewed_at": int(item["reviewed_at"]) if item.get("reviewed_at") else None,
        "resolution": item.get("resolution"),
        "notes": item.get("notes", ""),
        "created_at": int(item.get("created_at", 0)),
    }


def _case_to_dict(item: dict) -> dict:
    return {
        "case_id": item["case_id"],
        "user_id": item["user_id"],
        "status": item.get("status", "open"),
        "assigned_to": item.get("assigned_to"),
        "flags": item.get("flags", []),
        "resolution": item.get("resolution"),
        "notes": item.get("notes", ""),
        "created_at": int(item.get("created_at", 0)),
        "resolved_at": int(item["resolved_at"]) if item.get("resolved_at") else None,
    }
```

### 3.5 Router: `app/routers/admin_fraud.py`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/admin/fraud/queue` | `require_admin_or_root` | Flagged transaction queue |
| POST | `/v1/admin/fraud/flags/{flag_id}/review` | `require_admin_or_root` | Review flagged tx |
| GET | `/v1/admin/fraud/users/{user_id}/risk` | `require_admin_or_root` | User risk profile |
| POST | `/v1/admin/fraud/users/{user_id}/freeze` | `require_admin_or_root` | Freeze user |
| POST | `/v1/admin/fraud/users/{user_id}/unfreeze` | `require_admin_or_root` | Unfreeze user |
| POST | `/v1/admin/fraud/cases` | `require_admin_or_root` | Create fraud case |
| GET | `/v1/admin/fraud/cases` | `require_admin_or_root` | List fraud cases |
| GET | `/v1/admin/fraud/cases/{case_id}` | `require_admin_or_root` | Get case details |
| POST | `/v1/admin/fraud/cases/{case_id}/resolve` | `require_admin_or_root` | Resolve case |
| GET | `/v1/admin/fraud/config` | `require_admin_or_root` | Get fraud config |
| PATCH | `/v1/admin/fraud/config` | `require_root` | Update fraud config |
| GET | `/v1/admin/fraud/stats` | `require_admin_or_root` | Dashboard statistics |

### 3.6 API Request/Response Examples

**GET /v1/admin/fraud/queue?status=pending&limit=10**

```bash
curl -s -X GET "http://localhost:8000/v1/admin/fraud/queue?status=pending&limit=10" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root_123"
```

Response `200 OK`:
```json
{
  "flags": [
    {
      "flag_id": "flg_a1b2c3d4",
      "user_id": "alice_sub_123",
      "tx_id": "led_9f3a2b1c",
      "rule_triggered": "velocity_count",
      "risk_score": 72,
      "amount_cents": 500,
      "status": "pending",
      "reviewed_by": null,
      "reviewed_at": null,
      "resolution": null,
      "notes": "",
      "created_at": 1748520600
    },
    {
      "flag_id": "flg_e5f6g7h8",
      "user_id": "alice_sub_123",
      "tx_id": "led_2d3e4f5g",
      "rule_triggered": "new_account",
      "risk_score": 72,
      "amount_cents": 15000,
      "status": "pending",
      "reviewed_by": null,
      "reviewed_at": null,
      "resolution": null,
      "notes": "",
      "created_at": 1748520500
    }
  ],
  "count": 2,
  "cursor": null
}
```

**POST /v1/admin/fraud/flags/{flag_id}/review**

```bash
curl -s -X POST "http://localhost:8000/v1/admin/fraud/flags/flg_a1b2c3d4/review" \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root_123" \
  -d '{"action": "approve", "notes": "Legitimate high-volume creator"}'
```

Response `200 OK`:
```json
{
  "flag_id": "flg_a1b2c3d4",
  "status": "approved",
  "resolution": "false_positive"
}
```

**GET /v1/admin/fraud/users/{user_id}/risk**

```bash
curl -s -X GET "http://localhost:8000/v1/admin/fraud/users/alice_sub_123/risk" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..."
```

Response `200 OK`:
```json
{
  "user_id": "alice_sub_123",
  "score": 72,
  "components": {
    "velocity": 15,
    "amount": 10,
    "account_age": 30,
    "chargeback": 12,
    "geo": 5
  },
  "flagged": true,
  "frozen": false,
  "frozen_at": null,
  "frozen_by": null,
  "tx_count_24h": 47,
  "tx_total_24h": 23400,
  "chargeback_count": 2,
  "last_scored_at": 1748520600,
  "recent_flags": [
    {
      "flag_id": "flg_a1b2c3d4",
      "rule_triggered": "velocity_count",
      "amount_cents": 500,
      "status": "pending",
      "created_at": 1748520600
    }
  ]
}
```

**POST /v1/admin/fraud/users/{user_id}/freeze**

```bash
curl -s -X POST "http://localhost:8000/v1/admin/fraud/users/alice_sub_123/freeze" \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root_123" \
  -d '{"reason": "Multiple velocity violations in 24-hour period"}'
```

Response `200 OK`:
```json
{
  "user_id": "alice_sub_123",
  "frozen": true,
  "frozen_at": 1748520900
}
```

**POST /v1/admin/fraud/users/{user_id}/unfreeze**

```bash
curl -s -X POST "http://localhost:8000/v1/admin/fraud/users/alice_sub_123/unfreeze" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root_123"
```

Response `200 OK`:
```json
{
  "user_id": "alice_sub_123",
  "frozen": false
}
```

**POST /v1/admin/fraud/cases**

```bash
curl -s -X POST "http://localhost:8000/v1/admin/fraud/cases" \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root_123" \
  -d '{
    "user_id": "alice_sub_123",
    "flag_ids": ["flg_a1b2c3d4", "flg_e5f6g7h8"],
    "notes": "Velocity + new account flags within 1 hour"
  }'
```

Response `201 Created`:
```json
{
  "case_id": "case_x1y2z3",
  "status": "open",
  "created_at": 1748521000
}
```

**GET /v1/admin/fraud/cases?status=open**

```bash
curl -s -X GET "http://localhost:8000/v1/admin/fraud/cases?status=open" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..."
```

Response `200 OK`:
```json
[
  {
    "case_id": "case_x1y2z3",
    "user_id": "alice_sub_123",
    "status": "open",
    "assigned_to": "root.admin@testdev.local",
    "flags": ["flg_a1b2c3d4", "flg_e5f6g7h8"],
    "resolution": null,
    "notes": "Velocity + new account flags within 1 hour",
    "created_at": 1748521000,
    "resolved_at": null
  }
]
```

**GET /v1/admin/fraud/cases/{case_id}**

```bash
curl -s -X GET "http://localhost:8000/v1/admin/fraud/cases/case_x1y2z3" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..."
```

Response `200 OK`:
```json
{
  "case_id": "case_x1y2z3",
  "user_id": "alice_sub_123",
  "status": "open",
  "assigned_to": "root.admin@testdev.local",
  "flags": ["flg_a1b2c3d4", "flg_e5f6g7h8"],
  "resolution": null,
  "notes": "Velocity + new account flags within 1 hour",
  "created_at": 1748521000,
  "resolved_at": null
}
```

**POST /v1/admin/fraud/cases/{case_id}/resolve**

```bash
curl -s -X POST "http://localhost:8000/v1/admin/fraud/cases/case_x1y2z3/resolve" \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root_123" \
  -d '{"resolution": "false_positive", "notes": "Verified creator with high engagement"}'
```

Response `200 OK`:
```json
{
  "case_id": "case_x1y2z3",
  "status": "resolved",
  "resolution": "false_positive",
  "resolved_at": 1748521200
}
```

**GET /v1/admin/fraud/config**

```bash
curl -s -X GET "http://localhost:8000/v1/admin/fraud/config" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..."
```

Response `200 OK`:
```json
{
  "velocity_max_tx_per_hour": 20,
  "velocity_max_amount_per_hour": 50000,
  "large_tx_threshold": 25000,
  "new_account_age_days": 7,
  "new_account_high_value": 10000,
  "chargeback_threshold": 3,
  "flag_score_threshold": 70
}
```

**PATCH /v1/admin/fraud/config**

```bash
curl -s -X PATCH "http://localhost:8000/v1/admin/fraud/config" \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root_123" \
  -d '{"flag_score_threshold": 80, "velocity_max_tx_per_hour": 30}'
```

Response `200 OK`:
```json
{
  "velocity_max_tx_per_hour": 30,
  "velocity_max_amount_per_hour": 50000,
  "large_tx_threshold": 25000,
  "new_account_age_days": 7,
  "new_account_high_value": 10000,
  "chargeback_threshold": 3,
  "flag_score_threshold": 80,
  "updated_at": 1748521500,
  "updated_by": "root.admin@testdev.local"
}
```

**GET /v1/admin/fraud/stats**

```bash
curl -s -X GET "http://localhost:8000/v1/admin/fraud/stats" \
  -H "Cookie: ui_session=sess_root_abc; ui_csrf=csrf_root_123; ui_access_token=eyJ..."
```

Response `200 OK`:
```json
{
  "pending_flags": 12,
  "open_cases": 3,
  "frozen_users": 1,
  "flags_resolved_today": 8,
  "avg_resolution_hours": 4.2
}
```

### 3.7 Error Handling Matrix

| Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|---|---|---|---|
| Non-admin requests fraud queue | 403 | `forbidden` | "Admin role required" | Use admin session |
| Non-root updates fraud config | 403 | `forbidden` | "Root role required" | Use root session |
| Flag not found | 404 | `not_found` | "Flag {flag_id} not found" | Verify flag ID |
| Case not found | 404 | `not_found` | "Case {case_id} not found" | Verify case ID |
| Invalid review action | 422 | `validation_error` | "action must be approve, block, or investigate" | Correct the action value |
| Invalid resolution | 422 | `validation_error` | "resolution must be false_positive, confirmed_fraud, or inconclusive" | Correct the resolution value |
| Empty freeze reason | 422 | `validation_error` | "reason: ensure this value has at least 1 character" | Provide a reason string |
| Freeze reason too long (>500) | 422 | `validation_error` | "reason: ensure this value has at most 500 characters" | Shorten reason |
| Case notes too long (>2000) | 422 | `validation_error` | "notes: ensure this value has at most 2000 characters" | Shorten notes |
| Empty flag_ids list on case create | 422 | `validation_error` | "flag_ids: ensure this value has at least 1 item" | Provide at least one flag ID |
| Risk profile for unknown user | 200 | N/A | Returns zero-score defaults | Normal for users with no fraud history |
| Config threshold below minimum | 422 | `validation_error` | "velocity_max_tx_per_hour must be >= 1" | Adjust value |
| Config threshold above maximum | 422 | `validation_error` | "velocity_max_tx_per_hour must be <= 1000" | Adjust value |
| Transaction blocked by fraud rules | 402 | `payment_declined` | "Payment could not be processed" | User contacts support |
| Velocity check DDB throttled | 500 | `internal_error` | "Service temporarily unavailable" | Automatic retry; scale DDB capacity |
| Freeze already-frozen user | 200 | N/A | Returns current freeze state (idempotent) | No action needed |
| Unfreeze already-unfrozen user | 200 | N/A | Returns current unfreeze state (idempotent) | No action needed |
| Resolve already-resolved case | 409 | `conflict` | "Case already resolved" | Check case status first |

### 3.8 Pydantic Models (`app/models.py`)

```python
from pydantic import BaseModel, Field
from typing import Dict, List, Optional


class FraudFlagOut(BaseModel):
    """Response model for a flagged transaction."""
    flag_id: str = Field(..., description="Unique flag identifier", examples=["flg_a1b2c3d4"])
    user_id: str = Field(..., description="User who triggered the flag")
    tx_id: str = Field(..., description="Billing ledger entry ID that triggered the flag")
    rule_triggered: str = Field(
        ..., description="Which fraud rule fired",
        examples=["velocity_count", "velocity_amount", "large_amount", "new_account", "chargeback_rate"],
    )
    risk_score: int = Field(..., ge=0, le=100, description="User's risk score at time of flag")
    amount_cents: int = Field(..., ge=0, description="Transaction amount in cents")
    status: str = Field(
        ..., description="Current flag status",
        examples=["pending", "approved", "blocked", "investigating"],
    )
    reviewed_by: Optional[str] = Field(None, description="Admin who reviewed this flag")
    reviewed_at: Optional[int] = Field(None, description="Unix timestamp of review")
    resolution: Optional[str] = Field(
        None, description="Resolution outcome",
        examples=["false_positive", "confirmed_fraud", "inconclusive"],
    )
    notes: Optional[str] = Field(None, description="Admin notes")
    created_at: int = Field(..., description="Unix timestamp when flag was created")

    model_config = {"json_schema_extra": {"examples": [{
        "flag_id": "flg_a1b2c3d4",
        "user_id": "alice_sub_123",
        "tx_id": "led_9f3a2b1c",
        "rule_triggered": "velocity_count",
        "risk_score": 72,
        "amount_cents": 500,
        "status": "pending",
        "reviewed_by": None,
        "reviewed_at": None,
        "resolution": None,
        "notes": "",
        "created_at": 1748520600,
    }]}}


class FraudFlagReview(BaseModel):
    """Request model for reviewing a flagged transaction."""
    action: str = Field(
        ..., pattern=r"^(approve|block|investigate)$",
        description="Review action to take",
        examples=["approve", "block", "investigate"],
    )
    notes: str = Field(
        default="", max_length=1000,
        description="Optional admin notes about the review decision",
    )


class FraudFlagQueueOut(BaseModel):
    """Paginated list of flagged transactions."""
    flags: List[FraudFlagOut]
    count: int = Field(..., ge=0, description="Number of flags in this page")
    cursor: Optional[str] = Field(None, description="Pagination cursor for next page")


class UserRiskProfile(BaseModel):
    """Full risk profile for a user."""
    user_id: str
    score: int = Field(..., ge=0, le=100, description="Composite risk score (0-100)")
    components: Dict[str, int] = Field(
        ..., description="Score breakdown by component",
        examples=[{"velocity": 15, "amount": 10, "account_age": 30, "chargeback": 12, "geo": 5}],
    )
    flagged: bool = Field(..., description="Whether user is currently flagged for review")
    frozen: bool = Field(..., description="Whether user's financial operations are frozen")
    frozen_at: Optional[int] = Field(None, description="Unix timestamp when frozen (null if not frozen)")
    frozen_by: Optional[str] = Field(None, description="Admin who froze the user")
    tx_count_24h: int = Field(..., ge=0, description="Number of transactions in last 24 hours")
    tx_total_24h: int = Field(..., ge=0, description="Total transaction amount (cents) in last 24h")
    chargeback_count: int = Field(..., ge=0, description="Lifetime chargeback count")
    last_scored_at: int = Field(..., description="Unix timestamp of last score computation")
    recent_flags: Optional[List[FraudFlagOut]] = Field(
        None, description="Most recent flags for this user (up to 20)",
    )


class FreezeUserRequest(BaseModel):
    """Request model for freezing a user's financial operations."""
    reason: str = Field(
        ..., min_length=1, max_length=500,
        description="Reason for freezing the user",
        examples=["Multiple velocity violations in 24-hour period"],
    )


class FraudCaseCreate(BaseModel):
    """Request model for creating a fraud investigation case."""
    user_id: str = Field(..., description="User ID to investigate")
    flag_ids: List[str] = Field(
        ..., min_length=1,
        description="List of flag IDs to link to this case",
        examples=[["flg_a1b2c3d4", "flg_e5f6g7h8"]],
    )
    notes: str = Field(
        default="", max_length=2000,
        description="Initial case notes",
    )


class FraudCaseOut(BaseModel):
    """Response model for a fraud investigation case."""
    case_id: str = Field(..., description="Unique case identifier", examples=["case_x1y2z3"])
    user_id: str = Field(..., description="User under investigation")
    status: str = Field(
        ..., description="Case status",
        examples=["open", "investigating", "resolved"],
    )
    assigned_to: Optional[str] = Field(None, description="Admin assigned to the case")
    flags: List[str] = Field(..., description="List of linked flag IDs")
    resolution: Optional[str] = Field(
        None, description="Resolution outcome when closed",
        examples=["false_positive", "confirmed_fraud", "inconclusive"],
    )
    notes: Optional[str] = Field(None, description="Case notes")
    created_at: int = Field(..., description="Unix timestamp when case was opened")
    resolved_at: Optional[int] = Field(None, description="Unix timestamp when case was resolved")


class FraudCaseResolve(BaseModel):
    """Request model for resolving a fraud case."""
    resolution: str = Field(
        ..., pattern=r"^(false_positive|confirmed_fraud|inconclusive)$",
        description="Resolution outcome",
    )
    notes: str = Field(
        default="", max_length=2000,
        description="Resolution notes",
    )


class FraudConfigOut(BaseModel):
    """Response model for fraud detection configuration."""
    velocity_max_tx_per_hour: int = Field(..., ge=1, le=1000)
    velocity_max_amount_per_hour: int = Field(..., ge=1000)
    large_tx_threshold: int = Field(..., ge=1000)
    new_account_age_days: int = Field(..., ge=1, le=90)
    new_account_high_value: int = Field(..., ge=100)
    chargeback_threshold: int = Field(..., ge=1, le=100)
    flag_score_threshold: int = Field(..., ge=10, le=100)
    updated_at: Optional[int] = None
    updated_by: Optional[str] = None


class FraudConfigUpdate(BaseModel):
    """Request model for updating fraud detection thresholds."""
    velocity_max_tx_per_hour: Optional[int] = Field(default=None, ge=1, le=1000)
    velocity_max_amount_per_hour: Optional[int] = Field(default=None, ge=1000)
    large_tx_threshold: Optional[int] = Field(default=None, ge=1000)
    new_account_age_days: Optional[int] = Field(default=None, ge=1, le=90)
    new_account_high_value: Optional[int] = Field(default=None, ge=100)
    chargeback_threshold: Optional[int] = Field(default=None, ge=1, le=100)
    flag_score_threshold: Optional[int] = Field(default=None, ge=10, le=100)


class FraudStatsOut(BaseModel):
    """Response model for fraud dashboard statistics."""
    pending_flags: int = Field(..., ge=0, description="Number of flags awaiting review")
    open_cases: int = Field(..., ge=0, description="Number of open investigation cases")
    frozen_users: int = Field(..., ge=0, description="Number of currently frozen users")
    flags_resolved_today: int = Field(..., ge=0, description="Flags resolved since midnight UTC")
    avg_resolution_hours: float = Field(
        ..., ge=0, description="Average time from flag creation to resolution (hours)",
    )
```

### 3.9 Frontend: Fraud Detection Dashboard

**Route**: `/admin/fraud` in `frontend/src/App.tsx`  
**Page**: `frontend/src/pages/admin/fraud/FraudDashboard.tsx`

Tabbed layout:
- **Queue**: Flagged transactions table with risk score badge, approve/block/investigate actions
- **Cases**: Fraud case list with status, assignment, linked flags
- **Users**: User risk search — enter user ID, view risk profile, freeze/unfreeze
- **Config**: Fraud rule thresholds form
- **Stats**: KPI cards (pending flags, open cases, frozen users, avg resolution time)

### 3.10 Frontend Component Tree

```
FraudDashboard (route: /admin/fraud)
├── FraudStatsBar
│   ├── StatCard (props: { label: string, value: number | string, icon: LucideIcon, variant: "default" | "warning" | "danger" })
│   │   ├── Card (shadcn)
│   │   └── Badge (count)
│   ├── StatCard ("Pending Flags")
│   ├── StatCard ("Open Cases")
│   ├── StatCard ("Frozen Users")
│   └── StatCard ("Avg Resolution Time")
├── Tabs (shadcn)
│   ├── TabPanel: "Queue"
│   │   └── FlagQueue (props: { onReview: (flagId: string, action: string) => void })
│   │       ├── StatusFilter (props: { value: string, onChange: (v: string) => void })
│   │       │   └── Select (shadcn) — pending | approved | blocked | investigating
│   │       ├── DataTable (shadcn)
│   │       │   └── FlagRow
│   │       │       ├── RiskScoreBadge (props: { score: number }) — color-coded: green <40, yellow 40-69, red >=70
│   │       │       ├── RuleChip (props: { rule: string }) — e.g., "velocity_count" → "Velocity"
│   │       │       ├── AmountCell (props: { cents: number }) — formatted as $X.XX
│   │       │       ├── TimeAgo (props: { timestamp: number })
│   │       │       └── ActionButtons
│   │       │           ├── Button ("Approve") — variant="outline", color="green"
│   │       │           ├── Button ("Block") — variant="destructive"
│   │       │           └── Button ("Investigate") — variant="secondary"
│   │       └── ReviewDialog (props: { flag: FraudFlagOut, open: boolean, onConfirm: (action, notes) => void })
│   │           ├── Dialog (shadcn)
│   │           ├── Textarea (notes)
│   │           └── Button ("Confirm")
│   ├── TabPanel: "Cases"
│   │   └── CaseList (props: { onResolve: (caseId: string) => void })
│   │       ├── StatusFilter (reused) — open | investigating | resolved
│   │       ├── DataTable (shadcn)
│   │       │   └── CaseRow
│   │       │       ├── StatusBadge (props: { status: string })
│   │       │       ├── FlagCount (props: { count: number })
│   │       │       ├── AssignedTo (props: { admin: string | null })
│   │       │       └── Button ("View" → navigate to case detail)
│   │       └── CaseDetailDialog (props: { case: FraudCaseOut, flags: FraudFlagOut[] })
│   │           ├── Dialog (shadcn)
│   │           ├── linked flags list
│   │           ├── Textarea (resolution notes)
│   │           └── ResolveButtons — false_positive | confirmed_fraud | inconclusive
│   ├── TabPanel: "Users"
│   │   └── UserRiskSearch (props: { onFreeze: (userId: string, reason: string) => void })
│   │       ├── SearchInput (props: { onSearch: (userId: string) => void })
│   │       │   └── Input + Button ("Search")
│   │       └── RiskProfileCard (props: { profile: UserRiskProfile | null })
│   │           ├── ScoreGauge (props: { score: number }) — circular gauge 0-100
│   │           ├── ComponentBreakdown (props: { components: Record<string, number> })
│   │           │   └── horizontal stacked bar for each component
│   │           ├── FreezeToggle (props: { frozen: boolean, onFreeze: () => void, onUnfreeze: () => void })
│   │           │   ├── Switch (shadcn) + confirmation Dialog
│   │           │   └── Textarea (freeze reason)
│   │           └── RecentFlagsList (props: { flags: FraudFlagOut[] })
│   │               └── compact DataTable of recent flags
│   ├── TabPanel: "Config"
│   │   └── FraudConfigForm (props: { config: FraudConfigOut, onSave: (data: FraudConfigUpdate) => void, isRoot: boolean })
│   │       ├── Form (react-hook-form + zod)
│   │       │   ├── NumberInput ("Max TX per hour", field: velocity_max_tx_per_hour)
│   │       │   ├── NumberInput ("Max amount per hour (cents)", field: velocity_max_amount_per_hour)
│   │       │   ├── NumberInput ("Large TX threshold (cents)", field: large_tx_threshold)
│   │       │   ├── NumberInput ("New account age (days)", field: new_account_age_days)
│   │       │   ├── NumberInput ("Flag score threshold", field: flag_score_threshold)
│   │       │   └── Button ("Save Config") — disabled if !isRoot
│   │       └── Alert (shadcn) — "Only root users can modify fraud configuration"
│   └── TabPanel: "Stats"  (expanded view)
│       └── FraudStatsPanel
│           ├── StatCard grid (larger format)
│           ├── FlagResolutionChart (props: { data: { date: string, resolved: number, flagged: number }[] })
│           │   └── BarChart (recharts)
│           └── RiskDistribution (props: { data: { range: string, count: number }[] })
│               └── PieChart (recharts) — 0-30, 30-50, 50-70, 70-100
```

### 3.11 Frontend TypeScript Types (`frontend/src/api/types.ts`)

```typescript
// --- Fraud Detection (FIN-015) ---

export interface FraudFlagOut {
  flag_id: string;
  user_id: string;
  tx_id: string;
  rule_triggered: string;
  risk_score: number;
  amount_cents: number;
  status: "pending" | "approved" | "blocked" | "investigating";
  reviewed_by: string | null;
  reviewed_at: number | null;
  resolution: "false_positive" | "confirmed_fraud" | "inconclusive" | null;
  notes: string | null;
  created_at: number;
}

export interface FraudFlagQueueOut {
  flags: FraudFlagOut[];
  count: number;
  cursor: string | null;
}

export interface FraudFlagReview {
  action: "approve" | "block" | "investigate";
  notes?: string;
}

export interface UserRiskProfile {
  user_id: string;
  score: number;
  components: Record<string, number>;
  flagged: boolean;
  frozen: boolean;
  frozen_at: number | null;
  frozen_by: string | null;
  tx_count_24h: number;
  tx_total_24h: number;
  chargeback_count: number;
  last_scored_at: number;
  recent_flags?: FraudFlagOut[];
}

export interface FreezeUserRequest {
  reason: string;
}

export interface FraudCaseCreate {
  user_id: string;
  flag_ids: string[];
  notes?: string;
}

export interface FraudCaseOut {
  case_id: string;
  user_id: string;
  status: "open" | "investigating" | "resolved";
  assigned_to: string | null;
  flags: string[];
  resolution: "false_positive" | "confirmed_fraud" | "inconclusive" | null;
  notes: string | null;
  created_at: number;
  resolved_at: number | null;
}

export interface FraudCaseResolve {
  resolution: "false_positive" | "confirmed_fraud" | "inconclusive";
  notes?: string;
}

export interface FraudConfigOut {
  velocity_max_tx_per_hour: number;
  velocity_max_amount_per_hour: number;
  large_tx_threshold: number;
  new_account_age_days: number;
  new_account_high_value: number;
  chargeback_threshold: number;
  flag_score_threshold: number;
  updated_at?: number;
  updated_by?: string;
}

export interface FraudConfigUpdate {
  velocity_max_tx_per_hour?: number;
  velocity_max_amount_per_hour?: number;
  large_tx_threshold?: number;
  new_account_age_days?: number;
  new_account_high_value?: number;
  chargeback_threshold?: number;
  flag_score_threshold?: number;
}

export interface FraudStatsOut {
  pending_flags: number;
  open_cases: number;
  frozen_users: number;
  flags_resolved_today: number;
  avg_resolution_hours: number;
}
```

### 3.12 Frontend API (`frontend/src/api/endpoints/adminFraud.ts`)

```typescript
import client from "../client";
import type {
  FraudFlagQueueOut,
  FraudFlagReview,
  UserRiskProfile,
  FreezeUserRequest,
  FraudCaseCreate,
  FraudCaseOut,
  FraudCaseResolve,
  FraudConfigOut,
  FraudConfigUpdate,
  FraudStatsOut,
} from "../types";

export const getFraudQueue = (params?: { status?: string; limit?: number; cursor?: string }) =>
  client.get<FraudFlagQueueOut>("/v1/admin/fraud/queue", { params });

export const reviewFlag = (flagId: string, data: FraudFlagReview) =>
  client.post(`/v1/admin/fraud/flags/${flagId}/review`, data);

export const getUserRisk = (userId: string) =>
  client.get<UserRiskProfile>(`/v1/admin/fraud/users/${userId}/risk`);

export const freezeUser = (userId: string, data: FreezeUserRequest) =>
  client.post(`/v1/admin/fraud/users/${userId}/freeze`, data);

export const unfreezeUser = (userId: string) =>
  client.post(`/v1/admin/fraud/users/${userId}/unfreeze`);

export const createFraudCase = (data: FraudCaseCreate) =>
  client.post("/v1/admin/fraud/cases", data);

export const listFraudCases = (params?: { status?: string }) =>
  client.get<FraudCaseOut[]>("/v1/admin/fraud/cases", { params });

export const getFraudCase = (caseId: string) =>
  client.get<FraudCaseOut>(`/v1/admin/fraud/cases/${caseId}`);

export const resolveCase = (caseId: string, data: FraudCaseResolve) =>
  client.post(`/v1/admin/fraud/cases/${caseId}/resolve`, data);

export const getFraudConfig = () =>
  client.get<FraudConfigOut>("/v1/admin/fraud/config");

export const updateFraudConfig = (data: FraudConfigUpdate) =>
  client.patch<FraudConfigOut>("/v1/admin/fraud/config", data);

export const getFraudStats = () =>
  client.get<FraudStatsOut>("/v1/admin/fraud/stats");
```

---

## 4. Implementation Plan

### Phase 1: Backend — Fraud Rules (Days 1-3)

1. **`scripts/local-ddb-init.py`**: Add `fraud_detection` table with GSIs.
2. **`app/core/settings.py`**: Add `fraud_detection_table_name`.
3. **`app/core/tables.py`**: Add `fraud_detection` table handle.
4. **`app/services/fraud_rules.py`**: New file. Rule engine with velocity, amount, new account, chargeback checks. Risk score computation.

### Phase 2: Backend — Management (Days 3-5)

5. **`app/services/fraud_management.py`**: New file. Flag queue, case lifecycle, freeze/unfreeze, risk profiles.
6. **Integrate with billing**: Add `evaluate_transaction` call to billing endpoints (tip, unlock, deposit) to check before processing.

### Phase 3: Backend — Router (Days 5-7)

7. **`app/models.py`**: Add fraud detection Pydantic models.
8. **`app/routers/admin_fraud.py`**: New router with 12 endpoints.
9. **`app/main.py`**: Register router with prefix `/v1/admin/fraud`.

### Phase 4: Frontend (Days 7-10)

10. **`frontend/src/api/types.ts`**: Add TypeScript types.
11. **`frontend/src/api/endpoints/adminFraud.ts`**: New file.
12. **`frontend/src/pages/admin/fraud/FraudDashboard.tsx`**: New page.
13. **`frontend/src/App.tsx`**: Add `/admin/fraud` route.
14. **`frontend/src/components/layout/Sidebar.tsx`**: Add "Fraud Detection" admin nav link.

### Phase 5: E2E Tests (Days 10-12)

15. **`frontend/e2e/admin-fraud.spec.ts`**: 16 tests across 4 sections.

---

## 5. E2E Test Plan

**Test file**: `frontend/e2e/admin-fraud.spec.ts`

**Setup (beforeAll)**:
- Inject auth for Root (admin), Alice (user), Charlie (admin)
- Seed a risk score row for Alice (score=75, flagged=true)
- Seed 3 flagged transactions for Alice (2 pending, 1 resolved)
- Seed 1 open fraud case for Alice

**Section 531: Fraud Queue API (6 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | `Admin retrieves fraud flag queue` | GET `/v1/admin/fraud/queue` as Root -> 200; array with 2 pending flags, each has `flag_id`, `user_id`, `risk_score`, `amount_cents`, `status` |
| 2 | `Queue filters by status` | GET `?status=resolved` -> 200; returns 1 resolved flag |
| 3 | `Admin approves a flagged transaction` | POST `/v1/admin/fraud/flags/{id}/review` with `{action: "approve"}` -> 200; re-GET queue shows flag no longer pending |
| 4 | `Admin blocks a flagged transaction` | POST review with `{action: "block", notes: "Confirmed stolen card"}` -> 200; status becomes "blocked", resolution is "confirmed_fraud" |
| 5 | `Admin marks flag for investigation` | POST review with `{action: "investigate"}` -> 200; status becomes "investigating", flag stays in pending GSI |
| 6 | `Non-admin cannot access fraud queue` | GET as Alice -> 403 |

**Section 532: User Risk & Freeze API (6 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 7 | `Admin views user risk profile` | GET `/v1/admin/fraud/users/{alice}/risk` as Root -> 200; `score >= 0`, `components` is object, `flagged` is boolean |
| 8 | `Risk profile includes recent flags` | Response has `recent_flags` array with seeded flags |
| 9 | `Admin freezes a user` | POST `/v1/admin/fraud/users/{alice}/freeze` with `{reason: "investigation"}` -> 200; re-GET shows `frozen: true` |
| 10 | `Admin unfreezes a user` | POST `/v1/admin/fraud/users/{alice}/unfreeze` -> 200; re-GET shows `frozen: false` |
| 11 | `Freeze requires reason` | POST freeze with `{reason: ""}` -> 422 |
| 12 | `Freeze with reason exceeding 500 chars` | POST freeze with 501-char reason -> 422 |

**Section 533: Fraud Case Management API (6 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 13 | `Admin lists open fraud cases` | GET `/v1/admin/fraud/cases?status=open` as Root -> 200; array with seeded case |
| 14 | `Admin creates a fraud case` | POST `/v1/admin/fraud/cases` with `{user_id, flag_ids: [...]}` -> 201; `case_id` present |
| 15 | `Admin resolves a fraud case as false positive` | POST `/v1/admin/fraud/cases/{id}/resolve` with `{resolution: "false_positive"}` -> 200; `status: "resolved"` |
| 16 | `Admin resolves a fraud case as confirmed fraud` | POST resolve with `{resolution: "confirmed_fraud", notes: "Card stolen"}` -> 200 |
| 17 | `Case detail includes linked flags` | GET `/v1/admin/fraud/cases/{id}` -> 200; `flags` is non-empty array |
| 18 | `Case create with empty flag_ids returns 422` | POST cases with `{user_id, flag_ids: []}` -> 422 |

**Section 534: Fraud Config & Stats API (6 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 19 | `Admin views fraud stats` | GET `/v1/admin/fraud/stats` as Root -> 200; has `pending_flags`, `open_cases`, `frozen_users` |
| 20 | `Admin views fraud config` | GET `/v1/admin/fraud/config` -> 200; has `velocity_max_tx_per_hour`, `flag_score_threshold` |
| 21 | `Root updates fraud thresholds` | PATCH `/v1/admin/fraud/config` with `{flag_score_threshold: 80}` as Root -> 200; re-GET confirms value |
| 22 | `Root updates multiple thresholds at once` | PATCH with `{velocity_max_tx_per_hour: 30, large_tx_threshold: 30000}` -> 200; both values updated |
| 23 | `Non-root cannot update config` | PATCH as Charlie -> 403 |
| 24 | `Invalid config threshold returns 422` | PATCH with `{flag_score_threshold: 5}` (below 10 minimum) -> 422 |

**Section 535: Fraud Dashboard UI (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 25 | `Dashboard page loads with stats bar` | Navigate to `/admin/fraud` as Root; verify stat cards visible: "Pending Flags", "Open Cases", "Frozen Users" |
| 26 | `Queue tab shows flagged transactions` | Click "Queue" tab; verify DataTable with flag rows, risk score badges, action buttons |
| 27 | `Users tab allows risk profile search` | Click "Users" tab; enter Alice's user ID; verify risk profile card appears with score gauge and component breakdown |
| 28 | `Config tab shows threshold form` | Click "Config" tab; verify form fields for velocity, amount, and score thresholds |

**Section 536: Edge Cases & Concurrent Access (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 29 | `Freeze idempotent — freezing already-frozen user succeeds` | Freeze Alice, then freeze again -> 200 both times, still frozen |
| 30 | `Unfreeze idempotent — unfreezing unfrozen user succeeds` | Ensure Alice unfrozen, then unfreeze again -> 200, still unfrozen |
| 31 | `Risk profile for unknown user returns zero defaults` | GET risk for `nonexistent_user_id` -> 200; score=0, empty components |
| 32 | `Concurrent flag reviews do not conflict` | POST review on two different flags simultaneously; both succeed independently |

---

## 6. Observability & Monitoring

### 6.1 Metrics

| Metric Name | Type | Labels | Description |
|---|---|---|---|
| `fraud_evaluation_total` | Counter | `action` (allow/flag/block) | Total fraud evaluations performed |
| `fraud_evaluation_duration_seconds` | Histogram | — | Time to run all fraud rules per transaction |
| `fraud_rule_triggered_total` | Counter | `rule` (velocity_count/velocity_amount/large_amount/new_account/chargeback_rate) | Times each rule was triggered |
| `fraud_flag_created_total` | Counter | `rule` | New flags created |
| `fraud_flag_reviewed_total` | Counter | `action` (approve/block/investigate) | Flags reviewed by admin |
| `fraud_case_created_total` | Counter | — | New fraud cases opened |
| `fraud_case_resolved_total` | Counter | `resolution` (false_positive/confirmed_fraud/inconclusive) | Cases resolved |
| `fraud_user_frozen_total` | Counter | — | Users frozen |
| `fraud_user_unfrozen_total` | Counter | — | Users unfrozen |
| `fraud_risk_score_distribution` | Histogram | — | Distribution of risk scores across evaluations |
| `fraud_queue_size` | Gauge | `status` (pending/investigating) | Current queue depth |

### 6.2 Structured Log Events

All fraud operations produce structured JSON log entries:

```json
{
  "logger": "fraud_rules",
  "level": "INFO",
  "event": "fraud_evaluation",
  "user_id": "alice_sub_123",
  "amount_cents": 500,
  "entry_type": "tip",
  "score": 72,
  "triggered_rules": ["velocity_count"],
  "action": "flag",
  "evaluation_ms": 45,
  "timestamp": 1748520600
}
```

```json
{
  "logger": "fraud_management",
  "level": "INFO",
  "event": "flag_reviewed",
  "flag_id": "flg_a1b2c3d4",
  "action": "approve",
  "admin": "root.admin@testdev.local",
  "notes": "Legitimate high-volume creator",
  "timestamp": 1748520700
}
```

```json
{
  "logger": "fraud_management",
  "level": "WARNING",
  "event": "user_frozen",
  "user_id": "alice_sub_123",
  "admin": "root.admin@testdev.local",
  "reason": "Multiple velocity violations in 24-hour period",
  "timestamp": 1748520900
}
```

```json
{
  "logger": "fraud_rules",
  "level": "ERROR",
  "event": "fraud_evaluation_error",
  "user_id": "alice_sub_123",
  "error": "ProvisionedThroughputExceededException",
  "fallback_action": "allow",
  "timestamp": 1748521000
}
```

### 6.3 Alerting Rules

| Alert | Condition | Severity | Action |
|---|---|---|---|
| High block rate | > 10 `action=block` evaluations in 5 minutes | Critical | Possible mass fraud attack; review queue immediately |
| Evaluation latency degraded | p99 evaluation time > 500ms | Warning | Check DDB throttling; scale read capacity |
| Queue depth growing | Pending flags > 50 and unreviewed for > 2 hours | Warning | Admin attention needed; consider auto-escalation |
| Frozen user count spike | > 5 users frozen in 1 hour | Warning | Possible false positive in rules; review thresholds |
| Rule engine failure | > 3 evaluation errors in 1 minute | Critical | Fallback to "allow" mode; investigate DDB connectivity |
| Chargeback spike | > 5 new chargebacks in 1 hour | Critical | Possible coordinated fraud; tighten velocity limits |
| Score computation stale | No score recomputation for any user in 1 hour | Warning | Check billing integration hooks |

### 6.4 Dashboard Queries

**Pending flags trend (last 7 days)**:
```
SELECT date_trunc('day', to_timestamp(created_at)),
       COUNT(*) as flags_created,
       SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved,
       SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked
FROM fraud_flags
WHERE created_at >= :seven_days_ago
GROUP BY 1
ORDER BY 1
```

**Top triggered rules (last 30 days)**:
```
SELECT rule_triggered, COUNT(*) as trigger_count, AVG(risk_score) as avg_score
FROM fraud_flags
WHERE created_at >= :thirty_days_ago
GROUP BY rule_triggered
ORDER BY trigger_count DESC
```

---

## 7. Rollout Plan

### Phase 1: Shadow Mode (Week 1)

**Feature flag**: `FRAUD_DETECTION_ENABLED=false` (default)

- Deploy fraud rules engine and management service
- Fraud evaluation runs on every transaction but only LOGS results — no flags created, no transactions blocked
- Monitor evaluation latency, rule trigger rates, and score distributions
- Validate that rule thresholds produce reasonable flag rates (target: <5% of transactions flagged)
- Admin dashboard deployed but shows "Shadow Mode" badge — queue is empty in this phase

**Migration steps**:
1. Create `fraud_detection` DDB table via `local-ddb-init.py`
2. Add `fraud_detection_table_name` to settings
3. Deploy backend with shadow mode enabled
4. Monitor for 7 days

### Phase 2: Logging + Flag Mode (Week 2)

**Feature flag**: `FRAUD_DETECTION_ENABLED=true`, `FRAUD_BLOCK_ENABLED=false`

- Fraud evaluation creates flags for transactions that exceed thresholds
- Flagged transactions are NOT blocked — they proceed normally but appear in admin queue
- Admin reviews flags to calibrate thresholds
- False positive rate measured: target <20% of flags are false positives
- Adjust `flag_score_threshold` and individual rule thresholds based on review data

### Phase 3: Enforcement Mode (Week 3)

**Feature flag**: `FRAUD_BLOCK_ENABLED=true`

- Transactions with `action=block` (score >= 90 or 3+ rules triggered) are rejected
- Transactions with `action=flag` proceed but are queued for review
- Freeze functionality enabled
- Monitor for increased support tickets from legitimate users being blocked

### Phase 4: Full Production (Week 4+)

- Remove shadow mode code paths
- Enable all features including config UI for root
- Set up automated threshold adjustment based on false positive rates
- Enable chargeback webhook integration for real-time chargeback tracking

### Feature Flags

| Flag | Default | Description |
|---|---|---|
| `FRAUD_DETECTION_ENABLED` | `false` | Master toggle: when false, evaluate_transaction returns "allow" without checking |
| `FRAUD_BLOCK_ENABLED` | `false` | When false, "block" actions are downgraded to "flag" |
| `FRAUD_FREEZE_ENABLED` | `true` | Toggle freeze functionality |
| `FRAUD_CONFIG_UI_ENABLED` | `true` | Toggle config tab in dashboard |
| `FRAUD_SCORE_THRESHOLD` | `70` | Initial flag threshold (overridable via DDB config) |

### Rollback Procedure

1. Set `FRAUD_DETECTION_ENABLED=false` — immediately disables all fraud checks; transactions proceed normally
2. If flags need to be cleared: run `clear_pending_flags()` admin script
3. If users were incorrectly frozen: run `bulk_unfreeze()` admin script
4. Revert code deployment if needed
5. Post-mortem: analyze false positive rate and threshold calibration

---

## 8. Performance Considerations

### 8.1 Latency Targets

| Operation | Target | Notes |
|---|---|---|
| `evaluate_transaction()` | < 100ms | Must not degrade payment UX; runs synchronously before payment |
| `velocity_check()` | < 30ms | Single DDB query on billing table (last 1 hour range) |
| `compute_risk_score()` | < 50ms | Single DDB get + conditional put |
| GET /fraud/queue | < 200ms | GSI1 query with limit, paginated |
| POST /flags/{id}/review | < 100ms | Single conditional update |
| GET /users/{id}/risk | < 300ms | Get score + GSI2 query for recent flags |
| POST /users/{id}/freeze | < 100ms | Single update + alert write |
| GET /fraud/stats | < 500ms | 3 GSI count queries (pending, open, resolved today) |
| GET /fraud/config | < 50ms | Single DDB get |
| PATCH /fraud/config | < 100ms | Single DDB put |

### 8.2 DynamoDB Query Costs

| Query | Read Capacity Units (RCU) | Notes |
|---|---|---|
| Get risk score | 0.5 RCU (eventual) | Single item, ~200 bytes |
| Velocity check (billing table) | 5-50 RCU | Depends on tx count in last hour; heavy users may have 100+ items |
| List pending flags (GSI1) | 1-10 RCU | Depends on queue depth; paginated at 50 |
| Get flag detail | 0.5 RCU | Single item |
| List user flags (GSI2) | 1-5 RCU | Limited to 20 most recent |
| Stats count queries (3x) | 3-15 RCU total | Count-only queries, no item data transferred |

### 8.3 Caching Strategy

- **Fraud config**: Cached in-memory with 60-second TTL. Config changes are infrequent (admin-initiated). The `get_fraud_config()` function checks a module-level `_config_cache` dict with timestamp — if stale, re-fetches from DDB.
- **Risk scores**: NOT cached — always read from DDB to ensure consistency during active fraud evaluation.
- **Flag queue**: NOT cached — admin dashboard always shows real-time data.
- **Stats**: Cached for 30 seconds in the router layer. Stats queries hit 3 GSIs and are relatively expensive.

### 8.4 Rate Limiting

- `evaluate_transaction()` is called on every financial transaction. Under normal load, this is < 100 calls/second platform-wide.
- Admin endpoints are rate-limited to 60 requests/minute per admin session (shared with other admin endpoints).
- The `/fraud/stats` endpoint is rate-limited to 10 requests/minute per session to prevent expensive count queries from overwhelming DDB.

### 8.5 Scalability Considerations

- **Velocity check optimization**: For users with very high transaction volumes (>1000 tx/hour), the billing table range query becomes expensive. Mitigation: maintain a counter item `pk=USER#{id}, sk=TX_COUNT_1H` with atomic increment — query this instead of scanning the ledger.
- **Flag queue scaling**: With many concurrent flagged transactions, the `FLAGS#PENDING` GSI partition could become hot. Mitigation: if pending flags exceed 10,000, shard the GSI PK to `FLAGS#PENDING#0` through `FLAGS#PENDING#9` using hash of flag_id.
- **Frozen user count**: The `frozen_users` stat in `get_fraud_stats()` currently requires a table scan. For production, maintain a counter item `pk=STATS, sk=FROZEN_COUNT` updated atomically on freeze/unfreeze.

---

## 9. Security Considerations

### 9.1 Role-Based Access
- All fraud endpoints require ADMIN role
- Configuration changes require ROOT role
- Fraud data is highly sensitive and must not be exposed to regular users

### 9.2 Freeze Safety
- Freeze blocks new outgoing payments, tips, unlocks, and payouts
- Freeze does NOT block incoming payments (other users can still tip/pay frozen user)
- Freeze notification sent to user with generic message (does not reveal fraud investigation)
- Unfreeze requires admin action (no auto-unfreeze)

### 9.3 Rule Engine Integration
- Fraud checks run synchronously before transaction processing
- If `action=block`, transaction is rejected with generic "payment declined" error
- If `action=flag`, transaction proceeds but is added to review queue
- Rule evaluation must complete within 100ms to avoid degrading user experience

### 9.4 Audit Trail
- All flag reviews, freeze/unfreeze actions, and case resolutions logged with admin identity
- Fraud case notes and evidence are immutable after case resolution
- Risk score history preserved for post-incident analysis

### 9.5 Data Privacy
- Fraud data is accessible only to ADMIN/ROOT roles
- User freeze notifications use generic language to avoid tipping off actual fraudsters
- Risk score breakdown is never exposed to the user themselves
- IP addresses used in geo checks are not stored in the fraud_detection table — only the geo score component is retained

---

## 10. Files to Create

| File | Purpose |
|------|---------|
| `app/services/fraud_rules.py` | Fraud detection rule engine |
| `app/services/fraud_management.py` | Flag queue, case management, freeze |
| `app/routers/admin_fraud.py` | Admin fraud API (12 endpoints) |
| `frontend/src/api/endpoints/adminFraud.ts` | API wrappers |
| `frontend/src/pages/admin/fraud/FraudDashboard.tsx` | Dashboard page |
| `frontend/e2e/admin-fraud.spec.ts` | E2E tests (32 tests, sections 531-536) |

## 11. Files to Modify

| File | Change |
|------|--------|
| `app/models.py` | Add fraud detection Pydantic models |
| `app/main.py` | Register `admin_fraud_router` |
| `app/core/settings.py` | Add `fraud_detection_table_name` |
| `app/core/tables.py` | Add `fraud_detection` table handle |
| `scripts/local-ddb-init.py` | Add `fraud_detection` table with GSIs |
| `app/routers/billing.py` | Add `evaluate_transaction` call before tip/unlock/deposit |
| `frontend/src/api/types.ts` | Add fraud detection TypeScript types |
| `frontend/src/App.tsx` | Add `/admin/fraud` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Fraud Detection" admin nav link |

## 12. Acceptance Criteria

1. Fraud rules engine evaluates transactions for velocity, amount, new account, and chargeback anomalies
2. Risk score (0-100) computed per user with breakdown by component
3. Transactions exceeding score threshold auto-flagged and added to review queue
4. Admin queue lists pending flags with approve/block/investigate actions
5. User freeze/unfreeze blocks/restores financial operations
6. Fraud cases can be created, assigned, and resolved with audit trail
7. Stats endpoint returns pending flags, open cases, frozen users count
8. Fraud config thresholds updatable by ROOT only
9. All 32 E2E tests pass in `frontend/e2e/admin-fraud.spec.ts`
10. Fraud evaluation completes within 100ms p99 latency
11. Dashboard shows real-time queue depth and resolution metrics
12. Feature flags allow shadow mode, flag-only mode, and full enforcement mode

---

## Codebase References

| File | Lines | What |
|------|-------|------|
| `app/services/billing_shared.py` | :213, :217, :248 | `ledger_sk` at `:213`, `new_ledger_entry` at `:217` (field is `type` not `entry_type`), `settle_or_reverse_ledger` at `:248` |
| `app/services/rate_limit.py` | :17 | `rate_limit_or_429` at `:17`; no `check_rate_limit` function exists |
| `app/routers/billing.py` | — | Stripe billing router; registered at `app/main.py:326` |
| `app/routers/billing_ccbill.py` | — | CCBill router; registered at `app/main.py:314` |
| `app/auth/policy.py` | :63, :67 | `require_root` at `:63`, `require_admin_or_root` at `:67` |
| `app/services/alerts.py` | :355 | `write_alert` function (used for freeze notifications) |
| `app/core/cursor.py` | :83, :92 | `encode_cursor` at `:83`, `decode_cursor` at `:92` |
| `app/core/tables.py` | — | Table handles (`T.billing`, etc.) |
| `app/core/time.py` | — | `now_ts()` Unix timestamp helper |
| `scripts/local-ddb-init.py` | :59 | `billing` table definition (PK=pk, SK=sk, no GSIs) |
| `app/core/settings.py` | :321 | `billing_table_name` setting |

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_fraud_detection.py`

Mock external dependencies with `moto` (DynamoDB) and `unittest.mock`. All tests run without the dev stack.

  - `test_velocity_check_under_limit_passes`
  - `test_velocity_check_over_limit_triggers`
  - `test_large_amount_check_triggers`
  - `test_new_account_check_triggers`
  - `test_chargeback_check_triggers`
  - `test_compute_risk_score_components`
  - `test_evaluate_transaction_flag_action`
  - `test_evaluate_transaction_block_action`
  - `test_freeze_user_sets_frozen_true`
  - `test_unfreeze_user_sets_frozen_false`

### Integration Tests

  - evaluate_transaction called in billing tip endpoint flags high-risk tx
  - Freeze user blocks new tip/unlock/deposit requests
  - Flag review updates GSI from FLAGS#PENDING to FLAGS#RESOLVED
  - Fraud case lifecycle open -> investigating -> resolved
  - Risk score history records each recomputation

### E2E Tests (Playwright)

**File**: `frontend/e2e/admin-fraud.spec.ts`
**Test count**: 32

**Auth pattern**: Use `injectAuth(page, "root")` for admin endpoints; use `injectAuth(page, "alice")` for user-level endpoints. All POST/PATCH/DELETE requests include `x-csrf-token` header matching the session's CSRF token.

**Negative tests**:
- 401: Unauthenticated request returns 401
- 403: Non-admin/non-owner access returns 403
- 404: Non-existent resource returns 404
- 409: Conflict on duplicate or already-processed resource
- 422: Invalid input (bad field values, missing required fields)

**Edge cases**:
- Empty result sets return 200 with empty arrays (not 404)
- Pagination cursor works correctly across pages
- Concurrent requests do not produce inconsistent state

### Test Data Requirements

- **DDB seeds**: Seed `fraud_detection` table with test records in `beforeAll`
- **Test users**: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- **Cleanup**: Tests use unique timestamps/IDs per run to avoid cross-run interference

### CI/Pipeline Considerations

- **Feature flag**: `FRAUD_DETECTION_ENABLED=true` must be set in test environment
- **Serial execution**: E2E tests run with `workers: 1` to avoid shared-state conflicts
- **Retry safety**: All tests are idempotent; retries do not produce duplicate records

## Dependencies & Merge Safety

### Depends On

| Ticket | Title | Why |
|--------|-------|-----|
| (none) | — | This ticket has no blocking dependencies |

### Depended On By

| Ticket | Title | Impact |
|--------|-------|--------|
| FIN-017 | Bulk Payout/Refund Tools | Checks user frozen status before payout approval |

### Merge Strategy

**Feature-flag-gated**

Can be merged at any time behind the `FRAUD_DETECTION_ENABLED` feature flag. The flag defaults to `false` in production until validated, allowing safe incremental rollout.

### Merge Checklist

- [ ] All new DDB tables added to `scripts/local-ddb-init.py` with correct `attr_types` for numeric GSI keys
- [ ] New settings added to `app/core/settings.py` and `.env.local.example`
- [ ] New table handles added to `app/core/tables.py`
- [ ] Router registered in `app/main.py`
- [ ] Pydantic models added to `app/models.py`
- [ ] TypeScript types added to `frontend/src/api/types.ts`
- [ ] Route added to `frontend/src/App.tsx`
- [ ] Feature flag defaults to `true` in `.env.local.example`
- [ ] E2E session setup updated if new test identities needed
- [ ] `just restart` completes cleanly with new tables
- [ ] All 32 E2E tests pass with `npx playwright test admin-fraud.spec.ts`
