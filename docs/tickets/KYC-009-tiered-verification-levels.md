# KYC-009: KYC Tiered Verification Levels

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: Critical  
**Estimated effort**: 10-14 days  
**Dependencies**: KYC-001 (Admin Dashboard), KYC-008 (Risk Scoring Engine)

---

## 1. Overview & Motivation

### 1.1 The Gap

The current KYC system (`app/routers/kyc_cases.py`, 1294 lines; `app/services/kyc_cases.py`, 828 lines) implements a binary verification model:
<!-- NOTE: ticket originally cited 1295 and 829 lines -- actual counts are 1294 and 828 --> a user either has an approved KYC case or they do not. The case lifecycle (`draft -> submitted -> under_review -> approved/rejected -> expired`) determines whether a user passed identity verification, but there is no concept of graduated access based on verification depth.

This means every user who completes KYC gets the same level of platform access, regardless of whether they only verified their email or completed a full enhanced due diligence process with proof of funds and a verification call. The platform cannot distinguish between a casual browser who just signed up and a professional creator who has undergone comprehensive identity checks.

### 1.2 Why Tiered Verification Matters

1. **Regulatory compliance**: Financial regulations (AML/KYC) require different levels of due diligence based on risk profile and transaction volume. A user sending small tips needs less verification than a creator receiving thousands in payouts.
2. **Progressive onboarding**: Requiring full KYC before a user can even send a message drives abandonment. Tiered access lets users start with minimal friction and verify incrementally as they want to use more features.
3. **Risk management**: Higher-value operations (payouts, high-value transactions, API access) should require proportionally stronger identity assurance.
4. **Creator trust signals**: Verified creator badges (Tier 3+) build buyer confidence for subscriptions, tips, and purchases.
5. **Business accounts**: Institutional users (Tier 4) need a distinct verification path involving corporate documents, UBO identification, and enhanced due diligence (see KYC-015).

### 1.3 Tier Definitions

| Tier | Name | Requirements | Unlocked Features |
|------|------|-------------|------------------|
| 0 | Unverified | Account created | Browse content, view public profiles |
| 1 | Basic | Email verified + phone verified | Send messages, post to feed, comment, follow users |
| 2 | ID Verified | Tier 1 + approved KYC case (selfie + ID document) | Buy content, subscribe, send tips, upload content, shopping cart |
| 3 | Enhanced | Tier 2 + proof of address + verification call + questionnaire | Creator mode (receive payouts), high-value transactions (>$500), broadcast |
| 4 | Institutional | Tier 3 + business KYC (KYC-015) + API access approval | API access, white-label features, bulk operations, elevated rate limits |

### 1.4 Architecture After This Change

```
User Profile
  └── kyc_tier: 0 | 1 | 2 | 3 | 4
  └── kyc_tier_updated_at: int (Unix timestamp)
  └── kyc_tier_history: [{ tier, changed_at, reason, actor_sub }]

Feature Gating Flow:
  Request → Auth Middleware → require_ui_session → ctx["user_sub"]
                                                      │
                                            ┌─────────▼─────────┐
                                            │  get_user_kyc_tier │
                                            └─────────┬─────────┘
                                                      │
                                            ┌─────────▼─────────┐
                                            │ require_kyc_tier(N)│
                                            │  (FastAPI Depend)  │
                                            └─────────┬─────────┘
                                                      │
                                         tier >= N?   │
                                       ┌──yes──┐  ┌──no──┐
                                       │ allow │  │ 403  │
                                       │ req   │  │ body:│
                                       └───────┘  │ tier │
                                                   │ req  │
                                                   └──────┘

Tier Upgrade Flow:
  User Profile ──(email verified? phone verified?)──► Tier 0 → 1
  KYC Case ──(ID + selfie approved?)──► Tier 1 → 2
  KYC Case ──(PoA + call + questionnaire approved?)──► Tier 2 → 3
  Business KYC ──(corp docs + UBO approved?)──► Tier 3 → 4

Admin Override:
  POST /v1/kyc/tiers/{user_sub}/override
    { tier: 3, reason: "manual verification completed offline" }
    → Audit trail + immediate tier change
```

---

## 2. Current State Analysis

### 2.1 User Profile Storage (`app/services/profile.py`)

The profile service stores user data in the `users` table. The `get_profile(user_sub)` function (see `app/services/profiles.py:220`) returns fields including `display_name`, `bio`, `mailing_address`, `email`, `phone`, etc. There are no `kyc_tier`, `kyc_tier_updated_at`, or `kyc_tier_history` fields. The `apply_profile_update()` function (see `app/services/profiles.py:294`) handles field normalization and updates.
<!-- NOTE: ticket originally cited apply_profile_update at line 163 -- actual is line 294 -->

### 2.2 KYC Case Store (`app/services/kyc_cases.py`)

The `KycCaseStore` class manages case lifecycle. `create_case()` (see `app/services/kyc_cases.py:97`) creates a case with `status="draft"`. The `apply_admin_decision()` (see `app/services/kyc_cases.py:534`) method sets `status="approved"` or `status="rejected"`. When a case is approved, there is no downstream effect on the user's profile -- the approval is recorded only in the `kyc_cases` table. There is no tier elevation logic.

### 2.3 Auth Dependencies (`app/auth/deps.py`)

The `AuthenticatedUser` class (see `app/auth/deps.py:126`) has `sub`, `role`, and `admin_profile` fields. There is no `kyc_tier` field. The `require_ui_session` dependency returns a dict with `user_sub`, `role`, and `admin_profile`. Feature gating based on verification level does not exist.
<!-- NOTE: require_ui_session is in app/auth/deps.py, not app/services/sessions.py -->

### 2.4 Feature Access Points That Need Gating

Examining the codebase for endpoints that should require specific tiers:

- **Messaging** (`app/routers/messaging.py`): `create_dm`, `send_text_message`, `create_group` — should require Tier 1+
- **Newsfeed** (`app/routers/newsfeed.py`): `create_post`, `add_comment` — should require Tier 1+
- **Billing** (`app/routers/billing.py`): `create_payment_method`, `deposit_wallet` — should require Tier 2+
- **Tips/Unlocks** (`app/routers/messaging.py`): `tip_message`, `unlock_message` — should require Tier 2+
- **Catalog** (`app/routers/catalog.py`): `create_product` — should require Tier 2+
- **Subscriptions** (`app/routers/subscription_server.py`): `subscribe` — should require Tier 2+
- **Payouts** (`app/routers/admin_payouts.py`): Creator payout requests — should require Tier 3+
- **Broadcast** (`app/routers/broadcast.py`): `create_session` — should require Tier 3+
- **API Keys** (`app/routers/api_keys.py`): `create_api_key` — should require Tier 4
- **Webhooks** (`app/routers/webhooks.py`): `create_webhook_endpoint` — should require Tier 4

### 2.5 Email and Phone Verification State

The account registration flow (`app/routers/register.py`) handles email verification. Phone verification is handled by the MFA system (`app/routers/mfa_devices.py`). The profile record may have `email_verified` and `phone_verified` fields but these are not centrally queryable for tier determination.

### 2.6 Alert System (`app/services/alerts.py`)

`write_alert(user_sub, *, event, outcome, title, details)` (see `app/services/alerts.py:355`) creates in-app alerts. `audit_event(event, user_sub, request, **fields)` (see `app/services/alerts.py:695`) writes audit log entries. Both will be used for tier change notifications and audit trails.

---

## 3. Technical Design

### 3.1 New DDB Fields on User Profile

Add to the `users` table record for each user:

```python
# Fields added to user profile item
{
    "kyc_tier": 0,                          # Current tier (0-4)
    "kyc_tier_updated_at": 1717000000,      # Unix timestamp of last tier change
    "kyc_tier_history": [                   # Audit log of tier changes
        {
            "from_tier": 0,
            "to_tier": 1,
            "changed_at": 1717000000,
            "reason": "email_and_phone_verified",
            "actor_sub": "user_sub_value",   # User or admin who triggered
            "case_id": null,                 # KYC case ID if applicable
        }
    ],
}
```

### 3.2 New GSI on Users Table

Add a GSI for querying users by tier (admin reporting):

```python
# scripts/local-ddb-init.py — add to users table GSI list
{"index_name": "ByKycTier", "partition_key": "kyc_tier", "sort_key": "kyc_tier_updated_at"},
```

`attr_types`: `kyc_tier` is `"N"`, `kyc_tier_updated_at` is `"N"`.

### 3.3 New Service: `app/services/kyc_tiers.py`

```python
"""KYC tier management — progressive verification levels."""
from __future__ import annotations

from typing import Any, Optional
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import audit_event, write_alert

KYC_TIER_NAMES = {0: "Unverified", 1: "Basic", 2: "ID Verified", 3: "Enhanced", 4: "Institutional"}
KYC_TIER_MAX = 4

TIER_REQUIREMENTS = {
    1: {"email_verified", "phone_verified"},
    2: {"tier_1", "kyc_case_approved"},
    3: {"tier_2", "proof_of_address", "verification_call", "questionnaire_completed"},
    4: {"tier_3", "business_kyc_approved", "api_access_approved"},
}


def get_user_kyc_tier(user_sub: str) -> int:
    """Return current KYC tier for user (0-4). Defaults to 0 if not set."""
    item = T.users.get_item(Key={"pk": f"USER#{user_sub}", "sk": "PROFILE"}).get("Item")
    if not item:
        return 0
    return int(item.get("kyc_tier", 0))


def get_tier_details(user_sub: str) -> dict[str, Any]:
    """Return full tier info including history and requirements."""
    item = T.users.get_item(Key={"pk": f"USER#{user_sub}", "sk": "PROFILE"}).get("Item")
    tier = int((item or {}).get("kyc_tier", 0))
    return {
        "user_sub": user_sub,
        "current_tier": tier,
        "tier_name": KYC_TIER_NAMES.get(tier, "Unknown"),
        "updated_at": (item or {}).get("kyc_tier_updated_at"),
        "history": (item or {}).get("kyc_tier_history", []),
    }


def check_tier_requirements(user_sub: str, target_tier: int) -> dict[str, Any]:
    """Check which requirements are met/unmet for a target tier."""
    # Gather evidence from multiple sources
    profile = T.users.get_item(Key={"pk": f"USER#{user_sub}", "sk": "PROFILE"}).get("Item", {})
    current_tier = int(profile.get("kyc_tier", 0))

    met = set()
    unmet = set()

    # Tier 1 checks
    if profile.get("email_verified"):
        met.add("email_verified")
    else:
        unmet.add("email_verified")

    if profile.get("phone_verified"):
        met.add("phone_verified")
    else:
        unmet.add("phone_verified")

    # Tier 2 checks (requires tier 1 + KYC case)
    if current_tier >= 1:
        met.add("tier_1")
    else:
        unmet.add("tier_1")

    # Check for approved KYC case
    from app.services.kyc_cases import STORE
    cases = STORE.list_cases_by_owner(user_sub=user_sub, limit=10)
    has_approved_case = any(c.get("status") == "approved" for c in cases)
    if has_approved_case:
        met.add("kyc_case_approved")
    else:
        unmet.add("kyc_case_approved")

    # Tier 3 checks
    if current_tier >= 2:
        met.add("tier_2")
    else:
        unmet.add("tier_2")

    approved_case = next((c for c in cases if c.get("status") == "approved"), None)
    if approved_case:
        files = approved_case.get("files", [])
        has_poa = any(f.get("file_type") == "proof_of_address" for f in files)
        if has_poa:
            met.add("proof_of_address")
        else:
            unmet.add("proof_of_address")

        qnr = approved_case.get("questionnaire", {})
        if qnr.get("response_session_id"):
            met.add("questionnaire_completed")
        else:
            unmet.add("questionnaire_completed")

        review = approved_case.get("review", {})
        if review.get("verification_call_completed"):
            met.add("verification_call")
        else:
            unmet.add("verification_call")
    else:
        unmet.update({"proof_of_address", "questionnaire_completed", "verification_call"})

    # Tier 4 checks
    if current_tier >= 3:
        met.add("tier_3")
    else:
        unmet.add("tier_3")
    unmet.update({"business_kyc_approved", "api_access_approved"} - met)

    required_for_target = set()
    for t in range(1, target_tier + 1):
        required_for_target |= TIER_REQUIREMENTS.get(t, set())

    return {
        "target_tier": target_tier,
        "current_tier": current_tier,
        "met": sorted(met & required_for_target),
        "unmet": sorted(unmet & required_for_target),
        "eligible": len(unmet & required_for_target) == 0,
    }


def upgrade_tier(
    *,
    user_sub: str,
    new_tier: int,
    reason: str,
    actor_sub: str,
    case_id: str | None = None,
    request=None,
) -> dict[str, Any]:
    """Upgrade (or set) user's KYC tier. Returns updated tier details."""
    if new_tier < 0 or new_tier > KYC_TIER_MAX:
        raise ValueError(f"Invalid tier: {new_tier}")

    item = T.users.get_item(Key={"pk": f"USER#{user_sub}", "sk": "PROFILE"}).get("Item", {})
    current_tier = int(item.get("kyc_tier", 0))
    ts = now_ts()

    history_entry = {
        "from_tier": current_tier,
        "to_tier": new_tier,
        "changed_at": ts,
        "reason": reason,
        "actor_sub": actor_sub,
        "case_id": case_id,
    }

    T.users.update_item(
        Key={"pk": f"USER#{user_sub}", "sk": "PROFILE"},
        UpdateExpression=(
            "SET kyc_tier = :tier, kyc_tier_updated_at = :ts, "
            "kyc_tier_history = list_append(if_not_exists(kyc_tier_history, :empty), :entry)"
        ),
        ExpressionAttributeValues={
            ":tier": new_tier,
            ":ts": ts,
            ":entry": [history_entry],
            ":empty": [],
        },
    )

    # Audit trail
    audit_event(
        "kyc.tier.changed",
        actor_sub,
        request,
        outcome="success",
        user_sub=user_sub,
        from_tier=current_tier,
        to_tier=new_tier,
        reason=reason,
        case_id=case_id,
    )

    # Alert to user
    direction = "upgraded" if new_tier > current_tier else "downgraded"
    write_alert(
        user_sub,
        event=f"kyc.tier.{direction}",
        outcome="success",
        title=f"Verification level {direction} to {KYC_TIER_NAMES[new_tier]}",
        details={
            "from_tier": current_tier,
            "to_tier": new_tier,
            "tier_name": KYC_TIER_NAMES[new_tier],
            "reason": reason,
        },
    )

    return get_tier_details(user_sub)


def auto_evaluate_tier(user_sub: str, *, request=None) -> dict[str, Any]:
    """Automatically evaluate and upgrade tier based on current evidence."""
    current = get_user_kyc_tier(user_sub)

    for target in range(current + 1, KYC_TIER_MAX + 1):
        check = check_tier_requirements(user_sub, target)
        if check["eligible"]:
            return upgrade_tier(
                user_sub=user_sub,
                new_tier=target,
                reason="auto_evaluation",
                actor_sub=user_sub,
                request=request,
            )
        else:
            break  # Can't skip tiers

    return get_tier_details(user_sub)
```

### 3.4 FastAPI Dependency: `require_kyc_tier`

Add to `app/auth/deps.py`:

```python
from app.services.kyc_tiers import get_user_kyc_tier, KYC_TIER_NAMES


def require_kyc_tier(minimum_tier: int):
    """FastAPI dependency factory that enforces a minimum KYC tier."""
    async def _check(request: Request):
        user = await get_authenticated_user(request)
        tier = get_user_kyc_tier(user.sub)
        if tier < minimum_tier:
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "kyc_tier_insufficient",
                    "message": f"This action requires {KYC_TIER_NAMES.get(minimum_tier, f'Tier {minimum_tier}')} verification",
                    "current_tier": tier,
                    "required_tier": minimum_tier,
                    "upgrade_url": "/kyc",
                },
            )
        return user
    return _check
```

### 3.5 New Router: `app/routers/kyc_tiers.py`

```python
router = APIRouter(prefix="/v1/kyc/tiers", tags=["kyc-tiers"])
```

**Endpoints**:

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/me` | `require_ui_session` | Get current user's tier details + history |
| `GET` | `/me/requirements/{target_tier}` | `require_ui_session` | Check requirements for a target tier |
| `POST` | `/me/evaluate` | `require_ui_session` | Trigger auto-evaluation of tier |
| `GET` | `/admin/{user_sub}` | `require_root_session` | Get any user's tier details (admin) |
| `POST` | `/admin/{user_sub}/override` | `require_root_session` | Override a user's tier (admin) |
| `GET` | `/admin/by-tier/{tier}` | `require_root_session` | List users by tier (admin) |

**Endpoint signatures**:

```python
@router.get("/me")
async def get_my_tier(ctx=Depends(require_ui_session)):
    return get_tier_details(ctx["user_sub"])


@router.get("/me/requirements/{target_tier}")
async def check_my_requirements(target_tier: int, ctx=Depends(require_ui_session)):
    if target_tier < 0 or target_tier > 4:
        raise HTTPException(400, "target_tier must be 0-4")
    return check_tier_requirements(ctx["user_sub"], target_tier)


@router.post("/me/evaluate")
async def evaluate_my_tier(request: Request, ctx=Depends(require_ui_session)):
    return auto_evaluate_tier(ctx["user_sub"], request=request)


@router.get("/admin/{user_sub}")
async def admin_get_user_tier(user_sub: str, user=Depends(require_root_session)):
    return get_tier_details(user_sub)


@router.post("/admin/{user_sub}/override")
async def admin_override_tier(
    user_sub: str,
    body: TierOverrideRequest,
    request: Request,
    user=Depends(require_root_session),
):
    return upgrade_tier(
        user_sub=user_sub,
        new_tier=body.tier,
        reason=body.reason,
        actor_sub=user.sub,
        request=request,
    )


@router.get("/admin/by-tier/{tier}")
async def admin_list_by_tier(tier: int, user=Depends(require_root_session)):
    if tier < 0 or tier > 4:
        raise HTTPException(400, "tier must be 0-4")
    # Query ByKycTier GSI
    resp = T.users.query(
        IndexName="ByKycTier",
        KeyConditionExpression=Key("kyc_tier").eq(tier),
        ScanIndexForward=False,
        Limit=100,
    )
    return {"tier": tier, "users": [_user_summary(i) for i in resp.get("Items", [])]}
```

### 3.6 Pydantic Models (`app/contracts/kyc_cases_contract.py`)

```python
class TierOverrideRequest(BaseModel):
    tier: int = Field(ge=0, le=4)
    reason: str = Field(min_length=5, max_length=500)


class TierDetailsOut(BaseModel):
    user_sub: str
    current_tier: int
    tier_name: str
    updated_at: int | None = None
    history: list[dict[str, Any]] = Field(default_factory=list)


class TierRequirementsOut(BaseModel):
    target_tier: int
    current_tier: int
    met: list[str]
    unmet: list[str]
    eligible: bool
```

### 3.7 Feature Gating Integration

Apply `require_kyc_tier` to existing endpoints. Example for messaging:

```python
# app/routers/messaging.py — modify create_dm
@router.post("/conversations/dm")
async def create_dm(
    body: CreateDmRequest,
    ctx=Depends(require_ui_session),
    _tier=Depends(require_kyc_tier(1)),  # Tier 1+ for messaging
):
    ...
```

For billing:

```python
# app/routers/billing.py — modify deposit_wallet
@router.post("/billing/wallet/deposit")
async def deposit_wallet(
    body: DepositRequest,
    ctx=Depends(require_ui_session),
    _tier=Depends(require_kyc_tier(2)),  # Tier 2+ for transactions
):
    ...
```

### 3.8 Auto-Upgrade Trigger Points

Tier upgrades should be evaluated automatically at key moments:

1. **After email verification** (`app/routers/register.py`): Call `auto_evaluate_tier()` after email confirmation.
2. **After phone verification** (`app/routers/mfa_devices.py`): Call `auto_evaluate_tier()` after phone MFA setup.
3. **After KYC case approval** (`app/routers/kyc_cases.py`, `_admin_decide_case`): Call `auto_evaluate_tier()` when decision is "approved".

```python
# In app/routers/kyc_cases.py, after _admin_decide_case sets status to "approved":
if decision == "approved":
    from app.services.kyc_tiers import auto_evaluate_tier
    auto_evaluate_tier(case["user_sub"], request=request)
```

### 3.9 Frontend: Tier Badge Component

**File**: `frontend/src/components/shared/KycTierBadge.tsx`

```tsx
const TIER_CONFIG = {
  0: { label: "Unverified", color: "gray", icon: null },
  1: { label: "Basic", color: "blue", icon: "CheckCircle" },
  2: { label: "ID Verified", color: "green", icon: "ShieldCheck" },
  3: { label: "Enhanced", color: "purple", icon: "Award" },
  4: { label: "Institutional", color: "gold", icon: "Building2" },
};
```

### 3.10 Frontend: Tier Upgrade Progress Page

**File**: `frontend/src/pages/kyc/KycTierProgress.tsx`

Displays:
- Current tier with badge
- Next tier requirements checklist (met/unmet)
- "Upgrade" button that triggers `/v1/kyc/tiers/me/evaluate`
- Link to KYC wizard for completing unmet requirements
- History timeline of past tier changes

### 3.11 Frontend API Endpoints

**File**: `frontend/src/api/endpoints/kyc-tiers.ts`

```typescript
export const getMyTier = () => client.get("/v1/kyc/tiers/me");
export const checkRequirements = (targetTier: number) =>
  client.get(`/v1/kyc/tiers/me/requirements/${targetTier}`);
export const evaluateTier = () => client.post("/v1/kyc/tiers/me/evaluate");
export const adminGetUserTier = (userSub: string) =>
  client.get(`/v1/kyc/tiers/admin/${userSub}`);
export const adminOverrideTier = (userSub: string, data: { tier: number; reason: string }) =>
  client.post(`/v1/kyc/tiers/admin/${userSub}/override`, data);
```

### 3.12 Frontend Route

**File**: `frontend/src/App.tsx`

```tsx
const KycTierProgress = lazy(() => import("./pages/kyc/KycTierProgress"));
// Add route:
<Route path="/kyc/tiers" element={<KycTierProgress />} />
```

### 3.13 Registration in `app/main.py`

```python
from app.routers.kyc_tiers import router as kyc_tiers_router
app.include_router(kyc_tiers_router)
```

---

## 4. Implementation Plan

### Phase 1: Backend Service + DDB (3 days)

| File | Change |
|------|--------|
| `app/services/kyc_tiers.py` | New: tier management service (~200 lines) |
| `app/contracts/kyc_cases_contract.py` | Add `TierOverrideRequest`, `TierDetailsOut`, `TierRequirementsOut` models |
| `app/core/settings.py` | Add `kyc_tier_gating_enabled` feature flag (default `True`) |
| `scripts/local-ddb-init.py` | Add `ByKycTier` GSI to users table, declare `attr_types` |

### Phase 2: Router + Auth Dependency (2 days)

| File | Change |
|------|--------|
| `app/routers/kyc_tiers.py` | New: 6 endpoints (~180 lines) |
| `app/auth/deps.py` | Add `require_kyc_tier()` dependency factory |
| `app/main.py` | Register `kyc_tiers_router` |

### Phase 3: Feature Gating (2 days)

| File | Change |
|------|--------|
| `app/routers/messaging.py` | Add `require_kyc_tier(1)` to DM/group creation |
| `app/routers/newsfeed.py` | Add `require_kyc_tier(1)` to post/comment creation |
| `app/routers/billing.py` | Add `require_kyc_tier(2)` to payment methods, deposits |
| `app/routers/broadcast.py` | Add `require_kyc_tier(3)` to session creation |
| `app/routers/api_keys.py` | Add `require_kyc_tier(4)` to API key creation |
| `app/routers/webhooks.py` | Add `require_kyc_tier(4)` to webhook creation |

### Phase 4: Auto-Upgrade Triggers (1 day)

| File | Change |
|------|--------|
| `app/routers/register.py` | Call `auto_evaluate_tier()` after email verification |
| `app/routers/mfa_devices.py` | Call `auto_evaluate_tier()` after phone verification |
| `app/routers/kyc_cases.py` | Call `auto_evaluate_tier()` after case approval |

### Phase 5: Frontend (2 days)

| File | Change |
|------|--------|
| `frontend/src/api/endpoints/kyc-tiers.ts` | New: API endpoint wrappers |
| `frontend/src/api/types.ts` | Add `TierDetails`, `TierRequirements` types |
| `frontend/src/pages/kyc/KycTierProgress.tsx` | New: tier progress page |
| `frontend/src/components/shared/KycTierBadge.tsx` | New: tier badge component |
| `frontend/src/App.tsx` | Add `/kyc/tiers` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add KYC Verification link |

### Phase 6: E2E Tests (2 days)

| File | Change |
|------|--------|
| `frontend/e2e/kyc-tiers.spec.ts` | New: ~22 tests, sections 182-186 |

---

## 5. E2E Test Plan (`frontend/e2e/kyc-tiers.spec.ts`)

**Test file**: `frontend/e2e/kyc-tiers.spec.ts`  
**Total tests**: ~22  
**Sections**: 182-186

### Section 182: Tier Query API (4 tests)

1. `GET /v1/kyc/tiers/me returns tier 0 for new user` — Create a fresh user session; GET returns `current_tier: 0`, `tier_name: "Unverified"`.
2. `GET /v1/kyc/tiers/me/requirements/1 shows unmet requirements` — For tier-0 user, returns `unmet: ["email_verified", "phone_verified"]`, `eligible: false`.
3. `GET /v1/kyc/tiers/me/requirements/2 includes tier 1 prerequisites` — Returns unmet list that includes both tier 1 and tier 2 requirements.
4. `GET /v1/kyc/tiers/me returns history after tier change` — After admin override, verify `history` array has one entry with correct `from_tier`, `to_tier`, `reason`.

### Section 183: Tier Upgrade API (5 tests)

1. `POST /v1/kyc/tiers/me/evaluate does not upgrade without prerequisites` — Tier-0 user calls evaluate; stays at tier 0.
2. `POST /v1/kyc/tiers/me/evaluate upgrades to tier 1 when email+phone verified` — Seed `email_verified=true`, `phone_verified=true` on profile; evaluate returns `current_tier: 1`.
3. `POST /v1/kyc/tiers/me/evaluate upgrades to tier 2 after KYC approval` — Create and approve a KYC case for user; evaluate returns `current_tier: 2`.
4. `POST /v1/kyc/tiers/me/evaluate is idempotent` — Call evaluate twice; second call returns same tier, no duplicate history entries.
5. `Tier upgrade generates alert for user` — After upgrade, query alerts for user; verify alert with `event: "kyc.tier.upgraded"`.

### Section 184: Admin Tier Override API (5 tests)

1. `POST /v1/kyc/tiers/admin/{user_sub}/override sets tier directly` — Root overrides Alice to tier 3; verify response `current_tier: 3`.
2. `Admin override with tier > 4 returns 400` — Body `{ tier: 5 }` returns 422 (Pydantic validation).
3. `Admin override with short reason returns 422` — Body `{ tier: 2, reason: "ok" }` fails validation (min 5 chars).
4. `Non-root user cannot override tier` — Alice (USER role) calls override; returns 403.
5. `Admin override creates audit event` — After override, query audit log; verify entry with `event: "kyc.tier.changed"`, `actor_sub` = root.

### Section 185: Feature Gating API (5 tests)

1. `Tier 0 user cannot create DM (requires tier 1)` — POST to create DM returns 403 with `kyc_tier_insufficient` and `required_tier: 1`.
2. `Tier 1 user can create DM` — After upgrading to tier 1, POST to create DM succeeds (200/201).
3. `Tier 1 user cannot create payment method (requires tier 2)` — POST to billing returns 403 with `required_tier: 2`.
4. `Tier 2 user cannot create broadcast session (requires tier 3)` — POST to broadcast returns 403 with `required_tier: 3`.
5. `Feature gating returns upgrade_url in error body` — Verify 403 body contains `upgrade_url: "/kyc"`.

### Section 186: Tier Progress UI (3 tests)

1. `KYC Tier Progress page shows current tier badge` — Navigate to `/kyc/tiers`; verify tier badge displays "Unverified".
2. `Requirements checklist shows met/unmet items` — Verify checklist renders with checkmarks for met requirements and empty circles for unmet.
3. `Evaluate button triggers tier check` — Click "Check Eligibility"; verify API call to `/v1/kyc/tiers/me/evaluate` is made.

### Test Setup

```typescript
const TS = Date.now();
let alicePage: Page;
let rootPage: Page;

test.beforeAll(async ({ browser }) => {
  alicePage = await browser.newPage();
  await injectAuth(alicePage, "alice");
  rootPage = await browser.newPage();
  await injectAuth(rootPage, "root");
});
```

### Edge Cases

| Edge Case | Expected Behavior |
|-----------|-------------------|
| User has tier 3, admin overrides to tier 1 | Downgrade succeeds; history records downgrade; features above tier 1 become gated |
| Multiple KYC cases, one approved one rejected | Tier evaluation uses the approved case |
| KYC case expires after tier upgrade | Tier remains (no automatic downgrade unless KYC-016 monitoring triggers it) |
| Feature flag `kyc_tier_gating_enabled=false` | All tier checks pass; `require_kyc_tier` becomes a no-op |
| Admin overrides to tier 4 without business KYC | Override succeeds (admin bypass); history records reason |

---

## 6. Security Considerations

### 6.1 Authorization

- Tier query endpoints (`/me/*`) require `require_ui_session` — any authenticated user can see their own tier.
- Admin endpoints (`/admin/*`) require `require_root_session` — only root can override tiers or query other users.
- The `require_kyc_tier` dependency runs AFTER `require_ui_session` — unauthenticated requests are rejected before tier checks.

### 6.2 Audit Trail

- Every tier change (automatic or manual) is recorded in `kyc_tier_history` on the user profile AND via `audit_event()`.
- Admin overrides include the admin's `actor_sub` and `reason` in both the history entry and audit log.
- History entries are append-only; the DDB `list_append` expression prevents overwrites.

### 6.3 Race Conditions

- `auto_evaluate_tier` reads current tier, evaluates, and writes atomically per-user. Concurrent calls for the same user may produce duplicate history entries but will converge to the correct tier.
- Feature gating reads tier from DDB on each request. There is no caching — changes take effect immediately.

---

## 7. Rollback Plan

### 7.1 Feature Flag

Set `KYC_TIER_GATING_ENABLED=false` in `.env.local` to disable all tier checks without removing code. The `require_kyc_tier` dependency returns immediately when disabled.

### 7.2 DDB Changes

The `ByKycTier` GSI and new profile fields are additive. Existing code ignores unknown fields. Rollback requires no DDB changes.

### 7.3 Endpoint Removal

Remove `app/routers/kyc_tiers.py` import from `app/main.py` and remove `require_kyc_tier` dependencies from gated endpoints.

---

## Codebase References

> **Verification performed**: 2026-05-29

### Verified (EXISTS in codebase)

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| KYC cases router | `app/routers/kyc_cases.py` | all | VERIFIED (1294 lines, not 1295 as ticket states) |
| KYC cases service | `app/services/kyc_cases.py` | all | VERIFIED (828 lines, not 829 as ticket states) |
| `get_profile()` | `app/services/profiles.py` | 220 | VERIFIED |
| `apply_profile_update()` | `app/services/profiles.py` | 294 | VERIFIED (ticket cites line 163 -- INCORRECT, actual is 294) |
| `AuthenticatedUser` class | `app/auth/deps.py` | 126 | VERIFIED |
| `require_root_session` | `app/auth/deps.py` | 273 | VERIFIED |
| `Role` enum | `app/auth/roles.py` | 8 | VERIFIED |
| `AdminScope` class | `app/auth/roles.py` | 14 | VERIFIED |
| Current admin scopes | `app/auth/roles.py` | 26-30 | VERIFIED: AUTH_SUPPORT, BILLING_SUPPORT, CONTENT_MODERATION, CONTENT_MODERATION_SENIOR |
| KYC settings | `app/core/settings.py` | 1065-1072 | VERIFIED |
| `kyc_cases` DDB table | `scripts/local-ddb-init.py` | 91-96 | VERIFIED |

### Corrections

<!-- NOTE: The ticket states `app/routers/kyc_cases.py` has 1295 lines -- actual count is 1294. -->
<!-- NOTE: The ticket states `app/services/kyc_cases.py` has 829 lines -- actual count is 828. -->
<!-- NOTE: The ticket cites `apply_profile_update()` at line 163 of app/services/profiles.py -- actual line is 294. This is a SIGNIFICANT error. -->

### Not Yet Implemented (requires new code)

| Reference | Expected Location | Status |
|-----------|-------------------|--------|
| `require_kyc_tier()` dependency | `app/auth/deps.py` | NOT FOUND -- new dependency required |
| `KYC_VERIFIER` admin scope | `app/auth/roles.py` | NOT FOUND -- new scope required |
| `app/routers/kyc_tiers.py` | `app/routers/` | NOT FOUND -- new router required |
| `app/services/kyc_tiers.py` | `app/services/` | NOT FOUND -- new service required |
| `kyc_tiers_router` registration | `app/main.py` | NOT FOUND -- needs `app.include_router()` |
| `ByKycTier` GSI on users table | `scripts/local-ddb-init.py` | NOT FOUND -- new GSI required |
| `KYC_TIER_GATING_ENABLED` feature flag | `app/core/settings.py` | NOT FOUND -- new setting required |
| `kyc_tier` profile field | `app/services/profiles.py` | NOT FOUND -- new field required |
| `frontend/src/pages/kyc/KycTierProgressPage.tsx` | `frontend/src/pages/kyc/` | NOT FOUND -- new page required |

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_kyc_tiers.py`

Mock external dependencies with `moto` (DynamoDB) and `unittest.mock`. All tests run without the dev stack.

  - `test_evaluate_tier_unverified`
  - `test_evaluate_tier_basic`
  - `test_evaluate_tier_enhanced`
  - `test_evaluate_tier_full`
  - `test_tier_upgrade_on_component_completion`
  - `test_tier_downgrade_on_expiry`
  - `test_tier_limits_enforcement`
  - `test_get_tier_requirements`

### Integration Tests

  - Component completion triggers automatic tier re-evaluation
  - Transaction limits enforced based on current tier level
  - Tier change creates audit trail entry

### E2E Tests (Playwright)

**File**: `frontend/e2e/kyc-tiers.spec.ts`
**Test count**: 12

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

- **DDB seeds**: Seed `kyc_submissions (tier records)` table with test records in `beforeAll`
- **Test users**: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- **Cleanup**: Tests use unique timestamps/IDs per run to avoid cross-run interference

### CI/Pipeline Considerations

- **Feature flag**: `KYC_TIERS_ENABLED=true` must be set in test environment
- **Serial execution**: E2E tests run with `workers: 1` to avoid shared-state conflicts
- **Retry safety**: All tests are idempotent; retries do not produce duplicate records

## Dependencies & Merge Safety

### Depends On

| Ticket | Title | Why |
|--------|-------|-----|
| KYC-001 | Admin KYC Review Dashboard | Tier status displayed in dashboard |
| KYC-008 | Risk Scoring Engine | Risk score determines verification tier |

### Depended On By

| Ticket | Title | Impact |
|--------|-------|--------|
| KYC-011 | KYC Webhooks & Notifications | Tier changes trigger webhooks |
| KYC-013 | User Self-Service Portal | Users see their current tier and requirements |
| KYC-015 | Business/Corporate KYB | Business accounts have separate tier structure |

### Merge Strategy

**Sequential**

Merge after KYC-001, KYC-008. This ticket depends on tables/services introduced by those tickets.

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
- [ ] All 12 E2E tests pass with `npx playwright test kyc-tiers.spec.ts`
