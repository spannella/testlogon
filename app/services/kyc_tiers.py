"""KYC tier management — progressive verification levels."""
from __future__ import annotations

from typing import Any

from app.core.tables import T
from app.core.time import now_ts
from app.core.settings import S
from app.services.alerts import audit_event, write_alert

KYC_TIER_NAMES = {
    0: "Unverified",
    1: "Basic",
    2: "ID Verified",
    3: "Enhanced",
    4: "Institutional",
}
KYC_TIER_MAX = 4

TIER_REQUIREMENTS: dict[int, set[str]] = {
    1: {"email_verified", "phone_verified"},
    2: {"tier_1", "kyc_case_approved"},
    3: {"tier_2", "proof_of_address", "verification_call", "questionnaire_completed"},
    4: {"tier_3", "business_kyc_approved", "api_access_approved"},
}


def get_user_kyc_tier(user_sub: str) -> int:
    """Return current KYC tier for user (0-4). Defaults to 0 if not set."""
    if not S.kyc_tier_gating_enabled:
        return KYC_TIER_MAX  # When gating disabled, treat everyone as max tier
    item = T.users.get_item(Key={"user_sub": user_sub}).get("Item")
    if not item:
        return 0
    return int(item.get("kyc_tier", 0))


def get_tier_details(user_sub: str) -> dict[str, Any]:
    """Return full tier info including history and requirements."""
    item = T.users.get_item(Key={"user_sub": user_sub}).get("Item")
    tier = int((item or {}).get("kyc_tier", 0))
    history_raw = (item or {}).get("kyc_tier_history", [])
    # Coerce DynamoDB Decimal values in history entries to plain ints
    history = []
    for entry in history_raw:
        coerced: dict[str, Any] = {}
        for k, v in entry.items():
            if isinstance(v, (int, float)):
                coerced[k] = int(v)
            else:
                coerced[k] = v
        history.append(coerced)
    updated_at_raw = (item or {}).get("kyc_tier_updated_at")
    return {
        "user_sub": user_sub,
        "current_tier": tier,
        "tier_name": KYC_TIER_NAMES.get(tier, "Unknown"),
        "updated_at": int(updated_at_raw) if updated_at_raw is not None else None,
        "history": history,
    }


def check_tier_requirements(user_sub: str, target_tier: int) -> dict[str, Any]:
    """Check which requirements are met/unmet for a target tier."""
    profile = T.users.get_item(Key={"user_sub": user_sub}).get("Item", {})
    current_tier = int(profile.get("kyc_tier", 0))

    met: set[str] = set()
    unmet: set[str] = set()

    # Tier 1 checks
    if profile.get("email_verified"):
        met.add("email_verified")
    else:
        unmet.add("email_verified")

    if profile.get("phone_verified"):
        met.add("phone_verified")
    else:
        unmet.add("phone_verified")

    # Tier 2 checks
    if current_tier >= 1:
        met.add("tier_1")
    else:
        unmet.add("tier_1")

    # Check for approved KYC case
    from app.services.kyc_cases import STORE as KYC_STORE
    cases = KYC_STORE.list_cases_by_owner(user_sub=user_sub, limit=10)
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

    required_for_target: set[str] = set()
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
    request: Any = None,
) -> dict[str, Any]:
    """Upgrade (or set) user's KYC tier. Returns updated tier details."""
    if new_tier < 0 or new_tier > KYC_TIER_MAX:
        raise ValueError(f"Invalid tier: {new_tier}")

    item = T.users.get_item(Key={"user_sub": user_sub}).get("Item", {})
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
        Key={"user_sub": user_sub},
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
        target_user_sub=user_sub,
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


def auto_evaluate_tier(user_sub: str, *, request: Any = None) -> dict[str, Any]:
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


def list_users_by_tier(tier: int, limit: int = 100) -> list[dict[str, Any]]:
    """List users with a specific KYC tier using the ByKycTier GSI."""
    resp = T.users.query(
        IndexName="ByKycTier",
        KeyConditionExpression="kyc_tier = :tier",
        ExpressionAttributeValues={":tier": tier},
        ScanIndexForward=False,
        Limit=min(limit, 100),
    )
    items = resp.get("Items", [])
    return [
        {
            "user_sub": i.get("user_sub", ""),
            "kyc_tier": int(i.get("kyc_tier", 0)),
            "kyc_tier_updated_at": int(i["kyc_tier_updated_at"]) if i.get("kyc_tier_updated_at") is not None else None,
            "display_name": i.get("display_name"),
        }
        for i in items
    ]
