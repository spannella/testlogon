"""Organization billing service (ENTERPRISE-003)."""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import ddb_del, ddb_get, ddb_put, ddb_query_pk, ddb_update


def org_pk(org_id: str) -> str:
    return f"ORG#{org_id}"


def add_org_payment_method(
    org_id: str,
    user_sub: str,
    provider: str = "stripe",
    pm_type: str = "card",
    last4: str = "4242",
    brand: str = "visa",
    exp_month: int = 12,
    exp_year: int = 2027,
    billing_email: str = "",
) -> Dict[str, Any]:
    from app.services.org_service import assert_org_membership
    assert_org_membership(org_id, user_sub, min_role="owner")

    pm_id = f"pm_org_{uuid.uuid4().hex[:16]}"
    now = now_ts()
    item: Dict[str, Any] = {
        "pk": org_pk(org_id),
        "sk": f"PM#{pm_id}",
        "payment_method_id": pm_id,
        "provider": provider,
        "type": pm_type,
        "last4": last4,
        "brand": brand,
        "exp_month": exp_month,
        "exp_year": exp_year,
        "billing_email": billing_email,
        "added_by": user_sub,
        "created_at": now,
    }
    ddb_put(T.billing, item)

    existing_billing = ddb_get(T.billing, org_pk(org_id), "BILLING")
    if not existing_billing:
        ddb_put(T.billing, {
            "pk": org_pk(org_id),
            "sk": "BILLING",
            "default_payment_method_id": pm_id,
            "created_at": now,
        })
    return item


def list_org_payment_methods(org_id: str) -> List[Dict[str, Any]]:
    items = ddb_query_pk(T.billing, org_pk(org_id))
    return [i for i in items if i.get("sk", "").startswith("PM#")]


def set_org_default_payment_method(org_id: str, user_sub: str, pm_id: str) -> None:
    from app.services.org_service import assert_org_membership
    assert_org_membership(org_id, user_sub, min_role="owner")

    pm = ddb_get(T.billing, org_pk(org_id), f"PM#{pm_id}")
    if not pm:
        raise ValueError("Payment method not found")

    existing = ddb_get(T.billing, org_pk(org_id), "BILLING")
    if existing:
        ddb_update(
            T.billing,
            org_pk(org_id),
            "BILLING",
            "SET default_payment_method_id = :pm",
            {":pm": pm_id},
        )
    else:
        ddb_put(T.billing, {
            "pk": org_pk(org_id),
            "sk": "BILLING",
            "default_payment_method_id": pm_id,
            "created_at": now_ts(),
        })


def remove_org_payment_method(org_id: str, user_sub: str, pm_id: str) -> None:
    from app.services.org_service import assert_org_membership
    assert_org_membership(org_id, user_sub, min_role="owner")
    ddb_del(T.billing, org_pk(org_id), f"PM#{pm_id}")


def get_org_billing_history(org_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    items = ddb_query_pk(T.billing, org_pk(org_id))
    ledger = [i for i in items if i.get("sk", "").startswith("LEDGER#")]
    ledger.sort(key=lambda i: i.get("created_at", 0), reverse=True)
    return ledger[:limit]


def record_org_ledger_entry(
    org_id: str,
    user_sub: str,
    amount_cents: int,
    reason: str,
    payment_method_id: str = "",
) -> Dict[str, Any]:
    entry_id = f"ledger_{uuid.uuid4().hex[:16]}"
    now = now_ts()
    item: Dict[str, Any] = {
        "pk": org_pk(org_id),
        "sk": f"LEDGER#{now}#{entry_id}",
        "entry_id": entry_id,
        "amount_cents": amount_cents,
        "reason": reason,
        "user_sub": user_sub,
        "payment_method_id": payment_method_id,
        "created_at": now,
    }
    ddb_put(T.billing, item)
    return item
