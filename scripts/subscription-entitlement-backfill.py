from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone

from app.core.tables import T
from app.services.subscription_entitlement_backfill import (
    apply_subscription_entitlement_backfill,
    plan_subscription_entitlement_backfill,
    rollback_subscription_entitlement_backfill,
)


def _load_active_subscriptions() -> list[dict]:
    resp = T.subscriptions.scan()
    items = list(resp.get("Items", []))
    return [
        it
        for it in items
        if str(it.get("sk") or "") == "META" and str(it.get("pk") or "").startswith("SUB#") and str(it.get("status") or "").lower() in {"active", "trialing"}
    ]


def _load_plans() -> dict[str, dict]:
    resp = T.subscriptions.scan()
    items = list(resp.get("Items", []))
    out: dict[str, dict] = {}
    for it in items:
        if str(it.get("sk") or "") == "META" and str(it.get("pk") or "").startswith("PLAN#"):
            out[str(it.get("plan_id") or "")] = it
    return out


def _load_existing_entitlements() -> list[dict]:
    return list(T.entitlements.scan().get("Items", []))


def main() -> None:
    parser = argparse.ArgumentParser(description="CCE-067 subscription entitlement backfill")
    parser.add_argument("--mode", choices=["dry-run", "apply", "rollback"], default="dry-run")
    parser.add_argument("--batch-id", default=f"sub-backfill-{int(datetime.now(timezone.utc).timestamp())}")
    args = parser.parse_args()

    if args.mode == "rollback":
        out = rollback_subscription_entitlement_backfill(args.batch_id)
        print(json.dumps(out, indent=2, sort_keys=True))
        return

    report = plan_subscription_entitlement_backfill(
        subscriptions=_load_active_subscriptions(),
        plans_by_id=_load_plans(),
        existing_entitlements=_load_existing_entitlements(),
        batch_id=args.batch_id,
    )

    if args.mode == "dry-run":
        print(json.dumps({k: v for k, v in report.items() if k != "operations"}, indent=2, sort_keys=True))
        return

    applied = apply_subscription_entitlement_backfill(report)
    output = {k: v for k, v in report.items() if k != "operations"}
    output["apply_result"] = {"batch_id": applied.batch_id, "applied": applied.applied, "skipped": applied.skipped}
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
