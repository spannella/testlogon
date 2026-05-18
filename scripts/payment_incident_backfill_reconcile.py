#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from app.core.settings import S

FAILED_PAYMENT_STATUSES = {"payment_failed", "requires_payment_method", "canceled"}


@dataclass(frozen=True)
class Candidate:
    provider: str
    payment_reference: str
    account_id: str
    customer_id: str
    amount: str
    currency: str
    status: str


def collect_failed_payment_candidates(items: list[dict[str, Any]]) -> list[Candidate]:
    out: list[Candidate] = []
    for row in items:
        sk = str(row.get("sk") or "")
        if not sk.startswith("PAY#"):
            continue
        status = str(row.get("status") or "").strip().lower()
        if status not in FAILED_PAYMENT_STATUSES:
            continue
        provider = str(row.get("provider") or "stripe").strip().lower()
        payment_reference = str(row.get("payment_intent_id") or row.get("payment_reference") or sk.removeprefix("PAY#")).strip()
        if not payment_reference:
            continue
        pk = str(row.get("pk") or "")
        account_id = pk.removeprefix("USER#") if pk.startswith("USER#") else (str(row.get("user_sub") or "") or "unknown")
        out.append(
            Candidate(
                provider=provider,
                payment_reference=payment_reference,
                account_id=account_id,
                customer_id=str(row.get("customer_id") or account_id or "unknown"),
                amount=str(row.get("amount") or row.get("amount_cents") or "0"),
                currency=str(row.get("currency") or "usd").lower(),
                status=status,
            )
        )
    return sorted(out, key=lambda c: (c.provider, c.payment_reference, c.account_id))


def build_backfill_report(*, candidates: list[Candidate], incidents: list[dict[str, Any]]) -> dict[str, Any]:
    existing = {
        (
            str(it.get("provider") or "").strip().lower(),
            str(it.get("payment_reference") or it.get("provider_incident_id") or "").strip(),
        )
        for it in incidents
        if str(it.get("incident_type") or "") == "payment_failure"
    }
    missing: list[dict[str, Any]] = []
    for c in candidates:
        if (c.provider, c.payment_reference) in existing:
            continue
        missing.append(
            {
                "provider": c.provider,
                "payment_reference": c.payment_reference,
                "account_id": c.account_id,
                "customer_id": c.customer_id,
                "amount": c.amount,
                "currency": c.currency,
                "status": c.status,
            }
        )
    missing = sorted(missing, key=lambda x: (x["provider"], x["payment_reference"], x["account_id"]))
    return {
        "report_version": 1,
        "candidate_count": len(candidates),
        "existing_count": len(candidates) - len(missing),
        "missing_count": len(missing),
        "missing": missing,
    }


def _stable_backfill_incident_id(provider: str, payment_reference: str) -> str:
    digest = hashlib.sha256(f"{provider}:{payment_reference}".encode("utf-8")).hexdigest()[:16]
    return f"pinc_backfill_{digest}"


def apply_backfill(*, report: dict[str, Any], repo: Any) -> dict[str, Any]:
    applied: list[str] = []
    for row in report.get("missing", []):
        incident_id = _stable_backfill_incident_id(str(row.get("provider")), str(row.get("payment_reference")))
        repo.put_incident(
            {
                "incident_id": incident_id,
                "provider": row["provider"],
                "provider_incident_id": row["payment_reference"],
                "incident_type": "payment_failure",
                "payment_reference": row["payment_reference"],
                "account_id": row["account_id"],
                "customer_id": row["customer_id"],
                "subscription_id": None,
                "order_id": None,
                "amount": row["amount"],
                "currency": row["currency"],
                "status": "failed_initial" if row["status"] == "payment_failed" else "customer_action_required",
                "requires_customer_action": True,
                "customer_action_type": "update_method",
                "response_due_at": None,
                "raw_payload_ref": "backfill:billing_failed_payment",
            }
        )
        repo.append_incident_event(
            incident_id=incident_id,
            event_id=f"backfill:{incident_id}",
            event_type="backfill.payment_failure_created",
            payload=row,
        )
        applied.append(incident_id)
    return {"applied_count": len(applied), "applied_incident_ids": sorted(applied)}


def _scan_all(table: Any, *, limit: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    start_key = None
    while True:
        kwargs: dict[str, Any] = {"Limit": limit}
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = table.scan(**kwargs)
        out.extend(resp.get("Items", []))
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break
    return out


def main() -> None:
    from app.core.tables import T
    from app.services.payment_incidents_store import DynamoPaymentIncidentRepository

    parser = argparse.ArgumentParser(description="PDM-019: backfill/reconcile missing payment incidents from billing failed payments.")
    parser.add_argument("--apply", action="store_true", help="Apply backfill writes.")
    parser.add_argument("--scan-limit", type=int, default=250)
    parser.add_argument("--out", default="", help="Optional output JSON file path.")
    args = parser.parse_args()

    billing_items = _scan_all(T.billing, limit=max(1, args.scan_limit))
    incident_items = _scan_all(T.payment_incidents, limit=max(1, args.scan_limit))

    candidates = collect_failed_payment_candidates(billing_items)
    report = build_backfill_report(candidates=candidates, incidents=incident_items)
    result: dict[str, Any] = {"report": report, "applied": {"applied_count": 0, "applied_incident_ids": []}, "apply_requested": bool(args.apply)}

    if args.apply:
        if not bool(getattr(S, "payment_incidents_backfill_apply_enabled", False)):
            raise SystemExit("PAYMENT_INCIDENTS_BACKFILL_APPLY_ENABLED must be set to apply backfill.")
        repo = DynamoPaymentIncidentRepository()
        result["applied"] = apply_backfill(report=report, repo=repo)

    payload = json.dumps(result, indent=2, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
    print(payload)


if __name__ == "__main__":
    main()
