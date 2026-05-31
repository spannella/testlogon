#!/usr/bin/env python3
"""E2E seed helper for FIN-017 bulk payout/refund tools.

Writes pending payout / refund-request rows directly to DynamoDB so the
bulk-processing E2E spec has deterministic items to batch over.

Usage:
    python3 scripts/e2e_seed_bulk_payouts.py payout <user_id> <amount_cents>
    python3 scripts/e2e_seed_bulk_payouts.py refund <user_id> <amount_cents>

Prints the created ref_id (payout_id or refund_request_id) to stdout.
Must be run with the same env as the backend (sourced .env.local) so the DDB
endpoint + credentials resolve.
"""
from __future__ import annotations

import sys
import uuid

from app.core.tables import T
from app.core.time import now_ts


def seed_payout(user_id: str, amount_cents: int) -> str:
    payout_id = f"payout_{uuid.uuid4().hex}"
    now = now_ts()
    T.creator_payouts.put_item(Item={
        "payout_id": payout_id,
        "user_id": user_id,
        "amount_cents": int(amount_cents),
        "method": "bank_transfer",
        "status": "requested",
        "created_at": now,
        "updated_at": now,
        "notes": "e2e bulk seed",
        "reject_reason": "",
        "approved_by": "",
    })
    return payout_id


def seed_refund(user_id: str, amount_cents: int) -> str:
    request_id = f"rr_{uuid.uuid4().hex[:12]}"
    now = now_ts()
    T.refund_requests.put_item(Item={
        "pk": f"REFUND#{request_id}",
        "sk": "META",
        "refund_request_id": request_id,
        "requester_user_id": user_id,
        "requester_scope": f"USER#{user_id}",
        "transaction_entry_id": f"txn_{uuid.uuid4().hex[:8]}",
        "transaction_type": "purchase",
        "original_amount_cents": int(amount_cents),
        "amount_cents": int(amount_cents),
        "currency": "USD",
        "reason": "e2e bulk seed",
        "status": "pending",
        "status_scope": "STATUS#pending",
        "admin_user_id": "",
        "admin_notes": "",
        "stripe_refund_id": "",
        "created_at": now,
        "updated_at": now,
        "completed_at": 0,
    })
    return request_id


def main() -> None:
    if len(sys.argv) != 4:
        sys.stderr.write(
            "usage: e2e_seed_bulk_payouts.py <payout|refund> <user_id> <amount_cents>\n"
        )
        sys.exit(2)
    kind, user_id, amount = sys.argv[1], sys.argv[2], int(sys.argv[3])
    if kind == "payout":
        print(seed_payout(user_id, amount))
    elif kind == "refund":
        print(seed_refund(user_id, amount))
    else:
        sys.stderr.write(f"unknown kind: {kind}\n")
        sys.exit(2)


if __name__ == "__main__":
    main()
