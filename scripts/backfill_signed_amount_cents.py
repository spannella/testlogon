#!/usr/bin/env python3
"""Backfill ``signed_amount_cents`` onto legacy billing-ledger rows.

D1 / docs/CROSS_TICKET_AUDIT.md §A4: ``new_ledger_entry`` now stamps a
``signed_amount_cents`` (credit +, charge/debit -) at write time. Pre-existing
ledger rows written before that change lack the field. This one-time, idempotent
backfill scans the billing table and stamps any LEDGER#* row missing
``signed_amount_cents``, deriving it from the stored ``type`` + unsigned
``amount_cents`` via the canonical :data:`LEDGER_ENTRY_SIGN` map.

DynamoDB is schemaless — no table migration is needed; we simply set the new
attribute on existing items.

Usage:
    python3 scripts/backfill_signed_amount_cents.py --dry-run
    python3 scripts/backfill_signed_amount_cents.py
"""
from __future__ import annotations

import argparse
from typing import Any, Dict, Optional

from app.core.tables import T
from app.services.billing_shared import derive_signed_amount_cents


def _is_ledger_row(item: Dict[str, Any]) -> bool:
    sk = item.get("sk")
    return isinstance(sk, str) and sk.startswith("LEDGER#")


def _key_for(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Reconstruct the primary key for a billing item. The billing table is
    keyed (pk, sk)."""
    if "pk" in item and "sk" in item:
        return {"pk": item["pk"], "sk": item["sk"]}
    return None


def run(*, dry_run: bool) -> Dict[str, int]:
    table = T.billing
    scanned = 0
    eligible = 0
    stamped = 0
    skipped_no_key = 0

    scan_kwargs: Dict[str, Any] = {}
    while True:
        resp = table.scan(**scan_kwargs)
        for item in resp.get("Items", []):
            scanned += 1
            if not _is_ledger_row(item):
                continue
            if "signed_amount_cents" in item and item["signed_amount_cents"] is not None:
                # Idempotent: already stamped.
                continue
            eligible += 1
            entry_type = str(item.get("type", ""))
            amount_cents = int(item.get("amount_cents", 0))
            signed = derive_signed_amount_cents(entry_type, amount_cents)
            key = _key_for(item)
            if key is None:
                skipped_no_key += 1
                continue
            if dry_run:
                print(
                    f"[dry-run] would stamp {key['sk']} type={entry_type!r} "
                    f"amount_cents={amount_cents} -> signed_amount_cents={signed:+d}"
                )
            else:
                table.update_item(
                    Key=key,
                    UpdateExpression="SET signed_amount_cents = :v",
                    # Idempotency guard: only write if still missing.
                    ConditionExpression=(
                        "attribute_not_exists(signed_amount_cents) "
                        "OR signed_amount_cents = :null"
                    ),
                    ExpressionAttributeValues={":v": signed, ":null": None},
                )
            stamped += 1

        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        scan_kwargs["ExclusiveStartKey"] = lek

    summary = {
        "scanned": scanned,
        "eligible": eligible,
        "stamped": stamped,
        "skipped_no_key": skipped_no_key,
    }
    print(
        f"{'[dry-run] ' if dry_run else ''}done: scanned={scanned} "
        f"ledger_rows_missing_field={eligible} stamped={stamped} "
        f"skipped_no_key={skipped_no_key}"
    )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would change without writing.",
    )
    args = parser.parse_args()
    run(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
