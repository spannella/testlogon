#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Dict, Optional

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.api_key_capabilities import CANONICAL_API_KEY_CAPABILITIES


def backfill_api_key_capabilities(*, dry_run: bool = True, user_sub: Optional[str] = None) -> Dict[str, int]:
    scanned = 0
    updated = 0
    last_key: Optional[Dict[str, Any]] = None
    while True:
        kwargs: Dict[str, Any] = {"Limit": 200}
        fetch = T.api_keys.scan
        if user_sub:
            fetch = T.api_keys.query
            kwargs["IndexName"] = S.api_keys_user_index
            kwargs["KeyConditionExpression"] = Key("user_sub").eq(user_sub)
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = fetch(**kwargs)
        for item in resp.get("Items", []):
            scanned += 1
            if item.get("capabilities") is not None:
                continue
            if dry_run:
                updated += 1
                continue
            T.api_keys.update_item(
                Key={"key_id": item["key_id"]},
                UpdateExpression="SET capabilities = :caps, updated_at = :now",
                ExpressionAttributeValues={
                    ":caps": list(CANONICAL_API_KEY_CAPABILITIES),
                    ":now": now_ts(),
                },
            )
            updated += 1
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return {"scanned": scanned, "updated": updated}


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Backfill missing API key capability arrays on legacy keys")
    parser.add_argument("--apply", action="store_true", help="Persist updates (default is dry-run)")
    parser.add_argument("--user-sub", default=None, help="Optional user_sub to limit backfill scope")
    args = parser.parse_args()

    result = backfill_api_key_capabilities(dry_run=not args.apply, user_sub=args.user_sub)
    mode = "apply" if args.apply else "dry-run"
    print({"mode": mode, **result})
