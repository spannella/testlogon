#!/usr/bin/env python3
"""
E2E moderation-state reset (MOD/DMCA test isolation).

The dmca-takedown / moderation specs accumulate upheld DMCA claims and, once the
per-user strike threshold is crossed, the policy engine BANS the target user in
account_state. That ban (and the accumulated claims) persist in DDB-Local across
runs, so a later run — or any spec that posts as that user (e.g. post-hide) — gets
403 'account is banned' on POST /posts. This makes the run order-dependent.

This script restores a clean slate for the given user(s):
  1. clears any account_state ban  (status -> active, drop ban_until)
  2. deletes DMCA claims targeting the user (resets the strike count to 0)

Idempotent + safe to call from a spec's beforeAll. Loads .env.local FIRST so the
app table resources resolve to DDB-Local (not real AWS).

Usage: e2e_moderation_reset.py <user_sub> [<user_sub> ...]
"""
import os
import sys
from pathlib import Path

_env = Path(__file__).with_name(".env.local")
if _env.exists():
    for line in _env.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

from boto3.dynamodb.conditions import Key  # noqa: E402
from app.core.tables import T  # noqa: E402


def _clear_ban(user_sub: str) -> str:
    try:
        item = T.account_state.get_item(Key={"user_sub": user_sub}).get("Item") or {}
    except Exception as exc:  # table may not exist yet -> nothing to clear
        return f"account_state-skip({exc.__class__.__name__})"
    if not item:
        return "account_state-none"
    T.account_state.update_item(
        Key={"user_sub": user_sub},
        UpdateExpression="SET #s=:a REMOVE ban_until",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":a": "active"},
    )
    return f"account_state-cleared(was={item.get('status')})"


def _purge_claims(user_sub: str) -> int:
    deleted = 0
    start = None
    while True:
        kwargs = {
            "IndexName": "ByTargetUserCreatedAt",
            "KeyConditionExpression": Key("target_user_id").eq(user_sub),
            "Limit": 100,
        }
        if start:
            kwargs["ExclusiveStartKey"] = start
        try:
            resp = T.dmca_claims.query(**kwargs)
        except Exception:
            # fall back to a scan+filter if the GSI is unavailable
            resp = T.dmca_claims.scan()
            for it in resp.get("Items", []):
                if it.get("target_user_id") == user_sub:
                    T.dmca_claims.delete_item(Key={"claim_id": it["claim_id"]})
                    deleted += 1
            return deleted
        for it in resp.get("Items", []):
            T.dmca_claims.delete_item(Key={"claim_id": it["claim_id"]})
            deleted += 1
        start = resp.get("LastEvaluatedKey")
        if not start:
            break
    return deleted


def main() -> None:
    users = sys.argv[1:] or ["e2e_bob@test.local"]
    for u in users:
        ban = _clear_ban(u)
        claims = _purge_claims(u)
        print(f"reset {u}: {ban}, dmca_claims_deleted={claims}")


if __name__ == "__main__":
    main()
