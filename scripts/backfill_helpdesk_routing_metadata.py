#!/usr/bin/env python3
from __future__ import annotations

import os

from app.core.aws import ddb

DDB_CONVERSATIONS = os.getenv("DDB_CONVERSATIONS", "Conversations")


def _coerce_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def main() -> None:
    table = ddb.Table(DDB_CONVERSATIONS)
    scanned = 0
    updated = 0
    last_key = None

    while True:
        kwargs = {}
        if last_key is not None:
            kwargs["ExclusiveStartKey"] = last_key
        resp = table.scan(**kwargs)
        items = resp.get("Items", [])
        scanned += len(items)

        for item in items:
            conversation_id = item.get("conversation_id")
            if not conversation_id:
                continue

            routing_mode = item.get("routing_mode") or "standard"
            routing_state = item.get("routing_state") or ("awaiting_agent" if routing_mode == "helpdesk_bridge" else "none")
            group_id = item.get("routing_group_id") or ""
            active_agent_user_id = item.get("active_agent_user_id") or ""
            active_agent_claimed_at = _coerce_int(item.get("active_agent_claimed_at"), 0)
            last_failover_at = _coerce_int(item.get("last_failover_at"), 0)
            assignment_version = _coerce_int(item.get("assignment_version"), 0)
            no_agents_notice_sent_at = _coerce_int(item.get("no_agents_notice_sent_at"), 0)
            state_group_pk = item.get("routing_state_group_pk") or f"{routing_state}#{group_id}"
            state_group_sk = item.get("routing_state_group_sk") or conversation_id

            expected = {
                "routing_mode": routing_mode,
                "routing_group_id": group_id,
                "routing_state": routing_state,
                "active_agent_user_id": active_agent_user_id,
                "active_agent_claimed_at": active_agent_claimed_at,
                "last_failover_at": last_failover_at,
                "assignment_version": assignment_version,
                "no_agents_notice_sent_at": no_agents_notice_sent_at,
                "routing_state_group_pk": state_group_pk,
                "routing_state_group_sk": state_group_sk,
            }

            needs_update = any(item.get(k) != v for k, v in expected.items())
            if not needs_update:
                continue

            table.update_item(
                Key={"conversation_id": conversation_id},
                UpdateExpression=(
                    "SET routing_mode=:rm, routing_group_id=:gid, routing_state=:rs, "
                    "active_agent_user_id=:auid, active_agent_claimed_at=:ac, "
                    "last_failover_at=:lf, assignment_version=:av, "
                    "no_agents_notice_sent_at=:na, routing_state_group_pk=:sgpk, "
                    "routing_state_group_sk=:sgsk"
                ),
                ExpressionAttributeValues={
                    ":rm": routing_mode,
                    ":gid": group_id,
                    ":rs": routing_state,
                    ":auid": active_agent_user_id,
                    ":ac": active_agent_claimed_at,
                    ":lf": last_failover_at,
                    ":av": assignment_version,
                    ":na": no_agents_notice_sent_at,
                    ":sgpk": state_group_pk,
                    ":sgsk": state_group_sk,
                },
            )
            updated += 1

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    print(f"scanned={scanned} updated={updated}")


if __name__ == "__main__":
    main()
