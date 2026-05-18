#!/usr/bin/env python3
from __future__ import annotations

import argparse
from typing import Dict, Any

from app.routers import messaging
from app.services.messaging_thread_backfill import run_thread_backfill_for_conversation, ThreadBackfillStats


def _iter_conversation_ids() -> list[str]:
    query_kwargs: Dict[str, Any] = {
        "ProjectionExpression": "conversation_id",
    }
    ids: set[str] = set()
    while True:
        resp = messaging.tbl_msgs.scan(**query_kwargs)
        for item in resp.get("Items", []):
            cid = str(item.get("conversation_id") or "").strip()
            if cid:
                ids.add(cid)
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        query_kwargs["ExclusiveStartKey"] = lek
    return sorted(ids)


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill and reconcile message reply threads.")
    parser.add_argument("--conversation-id", default="", help="Reconcile only one conversation id.")
    parser.add_argument("--max-conversations", type=int, default=0, help="Optional cap for resumable runs.")
    args = parser.parse_args()

    if args.conversation_id:
        conversation_ids = [args.conversation_id]
    else:
        conversation_ids = _iter_conversation_ids()
    if args.max_conversations and args.max_conversations > 0:
        conversation_ids = conversation_ids[: args.max_conversations]

    totals = ThreadBackfillStats()
    for cid in conversation_ids:
        stats = run_thread_backfill_for_conversation(cid)
        totals.conversations_scanned += stats.conversations_scanned
        totals.eligible_roots += stats.eligible_roots
        totals.threads_created += stats.threads_created
        totals.messages_updated += stats.messages_updated
        print(
            f"[conversation={cid}] eligible_roots={stats.eligible_roots} "
            f"threads_created={stats.threads_created} messages_updated={stats.messages_updated}"
        )

    print(
        "Backfill complete: "
        f"conversations_scanned={totals.conversations_scanned} "
        f"eligible_roots={totals.eligible_roots} "
        f"threads_created={totals.threads_created} "
        f"messages_updated={totals.messages_updated}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
