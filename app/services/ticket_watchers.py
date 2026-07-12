"""CAS-007 — Ticket watchers / CC list.

Allows users to subscribe to ticket notifications without owning or being
assigned to a ticket.  Watcher subs are stored in a dedicated
`crm_cases_watchers` table (provisioned by CAS-001) and exposed via three
endpoints added to the tickets router (declared in app/routers/tickets.py).

All paths are gated on ``S.crm_cases_enabled``.  When the flag is off the
table is never written and no endpoints are registered.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts


def _watcher_sk(watcher_sub: str) -> str:
    return f"WATCHER#{watcher_sub}"


@dataclass
class TicketWatcherStore:
    _table: Any = field(default_factory=lambda: T.crm_cases_watchers)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_watcher(self, *, ticket_id: str, watcher_sub: str, actor_sub: str) -> dict[str, Any]:
        """Add *watcher_sub* to the CC list for *ticket_id*.

        Idempotent: if the watcher row already exists it is returned unchanged.
        """
        ts = now_ts()
        key = {"ticket_id": ticket_id, "sk": _watcher_sk(watcher_sub)}
        existing = self._table.get_item(Key=key).get("Item")
        if existing:
            return self._item_to_out(existing)
        item = {
            **key,
            "watcher_sub": watcher_sub,
            "added_by_sub": actor_sub,
            "created_at": ts,
        }
        self._table.put_item(Item=item)
        return self._item_to_out(item)

    def remove_watcher(self, *, ticket_id: str, watcher_sub: str) -> bool:
        """Remove *watcher_sub* from the CC list.  Returns True if the row existed."""
        key = {"ticket_id": ticket_id, "sk": _watcher_sk(watcher_sub)}
        existing = self._table.get_item(Key=key).get("Item")
        if not existing:
            return False
        self._table.delete_item(Key=key)
        return True

    def list_watchers(self, *, ticket_id: str) -> list[dict[str, Any]]:
        """Return all watcher rows for a given ticket."""
        resp = self._table.query(
            KeyConditionExpression="ticket_id = :tid AND begins_with(sk, :prefix)",
            ExpressionAttributeValues={":tid": ticket_id, ":prefix": "WATCHER#"},
        )
        return [self._item_to_out(item) for item in resp.get("Items", [])]

    def list_tickets_for_watcher(self, *, watcher_sub: str) -> list[str]:
        """Return all ticket_ids that *watcher_sub* is watching (via ByWatcher GSI)."""
        resp = self._table.query(
            IndexName="ByWatcher",
            KeyConditionExpression="watcher_sub = :ws",
            ExpressionAttributeValues={":ws": watcher_sub},
            ScanIndexForward=False,
        )
        return [item["ticket_id"] for item in resp.get("Items", []) if item.get("ticket_id")]

    def get_watcher_subs(self, *, ticket_id: str) -> list[str]:
        """Convenience: return only the list of watcher_sub strings."""
        return [w["watcher_sub"] for w in self.list_watchers(ticket_id=ticket_id)]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _item_to_out(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "ticket_id": item.get("ticket_id", ""),
            "watcher_sub": item.get("watcher_sub", ""),
            "added_by_sub": item.get("added_by_sub"),
            "created_at": int(item.get("created_at", 0) or 0),
        }


WATCHER_STORE = TicketWatcherStore()
