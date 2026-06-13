"""CAS-011 — Case-to-case relationship links.

Stores directed, typed links between tickets in the `crm_cases_links` table
provisioned by CAS-001.  Supported link types:

* ``duplicate``  — this ticket duplicates *related_ticket_id*
* ``blocks``     — this ticket blocks *related_ticket_id*
* ``relates_to`` — this ticket is related to *related_ticket_id*

All paths gated on ``S.crm_cases_enabled``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

_LINK_TYPES = frozenset({"duplicate", "blocks", "relates_to"})


def _link_sk(related_ticket_id: str) -> str:
    return f"LINK#{related_ticket_id}"


@dataclass
class TicketLinkStore:
    _table: Any = field(default_factory=lambda: T.crm_cases_links)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_link(
        self,
        *,
        ticket_id: str,
        related_ticket_id: str,
        link_type: str,
        created_by_sub: str,
    ) -> dict[str, Any]:
        """Create a directed link from *ticket_id* → *related_ticket_id*.

        Raises ``ValueError`` if *link_type* is not one of the allowed values.
        Idempotent: if the exact link already exists it is returned as-is.
        """
        if link_type not in _LINK_TYPES:
            raise ValueError(f"invalid link_type: {link_type!r}; must be one of {sorted(_LINK_TYPES)}")
        if ticket_id == related_ticket_id:
            raise ValueError("ticket_id and related_ticket_id must be different")

        ts = now_ts()
        key = {"ticket_id": ticket_id, "sk": _link_sk(related_ticket_id)}
        existing = self._table.get_item(Key=key).get("Item")
        if existing:
            return self._item_to_out(existing)

        item = {
            **key,
            "related_ticket_id": related_ticket_id,
            "link_type": link_type,
            "created_by_sub": created_by_sub,
            "created_at": ts,
        }
        self._table.put_item(Item=item)
        return self._item_to_out(item)

    def delete_link(self, *, ticket_id: str, related_ticket_id: str) -> bool:
        """Remove the link from *ticket_id* → *related_ticket_id*.  Returns True if it existed."""
        key = {"ticket_id": ticket_id, "sk": _link_sk(related_ticket_id)}
        existing = self._table.get_item(Key=key).get("Item")
        if not existing:
            return False
        self._table.delete_item(Key=key)
        return True

    def list_links(self, *, ticket_id: str) -> list[dict[str, Any]]:
        """Return all links originating from *ticket_id* (forward direction)."""
        resp = self._table.query(
            KeyConditionExpression="ticket_id = :tid AND begins_with(sk, :prefix)",
            ExpressionAttributeValues={":tid": ticket_id, ":prefix": "LINK#"},
        )
        return [self._item_to_out(item) for item in resp.get("Items", [])]

    def list_reverse_links(self, *, ticket_id: str) -> list[dict[str, Any]]:
        """Return all links pointing TO *ticket_id* (reverse direction via ByRelated GSI)."""
        resp = self._table.query(
            IndexName="ByRelated",
            KeyConditionExpression="related_ticket_id = :rtid",
            ExpressionAttributeValues={":rtid": ticket_id},
            ScanIndexForward=False,
        )
        return [self._item_to_out(item) for item in resp.get("Items", [])]

    def list_all_links(self, *, ticket_id: str) -> list[dict[str, Any]]:
        """Return forward + reverse links in a single combined list."""
        forward = self.list_links(ticket_id=ticket_id)
        reverse = self.list_reverse_links(ticket_id=ticket_id)
        seen: set[tuple[str, str]] = set()
        out: list[dict[str, Any]] = []
        for link in forward + reverse:
            key_tuple = (link["ticket_id"], link["related_ticket_id"])
            if key_tuple not in seen:
                seen.add(key_tuple)
                out.append(link)
        return out

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _item_to_out(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "ticket_id": item.get("ticket_id", ""),
            "related_ticket_id": item.get("related_ticket_id", ""),
            "link_type": item.get("link_type", ""),
            "created_by_sub": item.get("created_by_sub"),
            "created_at": int(item.get("created_at", 0) or 0),
        }


LINK_STORE = TicketLinkStore()
