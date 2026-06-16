"""CRM Workflow Record Fetcher — WFL-005.

Per-module helpers for fetching records that workflow rules are evaluated
against. Used by the scheduler tick functions (on_schedule / on_time_elapsed).
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def fetch_module_records(
    module: str,
    *,
    limit: int = 100,
) -> list[dict]:
    """Return up to `limit` records for the given module.

    Returns [] for unrecognised modules. Never raises.
    """
    try:
        if module == "ticket":
            return _fetch_tickets(limit=limit)
        if module == "contact":
            return _fetch_contacts(limit=limit)
        if module == "order":
            return _fetch_orders(limit=limit)
        logger.debug("crm_workflow record_fetcher: unsupported module=%s", module)
        return []
    except Exception as exc:
        logger.warning(
            "crm_workflow record_fetcher: fetch failed module=%s: %s",
            module,
            exc,
            exc_info=True,
        )
        return []


def fetch_single_record(module: str, record_id: str) -> dict | None:
    """Return a single record by module + record_id, or None if not found."""
    try:
        if module == "ticket":
            return _fetch_single_ticket(record_id)
        if module == "contact":
            return _fetch_single_contact(record_id)
        return None
    except Exception as exc:
        logger.warning(
            "crm_workflow record_fetcher: single fetch failed module=%s record_id=%s: %s",
            module,
            record_id,
            exc,
            exc_info=True,
        )
        return None


# ---------------------------------------------------------------------------
# Module-specific fetchers
# ---------------------------------------------------------------------------

def _fetch_tickets(*, limit: int = 100) -> list[dict]:
    """Fetch up to `limit` tickets system-wide across all statuses."""
    from app.services.tickets import TicketStore
    from app.core.tables import T

    store = TicketStore(T.tickets)
    # list_tickets without owner_sub does system-wide listing
    result = store.list_tickets(limit=limit, status=None)
    return result.get("tickets", [])


def _fetch_single_ticket(ticket_id: str) -> dict | None:
    """Fetch a single ticket by ticket_id."""
    from app.services.tickets import TicketStore
    from app.core.tables import T

    store = TicketStore(T.tickets)
    return store.get_ticket(ticket_id)


def _fetch_contacts(*, limit: int = 100) -> list[dict]:
    """Fetch up to `limit` contacts system-wide (system-level scan)."""
    from app.core.tables import T

    items: list[dict] = []
    # Contacts have PK owner_id / SK contact_id — scan is the only option
    resp = T.contacts.scan(Limit=limit)
    items.extend(resp.get("Items", []))
    return items


def _fetch_single_contact(contact_id: str) -> dict | None:
    """Scan for a contact with the given contact_id (linear scan — admin path only)."""
    from app.core.tables import T
    from boto3.dynamodb.conditions import Attr

    resp = T.contacts.scan(
        FilterExpression=Attr("contact_id").eq(contact_id),
        Limit=10,
    )
    items = resp.get("Items", [])
    return items[0] if items else None


def _fetch_orders(*, limit: int = 100) -> list[dict]:
    """Fetch up to `limit` orders (placeholder — T.orders already exists)."""
    from app.core.tables import T

    resp = T.orders.scan(Limit=limit)
    return resp.get("Items", [])
