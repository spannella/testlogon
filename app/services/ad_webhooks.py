"""Ad platform webhook event dispatch (ADS-011 / GAP-0055).

Thin dispatch adapter that REUSES the existing general-purpose webhook
infrastructure in :mod:`app.services.webhook_service`. Callers in the ad
billing / campaign lifecycle import and call :func:`emit_ad_event`; this module
validates the event type and dispatches via the existing signed, retried
delivery pipeline (``dispatch_webhook_event``).

This mirrors the pattern in :mod:`app.services.kyc_webhooks` (``emit_kyc_event``).

No new DynamoDB tables: ad webhook endpoints and deliveries use the existing
``webhook_endpoints`` and ``webhook_deliveries`` tables. The ``ad.`` event-type
namespace prefix provides partition isolation. ``emit_ad_event`` is best-effort
and never raises, so a dispatch failure can never break charge or campaign
processing.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from app.services.webhook_service import (
    AD_WEBHOOK_EVENT_TYPES,
    dispatch_webhook_event,
)

logger = logging.getLogger(__name__)

# Re-export the canonical ad event-type allowlist for callers/tests.
AD_EVENT_TYPES: Dict[str, str] = dict(AD_WEBHOOK_EVENT_TYPES)


def list_ad_event_types() -> List[Dict[str, str]]:
    """Return the canonical list of ad webhook event types + descriptions."""
    return [
        {"event_type": k, "description": v}
        for k, v in sorted(AD_EVENT_TYPES.items())
    ]


def is_ad_event_type(event_type: str) -> bool:
    return event_type in AD_EVENT_TYPES


def emit_ad_event(
    event_type: str,
    account_owner_sub: str,
    data: Dict[str, Any],
) -> List[str]:
    """Dispatch an ad-platform webhook event. Best-effort; never raises.

    Args:
        event_type: One of the ``ad.*`` types in ``AD_WEBHOOK_EVENT_TYPES``.
        account_owner_sub: ``user_sub`` of the advertiser account owner; the
            dispatcher only enqueues deliveries for that user's subscribed
            endpoints.
        data: Flat JSON-serializable payload for the event ``data`` field.

    Returns:
        List of created delivery IDs (empty on unknown event, missing owner,
        no subscribed endpoints, or any dispatch failure).
    """
    if not event_type or not is_ad_event_type(event_type):
        logger.warning("emit_ad_event: unknown event_type=%s", event_type)
        return []
    if not account_owner_sub:
        return []
    try:
        delivery_ids = dispatch_webhook_event(
            event_type=event_type,
            user_sub=account_owner_sub,
            data=data or {},
        )
        if delivery_ids:
            logger.debug(
                "ad_webhook_dispatched event=%s deliveries=%d",
                event_type,
                len(delivery_ids),
            )
        return delivery_ids
    except Exception:
        logger.warning(
            "emit_ad_event_failed event_type=%s sub=%s",
            event_type,
            account_owner_sub,
            exc_info=True,
        )
        return []
