"""Alert priority classification for toast and notification routing.

Maps alert event types to priority levels:
  - urgent: security alerts, payment failures — toast is persistent (duration=0)
  - normal: new messages, tips, social interactions — toast 5s
  - low: follows, reactions — toast 3s

Used by write_alert() to tag each alert and by the frontend to determine
toast display duration.
"""

from __future__ import annotations

from typing import Dict

# Priority levels
URGENT = "urgent"
NORMAL = "normal"
LOW = "low"

# Map event types → priority.  Any type not listed defaults to NORMAL.
_PRIORITY_MAP: Dict[str, str] = {
    # Security — urgent
    "login_failure": URGENT,
    "mfa_failure": URGENT,
    "challenge_failed": URGENT,
    "access_denied": URGENT,
    "security_event": URGENT,
    "device_new": URGENT,
    "device_location_mismatch": URGENT,
    "rate_limited": URGENT,

    # Billing — normal
    "subscription_started": NORMAL,
    "post_tip": NORMAL,
    "message_tip": NORMAL,

    # Social — normal
    "new_follower": LOW,
    "post_liked": LOW,
    "post_reaction": LOW,
    "post_comment": NORMAL,
    "comment_reply": NORMAL,
    "mention": NORMAL,
    "post_shared": LOW,

    # Session management — low
    "login_success": LOW,
    "mfa_success": LOW,
    "session_revoked": NORMAL,
    "api_key_created": LOW,
    "api_key_revoked": NORMAL,
    "api_key_ip_rules_updated": NORMAL,
    "totp_device_added": NORMAL,
    "totp_device_removed": NORMAL,
    "device_trust": LOW,
    "device_revoke": NORMAL,
    "challenge_created": LOW,
    "challenge_revoked": LOW,

    # Calendar — low
    "calendar_event_created": LOW,
    "calendar_event_updated": LOW,
    "calendar_event_deleted": LOW,

    # Tickets — normal
    "ticket_created": NORMAL,
    "ticket_assigned": NORMAL,
    "ticket_replied": NORMAL,
    "ticket_status_changed": NORMAL,
    "ticket_reopened": NORMAL,
}


def get_alert_priority(event_type: str) -> str:
    """Return the priority level for a given alert event type.

    Returns 'urgent', 'normal', or 'low'.
    Defaults to 'normal' for unknown event types.
    """
    return _PRIORITY_MAP.get(event_type, NORMAL)
