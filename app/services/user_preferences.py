"""User UI preferences persistence (UX-001).

Stores preferences as a DynamoDB map attribute `ui_preferences` on the
existing profile record. DynamoDB's schemaless design means no migration
is needed -- the attribute is created on first write.

DynamoDB key schema for profiles table:
  PK: user_sub (string)
  No SK (simple primary key)
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from app.core.tables import T

logger = logging.getLogger(__name__)


def update_user_preferences(user_sub: str, prefs: Dict[str, Any]) -> None:
    """Merge-update UI preferences for a user.

    Creates the ui_preferences map if it doesn't exist, then sets each
    provided key within the map. Uses two-step update to ensure the map
    exists before setting nested keys.

    Args:
        user_sub: The user's unique identifier (partition key).
        prefs: Dictionary of preference key-value pairs to merge.
               Only non-None values should be passed.
    """
    if not prefs:
        return

    # Step 1: Ensure the map attribute exists
    T.profile.update_item(
        Key={"user_sub": user_sub},
        UpdateExpression="SET ui_preferences = if_not_exists(ui_preferences, :empty)",
        ExpressionAttributeValues={":empty": {}},
    )

    # Step 2: Set each preference key within the map
    for key, value in prefs.items():
        # Sanitize key name to prevent expression injection
        safe_key = key.replace(".", "_").replace("#", "_")[:50]
        T.profile.update_item(
            Key={"user_sub": user_sub},
            UpdateExpression="SET ui_preferences.#k = :val",
            ExpressionAttributeNames={"#k": safe_key},
            ExpressionAttributeValues={":val": value},
        )


def get_user_preferences(user_sub: str) -> Dict[str, Any]:
    """Retrieve UI preferences for a user.

    Returns an empty dict if no preferences have been set.
    """
    resp = T.profile.get_item(Key={"user_sub": user_sub})
    item = resp.get("Item", {})
    return item.get("ui_preferences", {})
