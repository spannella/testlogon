"""LLM Provider Keys (AGENT-001) -- stub for AGENT-004 dependency."""

from __future__ import annotations

from typing import Any, Dict, Optional

from app.core.tables import T


def get_key(user_id: str, key_id: str) -> Optional[Dict[str, Any]]:
    """Get a single LLM key by user + key_id."""
    resp = T.llm_provider_keys.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"KEY#{key_id}"}
    )
    item = resp.get("Item")
    if not item:
        return None
    return {k: v for k, v in item.items() if k not in ("pk", "sk")}
