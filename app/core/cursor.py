from __future__ import annotations

import base64
import json
from typing import Any, Dict, Optional

def encode_cursor(last_evaluated_key: Optional[Dict[str, Any]]) -> Optional[str]:
    if not last_evaluated_key:
        return None
    raw = json.dumps(last_evaluated_key, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

def decode_cursor(cursor: Optional[str]) -> Optional[Dict[str, Any]]:
    if not cursor:
        return None
    s = cursor.strip()
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    try:
        raw = base64.urlsafe_b64decode((s + pad).encode("utf-8"))
        obj = json.loads(raw.decode("utf-8"))
        if isinstance(obj, dict):
            return obj
    except Exception:
        return None
    return None
