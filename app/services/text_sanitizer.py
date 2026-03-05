from __future__ import annotations

import html
import re

_SCRIPT_STYLE_RE = re.compile(r"<\s*(script|style)\b[^>]*>.*?<\s*/\s*\1\s*>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")


def sanitize_user_text(value: str | None, *, max_length: int = 4000) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""

    cleaned = _SCRIPT_STYLE_RE.sub("", raw)
    cleaned = _TAG_RE.sub("", cleaned)
    cleaned = html.unescape(cleaned)
    cleaned = cleaned.replace("\x00", "").strip()
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length]
    return cleaned
