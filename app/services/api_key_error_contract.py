from __future__ import annotations

from typing import Any, Dict

from fastapi import Request


def build_api_key_error_detail(
    *,
    code: str,
    reason: str,
    message: str,
    request: Request | None = None,
    route_id: str = "",
    product: str = "",
    api_key_id: str = "",
    extra: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    request_id = ""
    if request is not None:
        request_id = str(request.headers.get("x-request-id") or "").strip()
    payload: Dict[str, Any] = {
        "code": code,
        "reason": reason,
        "message": message,
        "route_id": route_id,
        "product": product,
        "api_key_id": api_key_id,
        "request_id": request_id,
    }
    if extra:
        payload.update(extra)
    return payload
