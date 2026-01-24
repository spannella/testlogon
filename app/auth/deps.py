from __future__ import annotations

import base64
import json
from typing import Optional

from fastapi import HTTPException, Request


def _decode_jwt_sub(token: str) -> Optional[str]:
    if token.count(".") != 2:
        return None
    _, payload, _ = token.split(".", 2)
    if not payload:
        return None
    padding = "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload + padding)
        data = json.loads(decoded.decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    sub = data.get("sub")
    return sub if isinstance(sub, str) and sub.strip() else None


def extract_bearer_token(auth_header: Optional[str]) -> str:
    if not auth_header:
        raise HTTPException(401, "Missing Authorization header")
    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(401, "Invalid Authorization header")
    return token.strip()

async def get_authenticated_user_sub(request: Request) -> str:
    """
    Wire this into your real authentication (Cognito JWT validation, cookies, etc.)

    Dev fallback: Authorization: Bearer <user_id>
    """
    auth = request.headers.get("authorization", "")
    token = extract_bearer_token(auth)
    return _decode_jwt_sub(token) or token
