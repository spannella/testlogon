from __future__ import annotations

from fastapi import HTTPException, Request

async def get_authenticated_user_sub(_: Request) -> str:
    '''
    Wire this into your real authentication (Cognito JWT validation, cookies, etc.)

    Keeping this as a dependency makes it easy to swap later and keeps the rest of
    the codebase (sessions, MFA, API keys, alerts) independent of auth.
    '''
    raise HTTPException(501, "Auth not wired: implement get_authenticated_user_sub()")
