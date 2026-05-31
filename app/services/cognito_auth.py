"""Cognito password re-verification (PLATFORM-018).

Used by account-deletion to re-authenticate a user's password before
scheduling a destructive operation. In dev mode any non-empty password
is accepted (consistent with the rest of the dev auth stack).
"""

from __future__ import annotations

import logging

from app.core.settings import S

logger = logging.getLogger(__name__)


def _cognito_configured() -> bool:
    return bool(S.cognito_user_pool_id and S.cognito_app_client_id)


def verify_user_password(user_sub: str, password: str) -> bool:
    """Verify a user's password.

    - Empty password is always rejected.
    - In dev mode (or when Cognito is not configured), any non-empty
      password is accepted.
    - In production with Cognito configured, verify via AdminInitiateAuth
      using the ADMIN_USER_PASSWORD_AUTH flow.
    """
    if not password:
        return False

    if S.dev_mode or not _cognito_configured():
        return True

    try:
        from boto3 import client as _boto3_client

        cog = _boto3_client("cognito-idp", region_name=S.aws_region or "us-east-1")
        resp = cog.admin_initiate_auth(
            UserPoolId=S.cognito_user_pool_id,
            ClientId=S.cognito_app_client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": user_sub, "PASSWORD": password},
        )
        return "AuthenticationResult" in resp
    except Exception as exc:  # noqa: BLE001
        # NotAuthorizedException and friends -> failed verification.
        name = type(exc).__name__
        if "NotAuthorized" in name or "UserNotFound" in name:
            return False
        logger.exception("Cognito password verification error for %s", user_sub)
        return False
