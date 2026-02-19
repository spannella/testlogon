from __future__ import annotations

from typing import Any, Dict
import logging

from fastapi import HTTPException

from app.core.aws_clients import cognito_client as shared_cognito_client
from app.core.settings import S

logger = logging.getLogger(__name__)


def _cognito_region() -> str:
    region = S.cognito_region or S.aws_region
    if not region:
        raise HTTPException(500, "Cognito region not configured")
    return region


def _cognito_client_id() -> str:
    if not S.cognito_app_client_id:
        raise HTTPException(500, "Cognito app client id not configured")
    return S.cognito_app_client_id


def _cognito_user_pool_id() -> str:
    if not S.cognito_user_pool_id:
        raise HTTPException(500, "Cognito user pool id not configured")
    return S.cognito_user_pool_id


def cognito_client():
    return shared_cognito_client()


def cognito_forgot_password(username: str) -> Dict[str, Any]:
    client = cognito_client()
    return client.forgot_password(ClientId=_cognito_client_id(), Username=username)


def cognito_confirm_forgot_password(username: str, code: str, new_password: str) -> Dict[str, Any]:
    client = cognito_client()
    return client.confirm_forgot_password(
        ClientId=_cognito_client_id(),
        Username=username,
        ConfirmationCode=code,
        Password=new_password,
    )


def cognito_refresh_tokens(refresh_token: str) -> Dict[str, Any]:
    client = cognito_client()
    try:
        resp = client.initiate_auth(
            ClientId=_cognito_client_id(),
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters={"REFRESH_TOKEN": refresh_token},
        )
    except client.exceptions.NotAuthorizedException as exc:  # type: ignore[attr-defined]
        raise HTTPException(401, "Invalid refresh token") from exc
    except client.exceptions.InvalidParameterException as exc:  # type: ignore[attr-defined]
        raise HTTPException(400, "Invalid refresh token") from exc
    result = resp.get("AuthenticationResult") or {}
    if not result:
        raise HTTPException(401, "Refresh token rejected")
    return result


def cognito_sign_up(username: str, password: str, full_name: str) -> Dict[str, Any]:
    client = cognito_client()
    try:
        return client.sign_up(
            ClientId=_cognito_client_id(),
            Username=username,
            Password=password,
            UserAttributes=[
                {"Name": "email", "Value": username},
                {"Name": "name", "Value": full_name},
            ],
        )
    except client.exceptions.UsernameExistsException as exc:  # type: ignore[attr-defined]
        logger.info("cognito sign_up user already exists", extra={"username": username})
        raise HTTPException(409, "User already exists") from exc
    except client.exceptions.InvalidPasswordException as exc:  # type: ignore[attr-defined]
        # Cognito's message lists every unmet requirement, e.g.
        # "Password did not conform with policy: Password must have uppercase
        #  characters; Password must have symbol characters"
        reason = str(exc)
        logger.warning(
            "cognito sign_up password policy violation for %s: %s",
            username, reason,
            extra={"username": username, "cognito_reason": reason},
        )
        raise HTTPException(400, "Invalid password") from exc
    except client.exceptions.InvalidParameterException as exc:  # type: ignore[attr-defined]
        logger.warning("cognito sign_up invalid parameters", extra={"username": username, "error": str(exc)})
        raise HTTPException(400, "Invalid registration parameters") from exc
    except Exception:
        logger.exception("cognito sign_up unexpected exception", extra={"username": username})
        raise


def cognito_confirm_sign_up(username: str, code: str) -> Dict[str, Any]:
    client = cognito_client()
    try:
        return client.confirm_sign_up(
            ClientId=_cognito_client_id(),
            Username=username,
            ConfirmationCode=code,
        )
    except client.exceptions.CodeMismatchException as exc:  # type: ignore[attr-defined]
        raise HTTPException(400, "Invalid confirmation code") from exc
    except client.exceptions.ExpiredCodeException as exc:  # type: ignore[attr-defined]
        raise HTTPException(400, "Confirmation code expired") from exc
    except client.exceptions.NotAuthorizedException as exc:  # type: ignore[attr-defined]
        raise HTTPException(400, "User already confirmed") from exc
    except client.exceptions.UserNotFoundException as exc:  # type: ignore[attr-defined]
        raise HTTPException(404, "User not found") from exc


def cognito_admin_confirm_sign_up(username: str) -> Dict[str, Any]:
    client = cognito_client()
    try:
        return client.admin_confirm_sign_up(
            UserPoolId=_cognito_user_pool_id(),
            Username=username,
        )
    except client.exceptions.UserNotFoundException as exc:  # type: ignore[attr-defined]
        raise HTTPException(404, "User not found") from exc
    except client.exceptions.NotAuthorizedException as exc:  # type: ignore[attr-defined]
        raise HTTPException(403, "Not authorized to confirm user") from exc
