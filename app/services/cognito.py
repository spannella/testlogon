from __future__ import annotations

from typing import Any, Dict

import boto3
from fastapi import HTTPException

from app.core.settings import S


def _cognito_region() -> str:
    region = S.cognito_region or S.aws_region
    if not region:
        raise HTTPException(500, "Cognito region not configured")
    return region


def _cognito_client_id() -> str:
    if not S.cognito_app_client_id:
        raise HTTPException(500, "Cognito app client id not configured")
    return S.cognito_app_client_id


def cognito_client():
    return boto3.client("cognito-idp", region_name=_cognito_region())


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
