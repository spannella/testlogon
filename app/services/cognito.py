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
