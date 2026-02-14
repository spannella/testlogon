#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError


ENV_FILE = Path(".env.local")
ENV_EXAMPLE_FILE = Path(".env.local.example")
DEFAULT_POOL_NAME = os.getenv("LOCAL_COGNITO_POOL_NAME", "local-user-pool")
DEFAULT_CLIENT_NAME = os.getenv("LOCAL_COGNITO_APP_CLIENT_NAME", "local-app-client")


def _region() -> str:
    return os.getenv("COGNITO_REGION") or os.getenv("AWS_REGION", "us-east-1")


def _endpoint_base() -> str:
    endpoint = os.getenv("COGNITO_ENDPOINT_URL") or os.getenv("AWS_ENDPOINT_URL") or "http://localhost:4566"
    return endpoint.rstrip("/")


def _cognito_client():
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
    return boto3.client(
        "cognito-idp",
        region_name=_region(),
        endpoint_url=_endpoint_base(),
    )


def _find_user_pool_id(client, pool_name: str) -> Optional[str]:
    next_token: Optional[str] = None
    while True:
        kwargs: Dict[str, object] = {"MaxResults": 60}
        if next_token:
            kwargs["NextToken"] = next_token
        response = client.list_user_pools(**kwargs)
        for pool in response.get("UserPools", []):
            if pool.get("Name") == pool_name:
                return pool.get("Id")
        next_token = response.get("NextToken")
        if not next_token:
            return None


def _ensure_user_pool(client, pool_name: str) -> str:
    pool_id = _find_user_pool_id(client, pool_name)
    if pool_id:
        return pool_id
    response = client.create_user_pool(PoolName=pool_name)
    return response["UserPool"]["Id"]


def _find_app_client_id(client, pool_id: str, client_name: str) -> Optional[str]:
    next_token: Optional[str] = None
    while True:
        kwargs: Dict[str, object] = {"UserPoolId": pool_id, "MaxResults": 60}
        if next_token:
            kwargs["NextToken"] = next_token
        response = client.list_user_pool_clients(**kwargs)
        for app_client in response.get("UserPoolClients", []):
            if app_client.get("ClientName") == client_name:
                return app_client.get("ClientId")
        next_token = response.get("NextToken")
        if not next_token:
            return None


def _ensure_app_client(client, pool_id: str, client_name: str) -> str:
    client_id = _find_app_client_id(client, pool_id, client_name)
    if client_id:
        return client_id

    response = client.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=client_name,
        GenerateSecret=False,
        ExplicitAuthFlows=[
            "ALLOW_USER_SRP_AUTH",
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
        ],
    )
    return response["UserPoolClient"]["ClientId"]


def _upsert_env_lines(path: Path, key_values: Dict[str, str]) -> None:
    if not path.exists() and ENV_EXAMPLE_FILE.exists():
        path.write_text(ENV_EXAMPLE_FILE.read_text())

    lines: List[str] = path.read_text().splitlines() if path.exists() else []
    pending = dict(key_values)
    updated: List[str] = []

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            updated.append(line)
            continue

        key, _ = line.split("=", 1)
        key = key.strip()
        if key in pending:
            updated.append(f"{key}={pending.pop(key)}")
        else:
            updated.append(line)

    if pending:
        if updated and updated[-1].strip():
            updated.append("")
        updated.append("# Local Cognito bootstrap")
        for key, value in pending.items():
            updated.append(f"{key}={value}")

    path.write_text("\n".join(updated).rstrip() + "\n")


def main() -> None:
    client = _cognito_client()
    pool_id = _ensure_user_pool(client, DEFAULT_POOL_NAME)
    app_client_id = _ensure_app_client(client, pool_id, DEFAULT_CLIENT_NAME)

    issuer_url = f"{_endpoint_base()}/{pool_id}"
    jwks_url = f"{issuer_url}/.well-known/jwks.json"

    _upsert_env_lines(
        ENV_FILE,
        {
            "COGNITO_USER_POOL_ID": pool_id,
            "COGNITO_APP_CLIENT_ID": app_client_id,
            "COGNITO_REGION": _region(),
            "COGNITO_ISSUER_URL": issuer_url,
            "COGNITO_JWKS_URL": jwks_url,
        },
    )

    print("Ensured local Cognito resources exist.")
    print(f"User pool id: {pool_id}")
    print(f"App client id: {app_client_id}")
    print(f"Wrote config to {ENV_FILE}")


if __name__ == "__main__":
    try:
        main()
    except (ClientError, BotoCoreError) as exc:
        raise SystemExit(f"Failed to initialize local Cognito: {exc}")
