#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError


ENV_FILE = Path(".env.local")
ENV_EXAMPLE_FILE = Path(".env.local.example")
FRONTEND_ENV_FILE = Path("frontend/.env.local")
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


def _upsert_env_lines(path: Path, key_values: Dict[str, str], seed_from: Path | None = None) -> None:
    if not path.exists() and seed_from and seed_from.exists():
        path.write_text(seed_from.read_text())

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


def _read_env_value(path: Path, key: str) -> Optional[str]:
    if not path.exists():
        return None

    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        candidate_key, candidate_value = stripped.split("=", 1)
        if candidate_key.strip() == key:
            value = candidate_value.strip()
            return value or None

    return None


def _frontend_api_base_url() -> str:
    explicit_value = os.getenv("VITE_API_BASE_URL")
    if explicit_value:
        return explicit_value

    existing_frontend_value = _read_env_value(FRONTEND_ENV_FILE, "VITE_API_BASE_URL")
    if existing_frontend_value:
        return existing_frontend_value

    backend_public_base = _read_env_value(ENV_FILE, "PUBLIC_BASE_URL")
    if backend_public_base:
        return backend_public_base

    return "http://localhost:8000"


def main() -> None:
    client = _cognito_client()
    pool_id = _ensure_user_pool(client, DEFAULT_POOL_NAME)
    app_client_id = _ensure_app_client(client, pool_id, DEFAULT_CLIENT_NAME)

    issuer_url = f"{_endpoint_base()}/{pool_id}"
    jwks_url = f"{issuer_url}/.well-known/jwks.json"

    cognito_values = {
        "COGNITO_USER_POOL_ID": pool_id,
        "COGNITO_APP_CLIENT_ID": app_client_id,
        "COGNITO_REGION": _region(),
        "COGNITO_ISSUER_URL": issuer_url,
        "COGNITO_JWKS_URL": jwks_url,
    }

    _upsert_env_lines(ENV_FILE, cognito_values, seed_from=ENV_EXAMPLE_FILE)
    _upsert_env_lines(
        FRONTEND_ENV_FILE,
        {
            "VITE_COGNITO_USER_POOL_ID": pool_id,
            "VITE_COGNITO_APP_CLIENT_ID": app_client_id,
            "VITE_COGNITO_REGION": _region(),
            "VITE_COGNITO_ISSUER_URL": issuer_url,
            "VITE_COGNITO_JWKS_URL": jwks_url,
            # VITE_API_BASE_URL is intentionally omitted: the frontend routes all
            # API calls through the Vite proxy so cookies stay on one origin.
        },
    )

    print("Ensured local Cognito resources exist.")
    print(f"User pool id: {pool_id}")
    print(f"App client id: {app_client_id}")
    print(f"Wrote backend config to {ENV_FILE}")
    print(f"Wrote frontend config to {FRONTEND_ENV_FILE}")


def _is_dev_mode() -> bool:
    if os.getenv("DEV_MODE") == "1":
        return True
    env_val = _read_env_value(ENV_FILE, "DEV_MODE")
    return env_val == "1"


if __name__ == "__main__":
    try:
        main()
    except (ClientError, BotoCoreError) as exc:
        if _is_dev_mode():
            print(
                f"Warning: Could not initialize local Cognito ({exc}). "
                "Skipping — Cognito is not used in dev_mode "
                "(DEV_MODE=1 causes _cognito_available() to return False)."
            )
        else:
            raise SystemExit(f"Failed to initialize local Cognito: {exc}")
