#!/usr/bin/env python3
"""Ensure a KMS key exists in the local mock KMS server and write its ID to .env.local.

The mock KMS server (scripts/mock_kms_server.py) persists key material to
.local/run/kms-state.json, so keys survive restarts.  This script is idempotent:
it reuses the key for alias/local-dev-key if it already exists.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

ENV_FILE = Path(".env.local")
ALIAS_NAME = "alias/local-dev-key"


def _endpoint() -> str:
    # Always target the dedicated mock KMS server regardless of KMS_ENDPOINT_URL,
    # which may still hold a stale value from a previous .env.local read.
    port = os.getenv("MOCK_KMS_PORT", "7999")
    return f"http://localhost:{port}"


def _kms_client():
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
    return boto3.client(
        "kms",
        region_name=os.getenv("AWS_REGION", "us-east-1"),
        endpoint_url=_endpoint(),
    )


def _find_key_for_alias(client) -> Optional[str]:
    try:
        resp = client.describe_key(KeyId=ALIAS_NAME)
        return resp["KeyMetadata"]["KeyId"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NotFoundException":
            return None
        raise


def _ensure_kms_key(client) -> str:
    key_id = _find_key_for_alias(client)
    if key_id:
        return key_id
    resp = client.create_key(Description="local-dev-key", KeyUsage="ENCRYPT_DECRYPT")
    key_id = resp["KeyMetadata"]["KeyId"]
    client.create_alias(AliasName=ALIAS_NAME, TargetKeyId=key_id)
    return key_id


def _upsert_env_lines(path: Path, key_values: Dict[str, str]) -> None:
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
        updated.append("# Local KMS bootstrap")
        for key, value in pending.items():
            updated.append(f"{key}={value}")

    path.write_text("\n".join(updated).rstrip() + "\n")


def main() -> None:
    endpoint = _endpoint()
    client = _kms_client()
    key_id = _ensure_kms_key(client)

    _upsert_env_lines(
        ENV_FILE,
        {
            "KMS_ENDPOINT_URL": endpoint,
            "KMS_KEY_ID": key_id,
        },
    )

    print("Ensured local KMS key exists.")
    print(f"KMS endpoint: {endpoint}")
    print(f"KMS key ID:   {key_id}")
    print(f"Wrote KMS config to {ENV_FILE}")


if __name__ == "__main__":
    try:
        main()
    except (ClientError, BotoCoreError) as exc:
        raise SystemExit(f"Failed to initialize local KMS: {exc}")
