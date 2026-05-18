from __future__ import annotations

from typing import Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import HTTPException

from app.core.settings import S


def is_secret_reference(value: str) -> bool:
    v = (value or "").strip()
    return (
        v.startswith("secret://")
        or v.startswith("arn:aws:secretsmanager:")
        or v.startswith("arn:aws:ssm:")
        or v.startswith("/broadcast/")
    )


def enforce_secret_reference_only(field_name: str, value: Optional[str]) -> None:
    if not value:
        return
    if not is_secret_reference(value):
        raise HTTPException(
            status_code=400,
            detail={
                "code": "BROADCAST_SECRET_REFERENCE_REQUIRED",
                "detail": f"{field_name} must be a secret reference and not raw secret material",
            },
        )


def resolve_secret_value(secret_ref: str) -> str:
    """Resolve secret by reference while surfacing non-sensitive errors only."""
    if not secret_ref:
        raise HTTPException(status_code=400, detail={"code": "BROADCAST_SECRET_REFERENCE_REQUIRED", "detail": "secret reference required"})

    backend = (S.broadcast_secrets_backend or "secrets_manager").strip().lower()
    region = S.aws_region or "us-east-1"
    endpoint = S.aws_endpoint_url or None
    try:
        if backend == "ssm" or secret_ref.startswith("arn:aws:ssm:") or secret_ref.startswith("/"):
            ssm = boto3.client("ssm", region_name=region, endpoint_url=endpoint)
            resp = ssm.get_parameter(Name=secret_ref, WithDecryption=True)
            return str(resp.get("Parameter", {}).get("Value") or "")

        secrets = boto3.client("secretsmanager", region_name=region, endpoint_url=endpoint)
        secret_id = secret_ref.replace("secret://", "", 1) if secret_ref.startswith("secret://") else secret_ref
        resp = secrets.get_secret_value(SecretId=secret_id)
        if "SecretString" in resp:
            return str(resp.get("SecretString") or "")
        binary = resp.get("SecretBinary") or b""
        return binary.decode("utf-8") if hasattr(binary, "decode") else str(binary)
    except (BotoCoreError, ClientError, ValueError, UnicodeDecodeError):
        raise HTTPException(
            status_code=502,
            detail={"code": "BROADCAST_SECRET_RETRIEVAL_FAILED", "detail": "unable to resolve secret reference"},
        )
