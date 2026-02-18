from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlparse
from typing import Optional

import boto3
from botocore.config import Config

from app.core.settings import S


def _resolve_endpoint_url(primary: Optional[str], fallback: Optional[str]) -> Optional[str]:
    if primary:
        return primary
    return fallback or None


def _aws_region() -> str:
    return S.aws_region or "us-east-1"


def _aws_endpoint_url() -> Optional[str]:
    return S.aws_endpoint_url or None


def _is_local_endpoint(endpoint_url: Optional[str]) -> bool:
    if not endpoint_url:
        return False
    host = (urlparse(endpoint_url).hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "0.0.0.0"}


def _is_non_aws_localish_endpoint(endpoint_url: Optional[str]) -> bool:
    if not endpoint_url:
        return False

    host = (urlparse(endpoint_url).hostname or "").lower()
    if not host:
        return False

    if host.endswith("amazonaws.com"):
        return False

    if S.dev_mode:
        return True

    if host in {"host.docker.internal", "localstack", "minio"}:
        return True

    if host.endswith(".local") or host.endswith(".internal"):
        return True

    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def _local_credentials_kwargs(endpoint_url: Optional[str]) -> dict:
    if not (_is_local_endpoint(endpoint_url) or _is_non_aws_localish_endpoint(endpoint_url)):
        return {}
    if os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY"):
        return {}
    return {
        "aws_access_key_id": "test",
        "aws_secret_access_key": "test",
        "aws_session_token": os.getenv("AWS_SESSION_TOKEN", "test"),
    }


def _ddb_endpoint_url() -> Optional[str]:
    return _resolve_endpoint_url(S.ddb_endpoint_url, _aws_endpoint_url())


def _s3_endpoint_url() -> Optional[str]:
    return _resolve_endpoint_url(S.s3_endpoint_url, _aws_endpoint_url())


def _cognito_endpoint_url() -> Optional[str]:
    return _resolve_endpoint_url(S.cognito_endpoint_url, _aws_endpoint_url())


def _kms_endpoint_url() -> Optional[str]:
    return _resolve_endpoint_url(S.kms_endpoint_url, _aws_endpoint_url())


def _sqs_endpoint_url() -> Optional[str]:
    return _resolve_endpoint_url(S.sqs_endpoint_url, _aws_endpoint_url())


def _s3_config() -> Config:
    if S.s3_use_path_style:
        return Config(s3={"addressing_style": "path"})
    return Config()


def ddb_resource():
    endpoint_url = _ddb_endpoint_url()
    return boto3.resource(
        "dynamodb",
        region_name=_aws_region(),
        endpoint_url=endpoint_url,
        **_local_credentials_kwargs(endpoint_url),
    )


def s3_client():
    endpoint_url = _s3_endpoint_url()
    return boto3.client(
        "s3",
        region_name=_aws_region(),
        endpoint_url=endpoint_url,
        config=_s3_config(),
        **_local_credentials_kwargs(endpoint_url),
    )


def cognito_client():
    endpoint_url = _cognito_endpoint_url()
    return boto3.client(
        "cognito-idp",
        region_name=_aws_region(),
        endpoint_url=endpoint_url,
        **_local_credentials_kwargs(endpoint_url),
    )


def kms_client():
    endpoint_url = _kms_endpoint_url()
    return boto3.client(
        "kms",
        region_name=_aws_region(),
        endpoint_url=endpoint_url,
        **_local_credentials_kwargs(endpoint_url),
    )


def sqs_client():
    endpoint_url = _sqs_endpoint_url()
    return boto3.client(
        "sqs",
        region_name=_aws_region(),
        endpoint_url=endpoint_url,
        **_local_credentials_kwargs(endpoint_url),
    )
