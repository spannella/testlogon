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
    # In dev mode, moto intercepts boto3 S3 calls in-process; no endpoint URL
    # should be set (a custom endpoint would bypass moto's botocore patching).
    if S.dev_mode:
        return None
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


def _secretsmanager_endpoint_url() -> Optional[str]:
    return _resolve_endpoint_url(getattr(S, "secretsmanager_endpoint_url", ""), _aws_endpoint_url())


def secretsmanager_client():
    endpoint_url = _secretsmanager_endpoint_url()
    return boto3.client(
        "secretsmanager",
        region_name=_aws_region(),
        endpoint_url=endpoint_url,
        **_local_credentials_kwargs(endpoint_url),
    )


_DDB_TRANSACT_CLIENT = None


def ddb_transact_client():
    """Return a cached bare low-level DynamoDB client for transact_write_items.

    Callers that build raw AttributeValue maps ({"S": ...}/{"N": ...}) must issue
    transact_write_items through a *plain* client. The boto3 resource's
    .meta.client carries the document transform injector, which re-serializes
    already-serialized values -> DDB-Local rejects it with
    ValidationException: Invalid attribute value type (every real tip 500s).

    Endpoint/region/credentials are inherited from the app's live dynamodb
    resource client, so it targets the SAME table on both DDB-Local (dev/prod-mock)
    and real AWS with no S.dev_mode branch (matches group_treasury pattern).
    """
    global _DDB_TRANSACT_CLIENT
    if _DDB_TRANSACT_CLIENT is not None:
        return _DDB_TRANSACT_CLIENT
    from app.core.aws import ddb as _ddb_resource
    resource_client = _ddb_resource.meta.client
    endpoint = resource_client.meta.endpoint_url
    region = resource_client.meta.region_name
    creds = resource_client._request_signer._credentials
    kwargs = {"region_name": region, "endpoint_url": endpoint}
    if creds is not None:
        frozen = creds.get_frozen_credentials()
        kwargs["aws_access_key_id"] = frozen.access_key
        kwargs["aws_secret_access_key"] = frozen.secret_key
        if frozen.token:
            kwargs["aws_session_token"] = frozen.token
    _DDB_TRANSACT_CLIENT = boto3.client("dynamodb", **kwargs)
    return _DDB_TRANSACT_CLIENT
