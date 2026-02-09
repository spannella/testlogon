from __future__ import annotations

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
    return boto3.resource("dynamodb", region_name=_aws_region(), endpoint_url=_ddb_endpoint_url())


def s3_client():
    return boto3.client(
        "s3",
        region_name=_aws_region(),
        endpoint_url=_s3_endpoint_url(),
        config=_s3_config(),
    )


def cognito_client():
    return boto3.client(
        "cognito-idp",
        region_name=_aws_region(),
        endpoint_url=_cognito_endpoint_url(),
    )


def kms_client():
    return boto3.client(
        "kms",
        region_name=_aws_region(),
        endpoint_url=_kms_endpoint_url(),
    )


def sqs_client():
    return boto3.client(
        "sqs",
        region_name=_aws_region(),
        endpoint_url=_sqs_endpoint_url(),
    )
