"""Moto-based in-process S3 mock for dev mode.

Activated at app startup when DEV_MODE=1.  mock_aws() patches botocore's HTTP
layer so every boto3 S3 call made anywhere in the process is served from
moto's in-memory store — no external LocalStack/MinIO process is needed.

Because the store is in-memory and per-process, the app must run with a single
uvicorn worker (the default when this module is used).
"""
from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

_mock_ctx: Optional[object] = None


def start_s3_mock(bucket_names: list[str]) -> None:
    """Activate the moto S3 mock and pre-create the given buckets."""
    global _mock_ctx
    try:
        import boto3
        from moto import mock_aws
    except ImportError:
        logger.warning("moto not installed; S3 mock unavailable in dev mode")
        return

    _mock_ctx = mock_aws()
    _mock_ctx.start()

    s3 = boto3.client("s3", region_name="us-east-1")
    for name in bucket_names:
        if not name:
            continue
        try:
            s3.create_bucket(Bucket=name)
            logger.debug("moto: created bucket %s", name)
        except Exception:
            pass  # bucket may already exist in moto state

    logger.info("moto S3 mock started; buckets: %s", bucket_names)
