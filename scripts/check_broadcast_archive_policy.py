#!/usr/bin/env python3
from __future__ import annotations

import json

import boto3

from app.core.settings import S
from app.services.broadcast_archive import (
    bucket_policy_allows_archive_writes,
    ensure_archive_lifecycle_policy,
)


def main() -> int:
    s3 = boto3.client(
        "s3",
        region_name=S.aws_region or "us-east-1",
        endpoint_url=S.aws_endpoint_url or None,
    )
    bucket = S.broadcast_archive_bucket or "broadcast-archive"
    ensure_archive_lifecycle_policy(
        s3_client=s3,
        bucket=bucket,
        retention_days=S.broadcast_archive_retention_days or 30,
    )
    policy = s3.get_bucket_policy(Bucket=bucket)
    policy_doc = json.loads(policy["Policy"])
    ok = bucket_policy_allows_archive_writes(policy_doc)
    print(
        json.dumps(
            {
                "bucket": bucket,
                "retention_days": S.broadcast_archive_retention_days,
                "archive_putobject_allowed": ok,
            }
        )
    )
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
