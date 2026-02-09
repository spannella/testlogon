#!/usr/bin/env python3
from __future__ import annotations

import os
import time
from typing import Iterable, List

from app.core.aws_clients import s3_client
from app.core.settings import S


def _bucket_names() -> List[str]:
    names = [
        os.getenv("UPLOAD_BUCKET", ""),
        os.getenv("S3_BUCKET_IMAGES", ""),
        S.filemgr_bucket or os.getenv("FILEMGR_BUCKET", ""),
    ]
    return [name for name in names if name]


def _ensure_bucket(client, name: str) -> None:
    existing = {b["Name"] for b in client.list_buckets().get("Buckets", [])}
    if name in existing:
        return
    region = S.aws_region or "us-east-1"
    if region == "us-east-1":
        client.create_bucket(Bucket=name)
    else:
        client.create_bucket(
            Bucket=name,
            CreateBucketConfiguration={"LocationConstraint": region},
        )


def main() -> None:
    client = s3_client()
    buckets = _bucket_names()
    for name in buckets:
        _ensure_bucket(client, name)
    print(f"Ensured {len(buckets)} S3 buckets exist.")


if __name__ == "__main__":
    main()
