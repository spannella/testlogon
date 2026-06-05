"""Download a video source from S3 to a local scratch path before FFmpeg.

Used by transcode_worker.py to convert an s3:// URI to a local file path
that standard FFmpeg builds (without the S3 protocol demuxer) can read.

The s3 client comes from app.core.aws_clients.s3_client — the same helper
used by vod_s3_uploader (SECOPS-007 dev/prod parity): moto intercepts
botocore calls in dev, real S3 in prod, identical code path.
"""
from __future__ import annotations

import re
from pathlib import Path

from app.core.aws_clients import s3_client


def download_source_to_scratch(source_uri: str, scratch_dir: Path) -> Path:
    """Download s3://bucket/key to scratch_dir/source.<ext>. Returns local path.

    If source_uri is not an s3:// URI (e.g. already a local path or HTTPS
    presigned URL), it is returned as a Path without downloading.
    """
    m = re.match(r"^s3://([^/]+)/(.+)$", source_uri)
    if not m:
        # Not an s3:// URI — assume it is already a usable local path / URL.
        return Path(source_uri)
    bucket, key = m.group(1), m.group(2)
    ext = Path(key).suffix or ".mp4"
    dest = scratch_dir / f"source{ext}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    s3_client().download_file(bucket, key, str(dest))
    return dest
