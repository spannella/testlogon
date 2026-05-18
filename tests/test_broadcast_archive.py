from __future__ import annotations

from app.services.broadcast_archive import (
    build_archive_output_group,
    build_archive_s3_prefix,
    bucket_policy_allows_archive_writes,
    ensure_archive_lifecycle_policy,
)


class _FakeS3:
    def __init__(self) -> None:
        self.last = None

    def put_bucket_lifecycle_configuration(self, **kwargs):
        self.last = kwargs


def test_build_archive_prefix_and_output_group() -> None:
    prefix = build_archive_s3_prefix(bucket="archive-bucket", prefix_root="sessions", session_id="s1")
    group = build_archive_output_group(bucket="archive-bucket", prefix_root="sessions", session_id="s1")
    assert prefix == "s3://archive-bucket/sessions/s1/"
    assert group["S3Prefix"] == prefix
    assert group["Destinations"][0]["Settings"][0]["Url"].startswith("s3ssl://")


def test_lifecycle_and_policy_helpers() -> None:
    s3 = _FakeS3()
    assert ensure_archive_lifecycle_policy(s3_client=s3, bucket="archive-bucket", retention_days=30) is True
    assert s3.last["Bucket"] == "archive-bucket"
    assert bucket_policy_allows_archive_writes({"Statement": [{"Action": ["s3:GetObject", "s3:PutObject"]}]}) is True
