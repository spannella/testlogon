from __future__ import annotations

from typing import Any, Dict


def build_archive_s3_prefix(*, bucket: str, prefix_root: str, session_id: str) -> str:
    base = prefix_root.strip("/").strip()
    return f"s3://{bucket}/{base}/{session_id}/"


def build_archive_output_group(*, bucket: str, prefix_root: str, session_id: str) -> Dict[str, Any]:
    destination_ref_id = "archive-destination"
    s3_prefix = build_archive_s3_prefix(bucket=bucket, prefix_root=prefix_root, session_id=session_id)
    s3_uri = s3_prefix.replace("s3://", "s3ssl://")
    return {
        "Name": "archive-s3",
        "OutputGroupSettings": {
            "ArchiveGroupSettings": {
                "Destination": {"DestinationRefId": destination_ref_id},
                "RolloverInterval": 60,
            }
        },
        "Outputs": [
            {
                "OutputSettings": {"ArchiveOutputSettings": {}},
                "NameModifier": "_archive",
            }
        ],
        "Destinations": [
            {
                "Id": destination_ref_id,
                "Settings": [{"Url": s3_uri}],
            }
        ],
        "S3Prefix": s3_prefix,
    }


def ensure_archive_lifecycle_policy(*, s3_client, bucket: str, retention_days: int) -> bool:
    rules = [
        {
            "ID": "broadcast-archive-retention",
            "Status": "Enabled",
            "Filter": {"Tag": {"Key": "retention", "Value": "broadcast"}},
            "Expiration": {"Days": int(retention_days)},
        }
    ]
    s3_client.put_bucket_lifecycle_configuration(
        Bucket=bucket,
        LifecycleConfiguration={"Rules": rules},
    )
    return True


def bucket_policy_allows_archive_writes(policy_doc: Dict[str, Any]) -> bool:
    statements = policy_doc.get("Statement") or []
    for stmt in statements:
        actions = stmt.get("Action")
        if isinstance(actions, str):
            actions = [actions]
        actions = actions or []
        if "s3:PutObject" in actions or "s3:*" in actions:
            return True
    return False
