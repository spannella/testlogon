from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.services.messaging_archive_query import query_archive_records


@dataclass(frozen=True)
class ExportArtifact:
    export_id: str
    artifact_dir: str
    manifest_path: str
    records_path: str
    record_count: int
    records_sha256: str
    manifest_sha256: str
    signature_value: str


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _sign_manifest(*, key: str, payload: bytes) -> str:
    digest = hmac.new(key.encode("utf-8"), payload, hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def build_case_export_bundle(
    *,
    export_id: str,
    case_id: str,
    tenant_id: str,
    requested_by_user_id: str,
    generated_at: int,
    expires_at: int,
    archive_root_dir: str,
    export_root_dir: str,
    manifest_signing_key: str,
    manifest_signing_key_id: str,
    query_snapshot: dict[str, Any],
    limit: int = 500,
) -> ExportArtifact:
    from_ts = int(query_snapshot.get("from_ts", 0) or 0)
    to_ts = int(query_snapshot.get("to_ts", 0) or 0)
    if from_ts > to_ts:
        raise ValueError("from_ts must be <= to_ts")

    include_payload = bool(query_snapshot.get("include_payload", True))
    sort_order = str(query_snapshot.get("sort", "asc") or "asc")
    conversation_id = (query_snapshot.get("conversation_id") or None)
    user_id = (query_snapshot.get("user_id") or None)

    all_items: list[dict[str, Any]] = []
    offset = 0
    while True:
        page = query_archive_records(
            root_dir=archive_root_dir,
            tenant_id=tenant_id,
            conversation_id=conversation_id,
            user_id=user_id,
            from_ts=from_ts,
            to_ts=to_ts,
            sort_order=sort_order,
            limit=max(1, int(limit)),
            offset=offset,
            include_payload=include_payload,
        )
        all_items.extend(page.items)
        if page.next_offset is None:
            break
        offset = page.next_offset

    artifact_dir = Path(export_root_dir) / tenant_id / case_id / export_id
    artifact_dir.mkdir(parents=True, exist_ok=True)
    records_path = artifact_dir / "records.jsonl"

    per_record_checksums: list[str] = []
    with records_path.open("w", encoding="utf-8") as f:
        for item in all_items:
            event_bytes = _canonical_json_bytes(item)
            record_sha = _sha256_hex(event_bytes)
            per_record_checksums.append(record_sha)
            row = {
                "event": item,
                "record_sha256": record_sha,
            }
            f.write(_canonical_json_bytes(row).decode("utf-8") + "\n")

    records_bytes = records_path.read_bytes() if records_path.exists() else b""
    records_sha256 = _sha256_hex(records_bytes)
    aggregate_digest = _sha256_hex("\n".join(per_record_checksums).encode("utf-8"))

    unsigned_manifest = {
        "manifest_version": 1,
        "export_id": export_id,
        "case_id": case_id,
        "tenant_id": tenant_id,
        "archive_schema_version": 1,
        "generated_at": int(generated_at),
        "generated_by_user_id": requested_by_user_id,
        "expires_at": int(expires_at),
        "records_file": {
            "path": "records.jsonl",
            "sha256": records_sha256,
            "record_count": len(all_items),
        },
        "bundle_checksums": {
            "manifest_sha256": "",
            "records_sha256": records_sha256,
        },
        "query_snapshot": {
            "conversation_id": conversation_id,
            "user_id": user_id,
            "from_ts": from_ts,
            "to_ts": to_ts,
            "sort": sort_order,
            "include_payload": include_payload,
        },
        "record_checksums": {
            "algorithm": "sha256",
            "aggregate_digest": aggregate_digest,
            "count": len(per_record_checksums),
        },
    }

    unsigned_manifest_bytes = _canonical_json_bytes(unsigned_manifest)
    unsigned_manifest_sha = _sha256_hex(unsigned_manifest_bytes)

    manifest = dict(unsigned_manifest)
    manifest["bundle_checksums"] = {
        "manifest_sha256": unsigned_manifest_sha,
        "records_sha256": records_sha256,
    }
    manifest["signature"] = {
        "algorithm": "hmac-sha256",
        "key_id": manifest_signing_key_id,
        "value": _sign_manifest(key=manifest_signing_key, payload=unsigned_manifest_bytes),
    }

    manifest_path = artifact_dir / "manifest.json"
    manifest_bytes = _canonical_json_bytes(manifest)
    manifest_path.write_bytes(manifest_bytes)

    return ExportArtifact(
        export_id=export_id,
        artifact_dir=str(artifact_dir),
        manifest_path=str(manifest_path),
        records_path=str(records_path),
        record_count=len(all_items),
        records_sha256=records_sha256,
        manifest_sha256=unsigned_manifest_sha,
        signature_value=str(manifest["signature"]["value"]),
    )
