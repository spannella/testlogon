from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ArchiveQueryResult:
    items: list[dict[str, Any]]
    next_offset: int | None
    total_matches: int


def _iter_manifest_paths(root_dir: Path):
    if not root_dir.exists():
        return []
    return root_dir.glob("*/[0-9][0-9][0-9][0-9]/[0-9][0-9]/[0-9][0-9]/[0-9][0-9]/manifest.jsonl")


def _load_event_object(root: Path, object_key: str) -> dict[str, Any]:
    p = root / object_key
    if not p.exists():
        return {}
    try:
        obj = json.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}
    return obj if isinstance(obj, dict) else {}


def query_archive_records(
    *,
    root_dir: str,
    tenant_id: str = "default",
    conversation_id: str | None = None,
    user_id: str | None = None,
    from_ts: int | None = None,
    to_ts: int | None = None,
    sort_order: str = "desc",
    limit: int = 50,
    offset: int = 0,
    include_payload: bool = False,
) -> ArchiveQueryResult:
    root = Path(root_dir)
    matched: list[dict[str, Any]] = []

    for manifest_path in _iter_manifest_paths(root):
        partition = str(manifest_path.relative_to(root).parent)
        partition_tenant = partition.split("/", 1)[0] if "/" in partition else "default"
        if partition_tenant != tenant_id:
            continue

        for line in manifest_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            event_ts = int(entry.get("event_ts", 0) or 0)
            if from_ts is not None and event_ts < int(from_ts):
                continue
            if to_ts is not None and event_ts > int(to_ts):
                continue
            if conversation_id and str(entry.get("conversation_id") or "") != conversation_id:
                continue

            envelope = _load_event_object(root, str(entry.get("object_key") or ""))
            if user_id:
                actor_user_id = str(envelope.get("actor_user_id") or "")
                effective_user_id = str(envelope.get("effective_user_id") or "")
                if user_id not in {actor_user_id, effective_user_id}:
                    continue

            item = {
                "event_id": str(entry.get("event_id") or ""),
                "event_ts": event_ts,
                "event_type": str(entry.get("event_type") or ""),
                "conversation_id": str(entry.get("conversation_id") or envelope.get("conversation_id") or ""),
                "message_id": str(entry.get("message_id") or envelope.get("message_id") or ""),
                "actor_user_id": str(envelope.get("actor_user_id") or ""),
                "effective_user_id": str(envelope.get("effective_user_id") or ""),
                "object_key": str(entry.get("object_key") or ""),
                "payload_hash": str(entry.get("payload_hash") or envelope.get("payload_hash") or ""),
                "prev_hash": str(entry.get("prev_hash") or envelope.get("prev_hash") or ""),
                "schema_version": int(entry.get("schema_version", envelope.get("schema_version", 1)) or 1),
            }
            if include_payload:
                item["payload"] = envelope.get("payload") if isinstance(envelope.get("payload"), dict) else {}
            matched.append(item)

    reverse = str(sort_order).lower() != "asc"
    matched.sort(key=lambda x: (int(x.get("event_ts", 0) or 0), str(x.get("event_id") or "")), reverse=reverse)

    safe_offset = max(0, int(offset or 0))
    slice_items = matched[safe_offset : safe_offset + int(limit)]
    next_offset = safe_offset + int(limit) if (safe_offset + int(limit)) < len(matched) else None

    return ArchiveQueryResult(items=slice_items, next_offset=next_offset, total_matches=len(matched))
