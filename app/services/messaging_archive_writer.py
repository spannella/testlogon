from __future__ import annotations

import hashlib
import json
import logging
import os
import time as time_module
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import time
from typing import Any, Mapping, Protocol

from app.core.settings import S
from app.metrics import record_messaging_archive_integrity_error, record_messaging_archive_write
from app.services.messaging_archive_retention import evaluate_archive_retention_decision
from app.services.messaging_supervisory_feed import publish_supervisory_review_message
from app.services.messaging_compliance_archive_schema import (
    ARCHIVE_EVENT_SCHEMA_VERSION,
    MessagingArchiveEvent,
    build_archive_event,
)

logger = logging.getLogger(__name__)


class ArchiveWriter(Protocol):
    def write_event(self, event: MessagingArchiveEvent) -> str: ...


@dataclass(frozen=True)
class LogArchiveWriter:
    """Fallback writer that only logs archive events."""

    def write_event(self, event: MessagingArchiveEvent) -> str:
        record_key = f"{event.tenant_id}/{event.conversation_id}/{event.event_ts}/{event.event_id}"
        logger.info(
            "messaging.compliance_archive.write",
            extra={
                "record_key": record_key,
                "event_id": event.event_id,
                "event_type": event.event_type,
                "schema_version": event.schema_version,
                "conversation_id": event.conversation_id,
                "message_id": event.message_id,
                "actor_user_id": event.actor_user_id,
                "effective_user_id": event.effective_user_id,
            },
        )
        return record_key


@dataclass(frozen=True)
class FileArchiveWriter:
    """Filesystem-based immutable archive writer with partition manifests + chain heads."""

    root_dir: str

    def _partition_path(self, event_ts: int) -> str:
        ts = datetime.fromtimestamp(event_ts, tz=timezone.utc)
        return f"{ts.year:04d}/{ts.month:02d}/{ts.day:02d}/{ts.hour:02d}"

    def _partition_key(self, event: MessagingArchiveEvent) -> str:
        return f"{event.tenant_id}/{self._partition_path(event.event_ts)}"

    def _object_key(self, event: MessagingArchiveEvent) -> str:
        return f"{self._partition_key(event)}/{event.event_id}.json"

    def _manifest_key(self, event: MessagingArchiveEvent) -> str:
        return f"{self._partition_key(event)}/manifest.jsonl"

    def _chain_heads_table_path(self) -> Path:
        return Path(self.root_dir) / ".chain_heads_table.json"

    def _load_chain_heads_table(self) -> dict[str, dict[str, Any]]:
        p = self._chain_heads_table_path()
        if not p.exists():
            return {}
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return {}

    def _persist_chain_heads_table(self, table: dict[str, dict[str, Any]]) -> None:
        p = self._chain_heads_table_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(table, sort_keys=True, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
        tmp.replace(p)

    @staticmethod
    def _compute_chain_hash(*, prev_hash: str, payload_hash: str, event_id: str, event_ts: int) -> str:
        seed = f"{prev_hash}|{payload_hash}|{event_id}|{event_ts}"
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()

    def write_event(self, event: MessagingArchiveEvent) -> str:
        partition_key = self._partition_key(event)
        object_key = self._object_key(event)
        manifest_key = self._manifest_key(event)
        object_path = Path(self.root_dir) / object_key
        manifest_path = Path(self.root_dir) / manifest_key

        object_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)

        event_payload = json.dumps(
            event.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        event_bytes = event_payload.encode("utf-8")
        object_sha = hashlib.sha256(event_bytes).hexdigest()

        chain_heads_table = self._load_chain_heads_table()
        head_item = chain_heads_table.get(partition_key, {})
        prev_chain_hash = str(head_item.get("head_hash") or event.prev_hash)
        chain_hash = self._compute_chain_hash(
            prev_hash=prev_chain_hash,
            payload_hash=event.payload_hash,
            event_id=event.event_id,
            event_ts=event.event_ts,
        )

        # Append-only object write: fail if an object with same key already exists.
        with object_path.open("xb") as f:
            f.write(event_bytes)

        written_at = int(time())
        retention = evaluate_archive_retention_decision(
            tenant_id=event.tenant_id,
            event_type=event.event_type,
            event_ts=event.event_ts,
            now_ts=written_at,
        )
        manifest_entry = {
            "event_id": event.event_id,
            "event_ts": event.event_ts,
            "object_key": object_key,
            "object_sha256": object_sha,
            "payload_hash": event.payload_hash,
            "prev_hash": prev_chain_hash,
            "chain_hash": chain_hash,
            "event_type": event.event_type,
            "schema_version": event.schema_version,
            "conversation_id": event.conversation_id,
            "message_id": event.message_id,
            "written_at": written_at,
            "retention": retention.as_audit_dict(),
        }
        manifest_line = json.dumps(manifest_entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        with manifest_path.open("a", encoding="utf-8") as mf:
            mf.write(manifest_line)
            mf.write("\n")

        chain_heads_table[partition_key] = {
            "partition_key": partition_key,
            "head_hash": chain_hash,
            "event_id": event.event_id,
            "updated_at": int(time()),
        }
        self._persist_chain_heads_table(chain_heads_table)

        logger.info(
            "messaging.compliance_archive.write",
            extra={
                "result": "success",
                "tenant_id": event.tenant_id,
                "actor_user_id": event.actor_user_id,
                "record_key": object_key,
                "object_key": object_key,
                "manifest_key": manifest_key,
                "event_id": event.event_id,
                "event_type": event.event_type,
                "schema_version": event.schema_version,
                "partition_key": partition_key,
                "chain_hash": chain_hash,
            },
        )
        return object_key


class MessagingArchiveWriteError(RuntimeError):
    pass


def _archive_enabled() -> bool:
    return os.getenv(
        "MESSAGING_COMPLIANCE_ARCHIVE_ENABLED",
        "true" if S.messaging_compliance_archive_enabled else "false",
    ) not in ("0", "false", "False")


def _archive_enforce_write_success() -> bool:
    return os.getenv(
        "MESSAGING_COMPLIANCE_ARCHIVE_ENFORCE_WRITE_SUCCESS",
        "true" if S.messaging_compliance_archive_enforce_write_success else "false",
    ) not in ("0", "false", "False")


def _archive_storage_mode() -> str:
    return str(
        os.getenv(
            "MESSAGING_COMPLIANCE_ARCHIVE_STORAGE_MODE",
            S.messaging_compliance_archive_storage_mode,
        )
        .strip()
        .lower()
    )


def _archive_root_dir() -> str:
    return str(
        os.getenv(
            "MESSAGING_COMPLIANCE_ARCHIVE_ROOT_DIR",
            S.messaging_compliance_archive_root_dir,
        )
        .strip()
        or ".compliance_archive"
    )


def _append_failed_archive_event(event: MessagingArchiveEvent, *, error: str, root_dir: str | None = None) -> str:
    sink_root = Path(root_dir or _archive_root_dir())
    sink_root.mkdir(parents=True, exist_ok=True)
    p = sink_root / ".failed_archive_events.jsonl"
    row = {
        "event": event.model_dump(mode="json"),
        "error": str(error or "unknown"),
        "failed_at": int(time()),
    }
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        f.write("\n")
    return str(p)


def _default_archive_writer() -> ArchiveWriter:
    if _archive_storage_mode() == "filesystem":
        return FileArchiveWriter(root_dir=_archive_root_dir())
    return LogArchiveWriter()


def verify_partition_chain(
    *,
    root_dir: str,
    tenant_id: str,
    year: int,
    month: int,
    day: int,
    hour: int,
    initial_prev_hash: str = "0" * 64,
) -> tuple[bool, str]:
    """Verify chain continuity and object checksums for a partition manifest."""
    partition = f"{tenant_id}/{year:04d}/{month:02d}/{day:02d}/{hour:02d}"
    manifest_path = Path(root_dir) / partition / "manifest.jsonl"
    if not manifest_path.exists():
        record_messaging_archive_integrity_error(reason="manifest_missing")
        return False, "manifest_missing"

    prev_hash = initial_prev_hash
    lines = [ln for ln in manifest_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if not lines:
        record_messaging_archive_integrity_error(reason="manifest_empty")
        return False, "manifest_empty"

    for line in lines:
        entry = json.loads(line)
        object_path = Path(root_dir) / entry["object_key"]
        if not object_path.exists():
            record_messaging_archive_integrity_error(reason="object_missing")
            return False, f"object_missing:{entry['object_key']}"

        object_sha = hashlib.sha256(object_path.read_bytes()).hexdigest()
        if object_sha != entry.get("object_sha256"):
            record_messaging_archive_integrity_error(reason="object_checksum_mismatch")
            return False, f"object_checksum_mismatch:{entry['event_id']}"

        if entry.get("prev_hash") != prev_hash:
            record_messaging_archive_integrity_error(reason="chain_prev_mismatch")
            return False, f"chain_prev_mismatch:{entry['event_id']}"

        expected_chain = FileArchiveWriter._compute_chain_hash(
            prev_hash=prev_hash,
            payload_hash=entry.get("payload_hash", ""),
            event_id=entry.get("event_id", ""),
            event_ts=int(entry.get("event_ts", 0)),
        )
        if entry.get("chain_hash") != expected_chain:
            record_messaging_archive_integrity_error(reason="chain_hash_mismatch")
            return False, f"chain_hash_mismatch:{entry['event_id']}"
        prev_hash = entry["chain_hash"]

    chain_heads = FileArchiveWriter(root_dir=root_dir)._load_chain_heads_table()
    head = chain_heads.get(partition)
    if not head or head.get("head_hash") != prev_hash:
        record_messaging_archive_integrity_error(reason="chain_head_mismatch")
        return False, "chain_head_mismatch"

    return True, "ok"


def emit_messaging_archive_event(
    *,
    event_id: str,
    event_ts: int,
    tenant_id: str,
    conversation_id: str,
    message_id: str,
    actor_user_id: str,
    effective_user_id: str,
    event_type: str,
    payload: Mapping[str, Any],
    prev_hash: str = "0" * 64,
    writer: ArchiveWriter | None = None,
) -> str | None:
    """Emit immutable archive event using shared writer abstraction.

    Non-blocking mode: swallow writer failures and return None.
    Fail-closed mode: raise MessagingArchiveWriteError.
    """
    if not _archive_enabled():
        return None

    writer_impl = writer or _default_archive_writer()
    event = build_archive_event(
        event_id=event_id,
        event_ts=event_ts,
        tenant_id=tenant_id,
        conversation_id=conversation_id,
        message_id=message_id,
        actor_user_id=actor_user_id,
        effective_user_id=effective_user_id,
        event_type=event_type,
        payload=payload,
        prev_hash=prev_hash,
        schema_version=ARCHIVE_EVENT_SCHEMA_VERSION,
    )

    try:
        started = time_module.monotonic()
        object_key = writer_impl.write_event(event)
        elapsed = time_module.monotonic() - started
        record_messaging_archive_write(result="success", event_type=event.event_type, elapsed_seconds=elapsed)
        try:
            publish_supervisory_review_message(
                archive_object_key=object_key,
                event=event.model_dump(mode="json"),
            )
        except Exception:  # noqa: BLE001
            logger.warning(
                "messaging.supervisory_feed.publish_failed",
                extra={
                    "event_id": event.event_id,
                    "event_type": event.event_type,
                    "conversation_id": event.conversation_id,
                    "message_id": event.message_id,
                },
            )
        return object_key
    except Exception as exc:  # noqa: BLE001
        elapsed = time_module.monotonic() - started
        record_messaging_archive_write(result="failure", event_type=event.event_type, elapsed_seconds=elapsed)
        failed_events_path = _append_failed_archive_event(
            event,
            error=str(exc),
            root_dir=(writer_impl.root_dir if isinstance(writer_impl, FileArchiveWriter) else _archive_root_dir()),
        )
        logger.warning(
            "messaging.compliance_archive.write_failed",
            extra={
                "result": "failure",
                "tenant_id": event.tenant_id,
                "event_id": event.event_id,
                "event_type": event.event_type,
                "conversation_id": event.conversation_id,
                "message_id": event.message_id,
                "actor_user_id": event.actor_user_id,
                "object_key": f"{event.tenant_id}/{event.conversation_id}/{event.event_id}",
                "failed_events_path": failed_events_path,
                "enforce_write_success": _archive_enforce_write_success(),
                "error": str(exc),
            },
        )
        if _archive_enforce_write_success():
            raise MessagingArchiveWriteError("compliance archive write failed") from exc
        return None
