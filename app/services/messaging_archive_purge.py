from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from time import time
from typing import Any, Iterable

from app.core.tables import T
from app.services.messaging_archive_retention import evaluate_archive_retention_decision
from app.services.messaging_archive_writer import _archive_root_dir

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PurgeRecordDecision:
    tenant_id: str
    partition: str
    event_id: str
    conversation_id: str
    message_id: str
    event_type: str
    event_ts: int
    object_key: str
    action: str
    reason: str
    legal_hold_active: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "partition": self.partition,
            "event_id": self.event_id,
            "conversation_id": self.conversation_id,
            "message_id": self.message_id,
            "event_type": self.event_type,
            "event_ts": self.event_ts,
            "object_key": self.object_key,
            "action": self.action,
            "reason": self.reason,
            "legal_hold_active": self.legal_hold_active,
        }


@dataclass(frozen=True)
class PurgeRunSummary:
    dry_run: bool
    scanned: int
    deleted: int
    skipped: int
    held_skips: int


def _iter_manifest_paths(root_dir: Path) -> Iterable[Path]:
    if not root_dir.exists():
        return []
    return root_dir.glob("*/[0-9][0-9][0-9][0-9]/[0-9][0-9]/[0-9][0-9]/[0-9][0-9]/manifest.jsonl")


def _load_active_legal_holds() -> set[tuple[str, str, str]]:
    """Return held records as (tenant_id, conversation_id, message_id|"*")."""
    holds: set[tuple[str, str, str]] = set()
    try:
        resp = T.message_legal_holds.scan()
    except Exception:
        logger.exception("messaging.archive_purge.load_holds_failed")
        return holds

    items = list(resp.get("Items", []))
    while resp.get("LastEvaluatedKey"):
        try:
            resp = T.message_legal_holds.scan(ExclusiveStartKey=resp["LastEvaluatedKey"])
        except Exception:
            break
        items.extend(resp.get("Items", []))

    for item in items:
        if str(item.get("status") or "") != "active":
            continue
        tenant_id = str(item.get("tenant_id") or "default")
        conversation_id = str(item.get("conversation_id") or "")
        message_id = str(item.get("message_id") or "") or "*"
        if conversation_id:
            holds.add((tenant_id, conversation_id, message_id))
    return holds


def _is_held(*, holds: set[tuple[str, str, str]], tenant_id: str, conversation_id: str, message_id: str) -> bool:
    return (tenant_id, conversation_id, message_id) in holds or (tenant_id, conversation_id, "*") in holds


def _append_purge_ledger(*, root_dir: Path, run_ts: int, decision: PurgeRecordDecision) -> None:
    ledger_path = root_dir / ".purge_ledger.jsonl"
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(
        {
            "run_ts": run_ts,
            **decision.as_dict(),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    with ledger_path.open("a", encoding="utf-8") as f:
        f.write(line)
        f.write("\n")


def run_archive_retention_purge(
    *,
    root_dir: str | None = None,
    now_ts: int | None = None,
    dry_run: bool = True,
    active_holds: set[tuple[str, str, str]] | None = None,
) -> PurgeRunSummary:
    """Evaluate and execute hold-aware purge decisions across archive partitions."""
    run_ts = int(now_ts if now_ts is not None else time())
    root = Path(root_dir or _archive_root_dir())
    holds = set(active_holds) if active_holds is not None else _load_active_legal_holds()

    scanned = 0
    deleted = 0
    skipped = 0
    held_skips = 0

    for manifest_path in _iter_manifest_paths(root):
        partition = str(manifest_path.relative_to(root).parent)
        tenant_id = partition.split("/", 1)[0] if "/" in partition else "default"
        lines = [ln for ln in manifest_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        for line in lines:
            scanned += 1
            entry = json.loads(line)
            conversation_id = str(entry.get("conversation_id") or "")
            message_id = str(entry.get("message_id") or "")
            legal_hold_active = _is_held(
                holds=holds,
                tenant_id=tenant_id,
                conversation_id=conversation_id,
                message_id=message_id,
            )
            decision = evaluate_archive_retention_decision(
                tenant_id=tenant_id,
                event_type=str(entry.get("event_type") or "message.sent"),
                event_ts=int(entry.get("event_ts", 0) or 0),
                now_ts=run_ts,
                legal_hold_active=legal_hold_active,
            )

            object_key = str(entry.get("object_key") or "")
            object_path = root / object_key
            if not decision.purge_eligible:
                reason = "legal_hold_active" if legal_hold_active else "retention_not_elapsed"
                if legal_hold_active:
                    held_skips += 1
                skipped += 1
                record = PurgeRecordDecision(
                    tenant_id=tenant_id,
                    partition=partition,
                    event_id=str(entry.get("event_id") or ""),
                    conversation_id=conversation_id,
                    message_id=message_id,
                    event_type=str(entry.get("event_type") or ""),
                    event_ts=int(entry.get("event_ts", 0) or 0),
                    object_key=object_key,
                    action="skipped",
                    reason=reason,
                    legal_hold_active=legal_hold_active,
                )
                _append_purge_ledger(root_dir=root, run_ts=run_ts, decision=record)
                continue

            if dry_run:
                skipped += 1
                record = PurgeRecordDecision(
                    tenant_id=tenant_id,
                    partition=partition,
                    event_id=str(entry.get("event_id") or ""),
                    conversation_id=conversation_id,
                    message_id=message_id,
                    event_type=str(entry.get("event_type") or ""),
                    event_ts=int(entry.get("event_ts", 0) or 0),
                    object_key=object_key,
                    action="dry_run_would_purge",
                    reason="eligible",
                    legal_hold_active=legal_hold_active,
                )
                _append_purge_ledger(root_dir=root, run_ts=run_ts, decision=record)
                continue

            if object_path.exists():
                object_path.unlink()
                deleted += 1
                action = "purged"
                reason = "eligible"
            else:
                skipped += 1
                action = "skipped"
                reason = "object_missing"

            record = PurgeRecordDecision(
                tenant_id=tenant_id,
                partition=partition,
                event_id=str(entry.get("event_id") or ""),
                conversation_id=conversation_id,
                message_id=message_id,
                event_type=str(entry.get("event_type") or ""),
                event_ts=int(entry.get("event_ts", 0) or 0),
                object_key=object_key,
                action=action,
                reason=reason,
                legal_hold_active=legal_hold_active,
            )
            _append_purge_ledger(root_dir=root, run_ts=run_ts, decision=record)

    logger.info(
        "messaging.archive_purge.summary",
        extra={
            "dry_run": dry_run,
            "scanned": scanned,
            "deleted": deleted,
            "skipped": skipped,
            "held_skips": held_skips,
        },
    )
    return PurgeRunSummary(dry_run=dry_run, scanned=scanned, deleted=deleted, skipped=skipped, held_skips=held_skips)


def run_scheduled_archive_retention_job(*, dry_run: bool = True, now_ts: int | None = None) -> PurgeRunSummary:
    """Entry point for scheduler/cron-driven retention execution."""
    return run_archive_retention_purge(dry_run=dry_run, now_ts=now_ts)
