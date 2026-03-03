from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from app.services.messaging_archive_writer import FileArchiveWriter
from app.services.messaging_compliance_archive_schema import MessagingArchiveEvent


@dataclass(frozen=True)
class ReplaySummary:
    attempted: int
    replayed: int
    failed: int
    remaining: int


def replay_failed_archive_events(*, root_dir: str, dry_run: bool = False, max_events: int | None = None) -> ReplaySummary:
    root = Path(root_dir)
    failed_path = root / ".failed_archive_events.jsonl"
    if not failed_path.exists():
        return ReplaySummary(attempted=0, replayed=0, failed=0, remaining=0)

    lines = [ln for ln in failed_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    writer = FileArchiveWriter(root_dir=str(root))

    attempted = replayed = failed = 0
    remaining_rows: list[dict] = []

    for ln in lines:
        row = json.loads(ln)
        evt = row.get("event") if isinstance(row, dict) else None
        if not isinstance(evt, dict):
            failed += 1
            remaining_rows.append({"event": {}, "error": "invalid_failed_event_row"})
            continue

        if max_events is not None and attempted >= max_events:
            remaining_rows.append(row)
            continue

        attempted += 1
        if dry_run:
            replayed += 1
            continue

        try:
            event = MessagingArchiveEvent(**evt)
            writer.write_event(event)
            replayed += 1
        except Exception as exc:  # noqa: BLE001
            failed += 1
            row["error"] = str(exc)
            remaining_rows.append(row)

    if dry_run:
        remaining = len(lines)
        return ReplaySummary(attempted=attempted, replayed=replayed, failed=failed, remaining=remaining)

    if remaining_rows:
        with failed_path.open("w", encoding="utf-8") as f:
            for row in remaining_rows:
                f.write(json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
    else:
        failed_path.unlink(missing_ok=True)

    return ReplaySummary(
        attempted=attempted,
        replayed=replayed,
        failed=failed,
        remaining=len(remaining_rows),
    )
