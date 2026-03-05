# Messaging Archive Replay + Backfill Runbook (FCA-020)

## Purpose
Use this runbook when archive sink/object-store outages prevent immediate archive writes and events are buffered in `.failed_archive_events.jsonl`.

## Tooling
- Replay tool: `app/services/messaging_archive_replay.py`
- Entry-point function: `replay_failed_archive_events(root_dir, dry_run=False, max_events=None)`

## Preconditions
1. Archive sink is healthy again.
2. `MESSAGING_COMPLIANCE_ARCHIVE_ENABLED=true`.
3. If fail-closed mode was enabled during incident, decide whether to temporarily set `MESSAGING_COMPLIANCE_ARCHIVE_ENFORCE_WRITE_SUCCESS=false` for controlled backfill windows.

## Dry-run validation
Run in a Python shell/job wrapper:

```python
from app.services.messaging_archive_replay import replay_failed_archive_events
summary = replay_failed_archive_events(root_dir=".compliance_archive", dry_run=True)
print(summary)
```

Expected: `attempted > 0` and source backlog file remains unchanged.

## Replay execution
```python
from app.services.messaging_archive_replay import replay_failed_archive_events
summary = replay_failed_archive_events(root_dir=".compliance_archive")
print(summary)
```

Success criteria:
- `failed == 0`
- `remaining == 0`
- `.failed_archive_events.jsonl` removed (or empty)

## Backfill chunking
For large backlogs, replay in bounded batches:

```python
summary = replay_failed_archive_events(root_dir=".compliance_archive", max_events=500)
```

Repeat until `remaining == 0`.

## Post-recovery checks
1. Verify archive health dashboard (`docs/dashboards/messaging-archive-health-dashboard.json`) failure ratios return to baseline.
2. Verify no active integrity alert (`MessagingArchiveIntegrityChainMismatch`).
3. Validate chain integrity for affected partitions using `verify_partition_chain`.

## Escalation
If replay continues to fail:
- preserve `.failed_archive_events.jsonl`
- open Sev incident
- attach failing row sample + error string
- follow integrity incident runbook.
