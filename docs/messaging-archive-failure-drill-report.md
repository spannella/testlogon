# Messaging Archive Object-Store Failure + Recovery Drill Report (FCA-020)

## Drill scenario
Simulated archive sink outage where writer throws exceptions during ingest, then sink recovers and buffered events are replayed.

## Procedure summary
1. Force writer failure path and confirm event buffering to `.failed_archive_events.jsonl`.
2. Run replay dry-run (`dry_run=True`) and confirm backlog remains intact.
3. Run replay execution and confirm buffered events are written to archive objects/manifests.
4. Validate backlog is drained (`remaining == 0`).

## Expected outcomes
- No archive event loss while sink is unavailable (events buffered locally).
- Recovery is operationally executable via replay tool without deploy.
- Integrity checks remain verifiable after replay.

## Evidence
- Automated tests:
  - `tests/test_messaging_archive_replay.py`
  - `tests/test_messaging_archive_writer.py`
- Observability checks:
  - archive write failure/success metrics
  - archive health dashboard and alerts.

## Sign-off
- [x] Drill executed in test simulation.
- [x] Replay + backfill workflow documented.
- [x] Integrity mismatch response runbook documented.
