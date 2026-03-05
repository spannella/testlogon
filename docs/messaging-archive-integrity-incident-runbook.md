# Messaging Archive Integrity Mismatch Incident Runbook (FCA-020)

## Trigger
Any firing of `MessagingArchiveIntegrityChainMismatch` alert.

## Immediate actions
1. Declare compliance incident.
2. Freeze destructive operations for affected tenant/partition.
3. Capture evidence:
   - `manifest.jsonl`
   - object referenced by failing `event_id`
   - `.chain_heads_table.json`

## Diagnosis steps
1. Run `verify_partition_chain` for affected partition.
2. Identify mismatch reason:
   - `manifest_missing` / `manifest_empty`
   - `object_checksum_mismatch`
   - `chain_prev_mismatch` / `chain_hash_mismatch`
   - `chain_head_mismatch`
3. Correlate with infrastructure incidents (storage outage, partial writes, operator actions).

## Recovery guidance
- For missing write paths after outage: execute replay/backfill runbook.
- For checksum mismatch: restore object from immutable backup/snapshot; do not rewrite content ad hoc.
- For chain-head mismatch only: rebuild chain-head from manifest scan and document change ticket.

## Communication
- Notify Compliance + Security + Messaging on-call.
- Record timeline and affected event range.
- Provide post-incident report with root cause and preventive controls.
