# Filemanager S3 mounts rollout runbook (FM-S3-6.3)

This runbook defines how to safely launch and roll back S3-backed file mounts in production.

## Owners
- Backend owner: Filemanager backend on-call
- On-call owner: Platform/API on-call
- Security owner: Credential + KMS policy owner

## Rollout controls
Feature flags used by this launch:
- `FILEMGR_S3_MOUNTS_ENABLED`
- `FILEMGR_S3_MOUNTS_WRITE_ENABLED`
- `FILEMGR_S3_MOUNTS_ALLOWED_BUCKET_PATTERNS`
- `FILEMGR_S3_MOUNTS_MAX_UPLOAD_BYTES`
- `FILEMGR_S3_MOUNTS_MAX_DOWNLOAD_BYTES`
- `FILEMGR_S3_MOUNTS_UPLOAD_RATE_PER_MINUTE`
- `FILEMGR_S3_MOUNTS_DOWNLOAD_RATE_PER_MINUTE`

## Environment enablement sequence

### Dev
1. Set `FILEMGR_S3_MOUNTS_ENABLED=1`.
2. Keep `FILEMGR_S3_MOUNTS_WRITE_ENABLED=0` for first verification.
3. Configure a strict allowlist, e.g. `FILEMGR_S3_MOUNTS_ALLOWED_BUCKET_PATTERNS=dev-*`.
4. Validate mount create/list/read.
5. Enable writes (`FILEMGR_S3_MOUNTS_WRITE_ENABLED=1`) and validate upload/delete/read-only enforcement.

### Staging
1. Promote same config as Dev with staging-scoped allowlist (e.g. `staging-*`).
2. Run FM-S3 integration tests (`tests/test_file_mounts_integration_moto.py`) in the gated integration job.
3. Execute a canary scenario:
   - create mount
   - list/read existing object
   - upload/read back
   - delete
   - set read-only and verify writes are denied
4. Keep write limits conservative for at least 24 hours.

### Production
1. Enable read-only path first:
   - `FILEMGR_S3_MOUNTS_ENABLED=1`
   - `FILEMGR_S3_MOUNTS_WRITE_ENABLED=0`
2. Restrict bucket allowlist to approved customer prefixes/accounts.
3. Monitor dashboards/alerts for one full on-call rotation.
4. Enable writes for a small canary cohort.
5. Gradually widen allowlist and write enablement.

## Monitoring and alerting
Monitor these signals split by provider/mode/operation (`local` vs `mounted`):
- mount operation latency (`list`, `read`, `write`, `delete`)
- mount bytes in/out
- mount error totals by AWS error code
- health worker counts (`active` vs `degraded` mounts)
- API error rates for mounted endpoints (403/404/413/429/502)

Alert thresholds (initial defaults):
- sustained 5xx mounted error rate > 2% for 10m
- sustained `SlowDown`/throttle errors > baseline + 3x for 10m
- degraded mounts > 5% of active mounts for 15m
- p95 mounted read or list latency > 2x local baseline for 15m

## Incident response and rollback

### Fast rollback (no deploy)
1. Disable writes immediately: `FILEMGR_S3_MOUNTS_WRITE_ENABLED=0`.
2. If issue persists, disable mounts globally: `FILEMGR_S3_MOUNTS_ENABLED=0`.
3. Keep allowlist unchanged (for audit trail), but no traffic should route to mounts when disabled.

### Partial rollback
- Narrow `FILEMGR_S3_MOUNTS_ALLOWED_BUCKET_PATTERNS` to remove affected cohorts.
- Reduce per-minute limits to control burst load.

### Verification after rollback
- Mounted route traffic drops to zero.
- Local filemanager traffic/error budget returns to baseline.
- No new mount write/delete events emitted.

## Escalation
- Primary: API on-call
- Secondary: Filemanager backend owner
- Security escalation: credential/KMS owner for auth/probe failures

## Sign-off
| Role | Name | Date | Status |
| --- | --- | --- | --- |
| Backend owner | TBD | TBD | Pending |
| On-call owner | TBD | TBD | Pending |

> Mark this runbook as **Approved** only after both rows are completed and checklist in `docs/filemanager-s3-mount-launch-checklist.md` is green.
