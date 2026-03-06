# Filemanager S3 mounts launch checklist (FM-S3-6.3)

Use this checklist for go/no-go decisions during S3 mounts launch.

## Preconditions
- [ ] Runbook reviewed: `docs/filemanager-s3-mount-rollout-runbook.md`
- [ ] Feature flags documented in environment config.
- [ ] Bucket allowlist reviewed by backend + security owners.
- [ ] Health worker schedule enabled in target environment.
- [ ] Dashboards and alerts deployed.

## Functional validation
- [ ] Create mount succeeds for allowlisted bucket.
- [ ] Create mount blocked for non-allowlisted bucket.
- [ ] Mounted list/read works.
- [ ] Mounted upload/delete works when `read_write` is enabled.
- [ ] Mounted write/delete blocked with `mount_read_only` on read-only mounts.
- [ ] Existing non-mounted filemanager list/download/upload/delete behavior unchanged.

## Reliability and safety
- [ ] Mounted size limits enforced with clear 413 errors.
- [ ] Mounted rate limits enforced with clear 429 errors.
- [ ] AWS error mapping returns provider-agnostic API errors (no provider-specific client branching required).
- [ ] Health failures mark only affected mounts degraded and do not block healthy mounts.

## Testing gates
- [ ] Unit tests pass for mount and credential flows.
- [ ] Integration test command/job for moto/localstack passes.
- [ ] Smoke test executed in staging with canary account.

## Go / no-go criteria

### Go
- [ ] Mounted 5xx error rate within SLO for 24h canary period.
- [ ] No critical security findings for credential handling/KMS use.
- [ ] No regressions in non-mounted traffic.
- [ ] On-call and backend owners signed runbook.

### No-go (block launch)
- [ ] Any unresolved P0/P1 defect in mounted CRUD/read/write flows.
- [ ] Missing rollback owner or inability to flip flags quickly.
- [ ] Missing alert coverage for mounted 5xx, throttling, or degraded mount growth.

## Sign-off
| Role | Name | Date | Decision |
| --- | --- | --- | --- |
| Backend owner | TBD | TBD | Pending |
| On-call owner | TBD | TBD | Pending |

Final decision:
- [ ] **GO**
- [ ] **NO-GO**
