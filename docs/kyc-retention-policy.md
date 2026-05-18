# KYC Retention & Purge Policy

## Status retention windows

- `rejected`: purge after **30 days** (config: `KYC_RETENTION_REJECTED_DAYS`)
- `expired`: purge after **7 days** (config: `KYC_RETENTION_EXPIRED_DAYS`)
- `approved`: retained for audit horizon (config placeholder: `KYC_RETENTION_APPROVED_DAYS`)

## Purge behavior

- Purge job processes eligible `rejected|expired` cases.
- Sensitive artifact references are redacted:
  - questionnaire links
  - file references
  - signature references
  - submission evidence snapshot/hash
- Case is tombstoned as `expired` with `review.purged_at` and `submission.purged_at`.
- Applicant reads after purge return `kyc_case_not_found` (predictable post-purge semantics).

## Operational workflow

- Admin-triggered job endpoint: `POST /v1/kyc/cases/admin/purge/run?dry_run=true|false`
- Recommended schedule:
  - daily dry-run report
  - daily execution run

## Auditing & monitoring

- Each purge run emits `kyc_retention_purge_run` audit event with:
  - `purged_count`
  - `purged_case_ids`
  - `dry_run`
  - `correlation_id`
- Alert when purge run repeatedly purges `0` for >7 days in active environments (potential scheduler failure).
