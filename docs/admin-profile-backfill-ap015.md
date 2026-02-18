# AP-015 admin profile backfill runbook

## Goal
Backfill existing `role=admin` users to explicit `admin_profile.type=general` so they retain broad admin capabilities during scoped-admin rollout.

## Script
Use:

- `scripts/backfill_admin_profiles_general.py`

## Behavior

- **Idempotent**:
  - skips non-admin users,
  - skips admins already set to `{"type":"general"}`,
  - skips admins already explicitly scoped,
  - only targets admins with missing/malformed profile payloads that normalize to `general`.
- Supports **dry-run by default**.
- Supports JSON **report output** for review/audit.

## Commands

### 1) Dry-run with report (recommended first)

```bash
python scripts/backfill_admin_profiles_general.py --report-file ap015-dry-run.json
```

### 2) Apply migration

```bash
python scripts/backfill_admin_profiles_general.py --apply --report-file ap015-apply.json
```

### 3) Re-run safely

Re-running is safe and should produce zero or reduced candidates once migration is complete.

```bash
python scripts/backfill_admin_profiles_general.py --apply --report-file ap015-rerun.json
```

## Rollback notes

This migration only writes explicit general profile state for legacy admin users. Existing scoped admins are not modified.

If rollback is needed:

1. Use `ap015-apply.json` candidate list to identify touched users.
2. For each touched user, either:
   - remove `admin_profile` to restore pre-backfill implicit behavior, or
   - set a corrected explicit profile (`general`/`scoped`) via root role-management API/UI.

Because runtime normalization already treats missing/malformed admin profile as `general`, rollback risk is low for access continuity.
