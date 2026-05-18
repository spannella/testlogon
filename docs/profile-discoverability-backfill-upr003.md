# UPR-003 Discoverability Backfill Runbook

Script: `scripts/backfill_profile_discoverability_state.py`

## What it does
Initializes `discoverability_status` for existing users by scanning users and reconciling account-state rows.

Target states:
- `active`
- `hidden`
- `deactivated`
- `deleted`

Default behavior for legacy/missing data:
- If `discoverability_status` is missing, derive from legacy `status` when possible.
- If no known discoverability can be derived, default to `active`.

## Usage
Dry-run (default):

```bash
python scripts/backfill_profile_discoverability_state.py --report-file upr003-dry-run.json
```

Apply writes:

```bash
python scripts/backfill_profile_discoverability_state.py --apply --report-file upr003-apply.json
```

## Report format
The script writes machine-readable JSON with:
- `stats` (including counts by target state, skipped, and errors)
- `candidates`
- `errors`
- `generated_at`

## Idempotency
The script only writes rows where `discoverability_status` is missing or stale/malformed. Re-running after a successful apply should produce `updated=0` unless data changed since the prior run.
