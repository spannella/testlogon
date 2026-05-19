# Newsfeed Tip-Lottery Rollout Runbook (LOT-012)

## Scope

This runbook covers production rollout for the `tip_lottery` lock strategy on newsfeed posts, including:

- schema-safe backend deploy sequencing,
- legacy data backfill,
- post-deploy validation,
- rollback and lottery-create disable procedures.

---

## Prerequisites

- Backend release with:
  - `CreatePostRequest` / `PostResponse` support for `lock_type` + `lottery_*` fields.
  - read-path normalization for legacy rows (`unlock_price_cents` -> `lock_type=fixed_price` inference).
  - `scripts/backfill_newsfeed_lock_type.py`.
- Access to application logs, API metrics, and DynamoDB read/write dashboards.
- Operator access to run backfill script in each environment.

---

## Rollout Order (Required)

1. **Deploy backend read/write support first**
   - Deploy API servers containing lottery schema support and legacy read normalization.
   - Do **not** run backfill before this deploy.

2. **Smoke test API behavior in target environment**
   - Create fixed-price post and verify existing unlock flow still works.
   - Create `tip_lottery` post and verify response includes:
     - `lock_type=tip_lottery`
     - `lottery_tip_cents`
     - `lottery_quiet_period_seconds`
     - `lottery_state=open`
     - `lottery_version=0`

3. **Run backfill in dry-run mode**
   - Command:
     - `python scripts/backfill_newsfeed_lock_type.py --dry-run --page-limit 200`
   - Capture output values:
     - `scanned`
     - `eligible`
     - `planned_updates`
     - `applied_updates` (should be `0` in dry-run)

4. **Run backfill in apply mode**
   - Command:
     - `python scripts/backfill_newsfeed_lock_type.py --page-limit 200`
   - Record output values and runtime.
   - Re-run once to confirm idempotency (`planned_updates=0`, `applied_updates=0` expected on second run).

5. **Verify metrics and error rates**
   - Monitor for at least 30–60 minutes after rollout/backfill:
     - 4xx/5xx rates on `POST /posts`, `GET /posts/{id}`, `GET /feed`
     - DynamoDB throttling / error rates
     - app logs containing `invalid_lock_configuration` and serialization errors

6. **Enable by environment using feature flag**
   - Backend toggle: `NEWSFEED_TIP_LOTTERY_ENABLED`
   - Frontend toggle: `VITE_NEWSFEED_TIP_LOTTERY_ENABLED`
   - Recommended staged values:
     - Dev: backend `true`, frontend `true`
     - Staging: backend `true`, frontend `true` after QA sign-off
     - Prod canary: backend `true`, frontend `false` (observe create-path protections)
     - Prod full rollout: backend `true`, frontend `true`

---

## Post-Deploy Validation Checklist

- [ ] `POST /posts` with fixed-price payload still succeeds.
- [ ] `POST /posts` with lottery payload succeeds and returns lottery defaults (`open`, `0` version).
- [ ] `GET /posts/{id}` returns lottery fields for lottery posts.
- [ ] `GET /feed` shows lottery fields for lottery posts.
- [ ] Legacy post without `lock_type` but with positive `unlock_price_cents` reads as `lock_type=fixed_price`.
- [ ] Backfill dry-run completes without write errors.
- [ ] Backfill apply completes and idempotent re-run is clean.

---

## Suggested Validation Queries

Use DynamoDB PartiQL (or equivalent table inspection tooling) after apply run:

1. **Legacy rows still missing lock_type with positive unlock price** (should trend to zero):
   ```sql
   SELECT post_id, unlock_price_cents
   FROM "app_single_table"
   WHERE Entity='Post'
     AND unlock_price_cents > 0
     AND (lock_type IS MISSING OR lock_type IS NULL)
   LIMIT 100;
   ```

2. **Lottery rows sanity check**:
   ```sql
   SELECT post_id, lock_type, lottery_tip_cents, lottery_quiet_period_seconds, lottery_state, lottery_version
   FROM "app_single_table"
   WHERE Entity='Post'
     AND lock_type='tip_lottery'
   LIMIT 100;
   ```

3. **Invalid lock combinations** (should be zero):
   ```sql
   SELECT post_id, lock_type, unlock_price_cents, lottery_tip_cents, lottery_quiet_period_seconds
   FROM "app_single_table"
   WHERE Entity='Post'
     AND (
       (lock_type='tip_lottery' AND unlock_price_cents > 0) OR
       (lock_type='fixed_price' AND (lottery_tip_cents IS NOT MISSING OR lottery_quiet_period_seconds IS NOT MISSING))
     )
   LIMIT 100;
   ```

---

## Dashboards / Alerts to Watch

Minimum recommended monitors during rollout window:

- **API availability**
  - `POST /posts` 5xx rate
  - `GET /posts/{id}` 5xx rate
  - `GET /feed` 5xx rate
- **Validation drift**
  - count of 400 responses for lock configuration errors
  - sudden spikes in `invalid_lock_configuration` messages
- **Data-store health**
  - DynamoDB throttles
  - DynamoDB conditional/check failures (if any)
  - elevated latency on read/write operations

---

## Rollback and Disable Plan

### Safe behavior when `lock_type` is absent

Read paths remain safe because legacy rows with positive `unlock_price_cents` are normalized to `lock_type=fixed_price` at serialization time. This allows rollback without requiring immediate data rewrites.

### Disable lottery create path

If lottery create traffic must be halted immediately:

1. **Preferred operational action:** set `NEWSFEED_TIP_LOTTERY_ENABLED=false` and redeploy API.
2. **Emergency edge control:** apply API gateway/WAF rule that blocks requests where body contains `lock_type":"tip_lottery"` for `POST /posts`.
3. Set `VITE_NEWSFEED_TIP_LOTTERY_ENABLED=false` for frontend to hide lottery controls/metadata.
4. Keep read-path support active so existing lottery posts remain readable while create is disabled.

### Full rollback

1. Roll back API to previous stable build.
2. Keep backfilled data (safe; additional `lock_type` field is additive).
3. Validate fixed-price create/read paths and feed rendering.
4. Track and remediate any client retries targeting `tip_lottery` create payloads.

---

## Environment Progression

- **Dev**: run full checklist + dry-run/apply backfill on small dataset.
- **Staging**: repeat and validate dashboards/alerts + smoke tests from web UI.
- **Prod**: canary deploy backend, then run dry-run/apply backfill, then full rollout.

## Toggle Ownership

- **Backend toggle owner:** Backend Platform / API on-call.
- **Frontend toggle owner:** Web Platform / Frontend on-call.
- **Approval authority for prod enablement:** Release Manager + Service Owner.
