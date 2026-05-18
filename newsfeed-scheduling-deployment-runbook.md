# Newsfeed Scheduling Deployment & Migration Runbook (NFS-028)

> Scope: deploy scheduled-post lifecycle safely across **staging** and **production**.
>
> Covers: schema migration order, worker startup, due-index backfill, explicit checkpoints, post-deploy verification, rollback, and incident fallback.

---

## 0) Prerequisites

- Release artifact includes:
  - API/router changes (`app/routers/newsfeed.py`)
  - scheduler service (`app/services/newsfeed_scheduler.py`)
  - worker wrapper (`scripts/newsfeed-scheduler-worker.py`)
  - migration script (`scripts/migrations/20260405_newsfeed_schedule_due_index.py`)
  - backfill script (`scripts/backfill_newsfeed_schedule_due_index.py`)
- Feature flags available:
  - `NEWSFEED_SCHEDULING_API_ENABLED`
  - `NEWSFEED_SCHEDULING_WORKER_ENABLED`
  - `VITE_NEWSFEED_SCHEDULING_UI_ENABLED`
- DynamoDB table + credentials for target environment.

---

## 1) Deployment order (must-follow)

1. **Deploy API code with scheduling flags OFF**
   - `NEWSFEED_SCHEDULING_API_ENABLED=false`
   - `NEWSFEED_SCHEDULING_WORKER_ENABLED=false`
   - `VITE_NEWSFEED_SCHEDULING_UI_ENABLED=false`
2. **Run schema migration** to create schedule due index.
3. **Run backfill** to populate due-index attributes for existing scheduled rows.
4. **Enable worker only** (API/UI still OFF) and observe metrics/logs.
5. **Enable API** for internal users/cohort.
6. **Enable UI** last.

This order minimizes user-facing blast radius while proving backend correctness first.

---

## 2) Staging runbook (executable)

### Step S1 — Deploy backend artifact (flags off)

**Checkpoint S1**
- Service healthy (`/health` or equivalent).
- No schedule endpoints reachable for clients (`schedule_feature_disabled` expected).

### Step S2 — Run migration

```bash
python3 scripts/migrations/20260405_newsfeed_schedule_due_index.py
```

**Checkpoint S2**
- Migration exits 0.
- GSI `GSI_SCHEDULE_DUE` exists and is `ACTIVE`.

### Step S3 — Run backfill (dry-run then apply)

```bash
python3 scripts/backfill_newsfeed_schedule_due_index.py --dry-run
python3 scripts/backfill_newsfeed_schedule_due_index.py
```

**Checkpoint S3**
- Dry-run reports expected candidate count.
- Apply run reports updated rows > 0 when scheduled rows exist.
- No unexpected errors in output.

### Step S4 — Enable worker only

Set:
- `NEWSFEED_SCHEDULING_WORKER_ENABLED=true`
- keep API/UI disabled.

Start worker (single-iteration canary):

```bash
NEWSFEED_SCHEDULER_ITERATIONS=1 python3 scripts/newsfeed-scheduler-worker.py
```

Then start normal loop/process supervisor.

**Checkpoint S4**
- Worker logs show successful loop summary.
- No sustained `error_threshold_breach` / `lag_threshold_breach`.

### Step S5 — Enable API for internal testing

Set:
- `NEWSFEED_SCHEDULING_API_ENABLED=true`
- keep UI disabled.

Internal API flow:
1. Create scheduled post (`publish_at` ~ +2 min).
2. Confirm absent from `/feed` before due.
3. Confirm appears in `/posts/scheduled` for owner.
4. Edit schedule and confirm updated metadata.
5. Cancel one post and confirm removal from scheduled listing.

**Checkpoint S5**
- All API lifecycle operations return expected statuses.
- Scheduled post publishes when due with worker on.

### Step S6 — Enable UI

Set:
- `VITE_NEWSFEED_SCHEDULING_UI_ENABLED=true`

**Checkpoint S6**
- Composer schedule controls visible.
- Scheduled panel visible.
- Edit dialog schedule controls visible for scheduled posts.

---

## 3) Production runbook (executable)

Use same sequence as staging, with hold points and approvals.

### Step P1 — Change window start + preflight
- Confirm on-call + rollback owner assigned.
- Capture baseline metrics (last 24h):
  - API error rate
  - worker error logs
  - feed publish throughput

### Step P2 — Backend deploy (flags off)
- Deploy API artifact.
- Validate health and zero elevated 5xx.

### Step P3 — Migration + backfill
- Run migration once.
- Run backfill dry-run then apply.
- If backfill is large, run in controlled batches.

### Step P4 — Worker canary
- Enable worker on 1 instance/process.
- Observe for 15–30 min:
  - publish outcomes (`published`, `retry_exhausted`, `error`)
  - lag and alert counters
- Expand to full worker fleet after stable canary.

### Step P5 — API rollout
- Enable API for internal/cohort only first (if tenant-scoped config available).
- Monitor 30–60 min.
- Expand to full API audience after pass.

### Step P6 — UI rollout
- Enable UI cohort first.
- Expand to GA after monitoring window passes.

**Production release gate (must pass)**
- No sustained scheduler error threshold breaches.
- Publish lag remains within agreed SLO.
- No regression in immediate-post publish path.

---

## 4) Post-deploy verification queries

## 4.1 API checks (manual/cURL)

> Replace `<COOKIE>` and `<CSRF>` with a valid session.

```bash
# create scheduled
curl -sS -X POST http://localhost:8000/posts \
  -H "x-csrf-token: <CSRF>" -H "Cookie: <COOKIE>" -H "Content-Type: application/json" \
  -d '{"body":"deploy check scheduled","publish_at":1893456000,"schedule_timezone":"UTC","scheduled_at_local":"2030-01-01T00:00"}'

# list scheduled
curl -sS http://localhost:8000/posts/scheduled -H "x-csrf-token: <CSRF>" -H "Cookie: <COOKIE>"

# cancel scheduled
curl -sS -X POST http://localhost:8000/posts/<POST_ID>/cancel -H "x-csrf-token: <CSRF>" -H "Cookie: <COOKIE>"
```

## 4.2 Worker verification command

```bash
NEWSFEED_SCHEDULER_ITERATIONS=1 python3 scripts/newsfeed-scheduler-worker.py
```

Expected: summary JSON with keys including `published`, `retry_exhausted`, `backlog_due`, `max_publish_lag_seconds`, `worker_enabled`.

## 4.3 DynamoDB spot checks (AWS CLI)

```bash
# Verify due-index query returns rows when due rows exist
aws dynamodb query \
  --table-name "$APP_TABLE" \
  --index-name "GSI_SCHEDULE_DUE" \
  --key-condition-expression "GSI_SCHEDULE_PK = :pk AND GSI_SCHEDULE_SK <= :sk" \
  --expression-attribute-values '{":pk":{"S":"SCHEDULED"},":sk":{"S":"999999999999#POST#~"}}' \
  --select COUNT
```

```bash
# Spot-check a scheduled post item has schedule fields / index attrs
aws dynamodb get-item \
  --table-name "$APP_TABLE" \
  --key '{"pk":{"S":"POST#<POST_ID>"},"sk":{"S":"META"}}'
```

---

## 5) Rollback procedures

## 5.1 Fast rollback (recommended first)

1. Disable worker:
   - `NEWSFEED_SCHEDULING_WORKER_ENABLED=false`
2. Disable UI:
   - `VITE_NEWSFEED_SCHEDULING_UI_ENABLED=false`
3. Disable API:
   - `NEWSFEED_SCHEDULING_API_ENABLED=false`

This halts new scheduling operations and publishes while preserving data.

## 5.2 Code rollback

- Roll back API and worker artifacts to previous stable release.
- Keep flags disabled until root cause is identified.

## 5.3 Migration rollback

- **Do not drop the due index during incident response** unless explicitly required.
- Prefer operational rollback via flags.
- If a schema rollback is required, execute a separate approved migration plan.

---

## 6) Incident fallback playbook

## Trigger conditions
- Repeated `retry_exhausted` / `error` publish outcomes.
- Lag threshold alerts sustained beyond one monitoring window.
- Data integrity symptom (scheduled posts published prematurely or never published).

## Immediate actions (first 15 minutes)
1. Set `NEWSFEED_SCHEDULING_WORKER_ENABLED=false`.
2. Page incident channel and assign incident commander.
3. Snapshot:
   - latest worker summary payloads
   - relevant API/worker logs
   - current feature flag values

## Diagnosis checklist
- DynamoDB throttling/RCU-WCU saturation?
- Index health and query cardinality?
- Transaction conflicts elevated?
- Invalid schedule payload patterns from client?

## Recovery path
- Fix root cause.
- Run worker in canary mode (`ITERATIONS=1`) repeatedly until stable.
- Re-enable worker -> API -> UI in that order.

---

## 7) Operational checkpoints matrix

- **CP-1 (post-migration):** GSI active.
- **CP-2 (post-backfill):** due-index attrs populated for historical scheduled rows.
- **CP-3 (worker canary):** zero sustained errors, reasonable lag.
- **CP-4 (API cohort):** create/list/edit/cancel pass.
- **CP-5 (UI cohort):** scheduling controls + panel behave as expected.
- **CP-6 (GA):** 24h stable metrics, no incident triggers.

---

## 8) Ownership

- Release owner: Backend on-call engineer.
- Worker owner: Platform/background-jobs on-call.
- Rollback approver: Incident commander / Eng manager on duty.
