# Newsfeed Rich Content No-Downtime Migration Runbook

## Purpose

Define a **no-downtime** migration strategy for rolling out the newsfeed rich-content envelope (`body_plain`, `body_markdown`, `body_rich`, `body_format`, `body_version`) while preserving compatibility for legacy rows and mixed client versions.

## Scope

- Posts + comments read/write paths.
- Backend serializers, request models, and persistence.
- Frontend clients with mixed release versions.
- Operational rollback for each phase.

## Compatibility guarantees

- Legacy records containing only `body` remain readable during all phases.
- Legacy clients sending only `body` remain writable during all phases.
- New clients can send/read `plain`, `markdown`, and `rich` payloads without requiring a full backfill first.

## Migration phases

## Phase 0 — Preconditions

1. Ensure feature flags are available and defaulted safely:
   - `newsfeed_markdown_enabled = false`
   - `newsfeed_richtext_enabled = false`
2. Deploy backend read-path support that can resolve content from either:
   - new envelope fields, or
   - legacy `body` fallback.
3. Verify dashboards/alerts exist for:
   - request validation failures,
   - serializer fallback rates,
   - client render fallback rates,
   - 4xx/5xx error changes on post/comment APIs.

Exit criteria:
- Backend can serve old and new shapes safely before any frontend behavior change.

## Phase 1 — Dual-read (required first deploy)

Behavior:
- **Read:** Prefer envelope fields when present.
- **Read fallback:** If envelope fields are missing/partial, fall back to legacy `body` and derive safe plain content.
- **Write:** Keep current behavior unchanged until Phase 2.

Operational checks:
- Compare feed render outcomes for legacy-heavy cohorts.
- Confirm no increase in empty-body responses for old rows.

Rollback:
- Keep code deployed; disable markdown/rich feature flags if any UI regression appears.
- Because this phase is read-only behavior expansion, rollback is low-risk and does not require data revert.

## Phase 2 — Dual-write (mixed client safe)

Behavior:
- Accept both payload styles:
  - legacy `body`, and
  - envelope format fields.
- Persist envelope fields for all writes from new clients.
- Continue writing/deriving legacy-compatible `body` from `body_plain` for backward compatibility.

Ordering requirements:
1. Backend dual-read must already be live (Phase 1 complete).
2. Then enable frontend markdown mode (incremental cohort).
3. Then enable frontend rich mode (incremental cohort).

Operational checks:
- Monitor ratio of legacy writes vs envelope writes.
- Confirm old clients can still create/edit without validation regressions.
- Confirm new content round-trips (`create -> get -> edit -> get`) across formats.

Rollback:
- Disable `newsfeed_richtext_enabled` first, then `newsfeed_markdown_enabled` if needed.
- Keep dual-read enabled; do **not** remove envelope reads during rollback.
- If needed, hotfix to force serializer output format to plain fallback while preserving stored source fields.

## Phase 3 — Cleanup / convergence (optional, post-stability)

Prerequisites:
- Sustained stable error budget for at least one release window.
- Legacy-client traffic below agreed threshold.
- Migration metrics show acceptable fallback/validation rates.

Actions:
1. Optional background backfill:
   - Fill missing `body_plain`/`body_format` for historical rows.
   - Do not rewrite content semantics; preserve original text.
2. Keep dual-read permanently (recommended) or deprecate legacy-only paths only after formal API deprecation notice.
3. Update API docs to mark `body` as legacy compatibility field.

Rollback:
- Cleanup tasks are reversible by stopping backfill jobs.
- Do not delete legacy read compatibility until at least one full client upgrade cycle is complete.

## Deployment ordering (safe sequence)

1. Deploy backend with dual-read support.
2. Deploy backend with dual-write support + validations.
3. Enable markdown UI for small cohort.
4. Enable rich-text UI for small cohort.
5. Ramp cohorts gradually while monitoring.
6. Execute optional backfill after steady-state.

## Mixed-version matrix (must-pass)

- Old client + old row (`body` only): read/write success.
- Old client + new row (envelope present): read success via legacy `body`/`body_plain` fallback.
- New client + old row: read success with derived format fallback.
- New client + new row: full round-trip by selected format.

## Rollback playbook (quick reference)

1. Freeze rollout (stop cohort expansion).
2. Disable rich flag.
3. Disable markdown flag.
4. Validate legacy post/comment create/edit flows.
5. Keep backend dual-read and compatibility serializers active.
6. Triage metrics/log reason codes and patch forward.

## Ownership

- Backend owner: API contract + serializers + validation.
- Frontend owner: editor mode gating + renderer fallback UX.
- SRE/on-call owner: rollout gating, alert response, rollback execution.


## Optional backfill execution (NFR-402)

Script:

- `scripts/backfill_newsfeed_plain_fields.py`

Recommended run sequence:

1. Dry run (no writes):
   - `python scripts/backfill_newsfeed_plain_fields.py --dry-run --page-limit 200 --max-items 1000`
2. Incremental write run:
   - `python scripts/backfill_newsfeed_plain_fields.py --page-limit 200 --max-items 1000`
3. Resume until checkpoint reports `done=true`.

Operational behavior:

- **Incremental:** `--max-items` supports bounded batches per run.
- **Idempotent:** rows already containing matching `body_plain`/`body_format` are skipped (`no_change`).
- **Retry:** retryable DynamoDB write errors are retried with backoff (`--max-retries`).
- **Progress metrics:** script reports `scanned`, `eligible`, `updated`, `dry_run_updates`, `no_change`, `malformed`, `errors`, `retries`.
- **Checkpointing:** progress checkpoint is persisted at `pk=SYSTEM#NEWSFEED_BACKFILL`, `sk=CONTENT#PLAIN_FORMAT`.
- **Integrity check:** run exits non-zero if malformed rows remain (`integrity.malformed_rows > 0`).


## Telemetry and alerting (NFR-602)

Track these metrics in dashboards:

- `newsfeed content metric` events by `event` + `body_format` (`create_post`, `edit_post`, `create_comment`, `edit_comment`) for adoption trend.
- `newsfeed content reject` events by `source` + `reason_code` for validation/sanitizer/renderer failures.

Recommended alerts:

- Sanitizer/validator reject spike: alert when `source in (markdown_sanitizer, validator)` reject count increases above normal baseline.
- Renderer fallback/error spike: alert when `source=renderer` reject events (`unsupported_format`, `render_exception`) breach threshold.

Operational note:

- Frontend renderer reports fallback/error events to `POST /telemetry/content-render`; backend emits structured logs that can be charted in dashboard tools.
