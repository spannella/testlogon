# Moderation Smoothing — WAVE 4 (admin tooling at scale)

Backend live-prod-hotfix helper (EC2 `i-08f937fc705ebea75`, via SSM) + folded here for
re-apply, plus the Android app changes and the web board changes. **The moderation core
(state machine / byte-for-byte hide-unhide / 30-day sweep / fail-closed ban) is unchanged
and still verifies** — this wave re-ran the feed_post core lifecycle end-to-end (report →
under_review+hidden → confirm(hold) → poster_respond(awaiting_final) → reinstate visible +
body byte-for-byte) and the Wave-3 human-loop suite, both green.

Plan: `ops/plans/moderation-rough-edges-plan.md` (Wave 4 = MODX-17..22).

## The problem
The moderators had no leverage at volume: parked 30-day holds inflated the SLA backlog and
paged on-call; the queue filters were dead chips (a category `Literal` that 422'd on the live
taxonomy, `in_review`/`resolved` statuses that never matched); there was no ban roster / lift,
no readable audit trail, an advisory-only claim model, no bulk actions, no app pagination, and
the **web** board ran the divergent legacy `resolve` path — invisible to the state machine, to
video/syndicate tickets, and rendering `undefined` prior-enforcement rows.

## Tickets

### MODX-18 — KPI trust + real filters + config visibility
- **Backend** (`app/services/moderation_kpis.py`): a confirmed hold keeps the ticket
  `status="open"` (the poster clock keeps ticking) but it is PARKED, not un-triaged backlog.
  `compute_moderation_kpis` now excludes `moderation_case_state in {hold, awaiting_final}` from
  the open/critical/oldest-age sets and surfaces them as a distinct **`on_hold_count`**.
- **Backend** (`app/routers/admin_moderation.py`): the ticket-list `topic` filter Literal is
  replaced with the live 6-category set + `illegal`, and legacy topics (`extortion`/`criminal`/
  `racist`/`csam`) are accepted as **server-side synonyms** (`_CATEGORY_SYNONYMS`) matched in
  Python against the aggregated topics. New read-only **`GET /auto-hide-rules`** exposes the
  (hardcoded) thresholds.
- **Backend** (`app/services/moderation_flags.py`): `video`/`video_comment`/`syndicate_post`
  each gain a reporting kill-switch (`report_video_enabled`/`report_syndicate_enabled`).
- **App/Web**: KPI header strip (backlog + on-hold + critical + oldest + resolved + p95);
  real status set + live-category filter controls.

### MODX-19 — Ban management surface
- **Backend**: `GET /admin/moderation/bans` (active-enforcement roster, ByStatusCreatedAt GSI
  with a scan fallback, joined against `account_state` for current status / permanence);
  `POST /admin/moderation/bans/{user}/lift` sets `account_state.status=active` (fail-closed ban
  gate re-admits), closes matching active ban enforcement rows as `lifted`, writes a `ban_lifted`
  audit event, notifies the user. Idempotent.
- **App**: `BanManagementScreen` (roster + one-tap lift), reachable from the board top bar.
- **Web**: an "Active bans" panel on the board with a Lift button.

### MODX-20 — Audit-trail read + claim enforcement
- **Backend**: `GET /admin/moderation/tickets/{id}/audit` (ByTicketCreatedAt) +
  `GET /admin/moderation/audit?actor=` (ByActorCreatedAt) read `moderation_audit_log`. Claim
  enforcement: a claim made through the claim endpoint stamps `assigned_at`; action routes
  (dismiss/confirm/final-call, and bulk) call `_enforce_claim` — a *fresh* claim by another
  moderator 409s unless `steal=true` (audited); a bare auto/legacy assignment (no stamp) or a
  claim older than the 30-min TTL auto-releases. `POST /tickets/{id}/unclaim` releases/reassigns.
- **Web**: unclaim/reassign endpoints wired in the API module.

### MODX-21 — App queue pagination + real filters
- **App**: the board threads `next_cursor` into an infinite-scroll VM (`loadMore`); adds a
  live-category filter row; replaces the dead `in_review`/`resolved` chips with the real
  `open`/`closed` set (`MODERATION_STATUS_FILTERS`).

### MODX-22 — Bulk actions
- **Backend**: `POST /admin/moderation/tickets/bulk` (ids + action `dismiss|confirm|reinstate|
  delete`) runs each id through the SAME guarded state-machine path and returns a **per-item**
  result (illegal-state / claimed / conflict errors are reported, not fatal).
- **App**: multi-select mode + bulk action bar. **Web**: checkbox select + bulk bar.

### MODX-17 — Web board parity with the state machine
- **Web** (`src/api/endpoints/moderation.ts`, `src/pages/admin/ModerationBoardPage.tsx`): the
  board now drives the STATE MACHINE (dismiss / confirm-30d-hold / final-call{reinstate|delete
  +ban}) with hold countdown, poster-response card, and the illegal-lane badge — no divergence
  from the app. An **All** queue tab omits the queue filter and a **General** tab surfaces the
  video/video_comment/syndicate_post tickets that fell to `general` (invisible before). The
  **prior-enforcement rows read the REAL projected fields** (`enforcement_type`/`status`/
  `source_ticket_id`/`created_by_admin_user_id`/`created_at`/`duration_days`/`note`) instead of
  rendering `undefined`.

## Files

Backend (`apply_wave4.py`, idempotent anchor edits — dev==prod byte-for-byte on each anchor):
`app/services/moderation_kpis.py`, `app/services/moderation_flags.py`,
`app/routers/admin_moderation.py`.

App: `data/adminmod/ModerationAdminApi.kt`,
`feature/adminmod/{ModerationBoardViewModel,ModerationBoardScreen,BanManagementScreen}.kt`,
`navigation/ModerationBoardNavigation.kt`.

Web: `src/api/endpoints/moderation.ts`, `src/pages/admin/ModerationBoardPage.tsx`,
`src/pages/admin/__tests__/ModerationBoardPage.test.tsx`.

## Prod apply / rollback
- Backend: `python3 apply_wave4.py /home/ubuntu/testlogon` (idempotent; asserts every anchor).
  `cp` the touched files to `*.bak_modx_<ts>` first, `chown ubuntu:ubuntu`, restart with
  `sudo -u ubuntu bash /home/ubuntu/restart_backend.sh`; confirm `openapi.json` → 200.
- Rollback: restore the `.bak_modx_<ts>` files + restart.

## Verify (local DDB in-process, non-destructive, self-cleaning — 0 residue)
`verify_wave4.py` — spins the moderation service/router layer against a DynamoDB (moto/
DynamoDB-Local on `:8001`), seeds synthetic users/content/tickets, asserts, cleans up.
**Result: 36/36 PASSED** (KPI hold-exclusion + on_hold_count, live-category + legacy-synonym +
real-status filters, ticket/actor audit read, claim exclusivity + steal + TTL auto-release,
ban roster + lift, bulk per-item results, AND the feed_post core lifecycle regression). The
Wave-3 suite re-ran **20/20**.
Run:
```
# start a local DDB on :8001 and init tables (docker amazon/dynamodb-local OR moto.server)
python3 -m moto.server -p 8001 &
AWS_ENDPOINT_URL=http://localhost:8001 PYTHONPATH=. ./.venv/bin/python scripts/local-ddb-init.py
set -a && source .env.local && set +a
AWS_ENDPOINT_URL=http://localhost:8001 PYTHONPATH=. ./.venv/bin/python \
  ops/prod-hotfixes/moderation-smoothing/wave4/verify_wave4.py
```

## Web build state
node/npm are **absent on the dev host** — the web code is written and type-coherent but the
`npm run build` / vitest run is **DEFERRED** (flag for a node-enabled host). The board test was
rewritten to exercise the new state-machine surface (not the removed legacy decision panel).

## Residuals / deferred
- Web `npm run build` + vitest deferred (no node on host).
- App ban-management is reachable from the board top bar (not a separate MoreCatalog hub entry).
- KPI compute is still a full-table scan (D13) — deferred to the perf/ops track (MODX-9).
- Audit timeline is exposed via API on both surfaces; the app renders the board/detail actions,
  the dedicated in-app audit timeline screen is a follow-up.
