# Moderation Smoothing — WAVE 3 (human loops)

Live prod hotfix (EC2 `i-08f937fc705ebea75`, via SSM) + folded here for re-apply, plus the
Android app changes. **The moderation core (state machine / byte-for-byte hide-unhide / 30d
sweep / fail-closed ban) is unchanged and still verifies** (this wave re-ran the feed_post
core lifecycle end-to-end: report → under_review+hidden → confirm(hold) → poster_respond
(awaiting_final) → reinstate visible + body byte-for-byte — all green).

Plan: `ops/plans/moderation-rough-edges-plan.md` (Wave 3 = MODX-13..16).

## The problem
The feedback loops that make moderation feel *fair* were broken:
- A **banned** user was `403`'d on every appeals endpoint (`deps._enforce_not_banned` runs in
  every auth branch of `get_authenticated_user`) — appeals were structurally unreachable by the
  exact users an enforcement concerns. The required Enforcement ID was never surfaced in-app.
- The admin **final call** was made blind: `ModerationTicketDetailOut` omitted the poster's
  hold response, and `poster_respond` notified no moderator (responses sat unseen).
- `NotificationType.MODERATION` was **Alerts-only** ("reserved for future engine bridge") — no
  push for reported/confirmed/removed/ban events; terminal/ban alerts deep-linked to the empty
  open-cases screen; the **reporter** got an ack but never an outcome.
- Admin action errors collapsed to a generic snackbar (scope / dual-approval / stale-state codes
  were discarded).

## Tickets

### MODX-13 — make appeals reachable (+ selectable Enforcement ID)
- Backend: `deps.require_appellant` — a scoped dependency that authenticates the caller for the
  appeals surface WITHOUT the ban gate, via a `contextvars` flag that `_enforce_not_banned`
  honors and that is always reset in a `finally` (no other route can admit a banned user). The
  4 `/v1/appeals*` endpoints now depend on it. New `GET /v1/appeals/enforcement-options`
  (`appeals.list_enforcement_options`) returns the user's own enforcement records + a `has_appeal`
  flag so the form offers a **dropdown**, not a hand-typed opaque id.
- App: `AppealsScreen` submit form uses an `ExposedDropdownMenu` fed by the new endpoint (falls
  back to a text field only if the picker loaded empty); a ban/removal alert deep-links into the
  form with the enforcement pre-selected (`AppealsDest.build(enforcementId)` +
  `AppealsViewModel.onPrefillEnforcement`).

### MODX-14 — un-blind the admin final call
- Backend: `poster_response`+`responded_at` added to `ModerationTicketDetailOut` (populated from
  the case). `poster_respond` now notifies the ticket **assignee** (`moderation_poster_responded`);
  un-assigned tickets already re-surface on the board (status=open) as the board-badge path.
- App: `ModerationDetailScreen` renders a "Poster response" card (tag `mod_detail_poster_response`)
  in the final-call section. (Permanent-ban dual-approval second-approver field is already wired
  via `ModerationFinalCallReq.secondApproverAdminUserId` from Wave-1/MODX-7 — see MODX-16 for the
  actionable error when it is missing.)

### MODX-15 — notifications + reporter feedback
- Backend: moderation/DMCA events registered in `ALERT_CATEGORIES["moderation"]`,
  `ALERT_EVENT_TYPES` (settable) and `DEFAULT_PUSH_EVENT_TYPES` (default-on, opt-out) — so
  `_notify` now delivers a real **push** (it calls `send_push_for_alert` after `write_alert`,
  which previously TypeError'd on a `push_event_types` kwarg and silently fell back to Alerts-only).
  Deep-links added in `_build_action_url` (ban/removal → `/appeals`, poster events →
  `/moderation/review`). `_notify_reporters` fans a `moderation_report_resolved` outcome to the
  DISTINCT reporter set (never the owner) on delete/dismiss/reinstate. Reporter `report_received`
  ack now pushes + carries expanded what-happens-next copy. New `GET /v1/moderation/reports/mine`
  ("reports you filed" + outcome bucket).
- App: `NotificationTargetResolver` routes an enforcement moderation alert to
  `NotificationTarget.Appeals` (else `ModerationReview`); the Alerts inbox routes
  ban/removal events to Appeals (`onOpenAppeals`) and keeps poster-review events on the content
  review screen (removing the terminal `reinstated/restored` rows that used to open an empty list).

### MODX-16 — admin error legibility
- App: `ModerationBoardViewModel.actionableForbidden` maps backend `code` to distinct guidance
  (`role_required_scope` → needs Senior role; `dual_approval_required` / `_self` /
  `_invalid_approver` → second-approver guidance); a `409` stale-state now says "this case changed,
  refresh and retry" instead of a generic server error.

## Files patched (prod == dev byte-for-byte on every anchor; dry-run confirmed before apply)
Backend (`apply_wave3.py`, idempotent anchor edits):
`app/auth/deps.py`, `app/routers/appeals.py`, `app/services/appeals.py`, `app/models.py`,
`app/routers/admin_moderation.py`, `app/services/moderation_lifecycle.py`,
`app/services/alerts.py`, `app/routers/moderation.py`.

App: `feature/appeals/{AppealsScreen,AppealsUiState,AppealsViewModel}.kt`,
`data/appeals/{AppealsApi,AppealsDomain,AppealsRepository}.kt`,
`navigation/{AppealsNavigation,AlertsNavigation,AuthenticatedGraph}.kt`,
`feature/notifications/NotificationUi.kt`, `feature/alerts/AlertsScreen.kt`,
`data/adminmod/ModerationAdminApi.kt`, `feature/adminmod/{ModerationDetailScreen,ModerationBoardViewModel}.kt`,
`res/values/strings.xml`.

## Prod apply / rollback
- Applied `2026-07-14`. Backups: `*.bak_modx_20260714_204447` next to each of the 8 files.
- Re-apply: `python3 apply_wave3.py /home/ubuntu/testlogon` (idempotent). Restart:
  `sudo -u ubuntu bash /home/ubuntu/restart_backend.sh`; `openapi.json` → 200.
- Rollback: restore the `.bak_modx_20260714_204447` files + restart.

## Verify (prod DDB, in-process, self-cleaning — 0 residue)
`verify_wave3.py` — seeds synthetic users/content, sources `.env.local` for creds, runs the
service flows, asserts, cleans up. **Result: 20/20 PASSED** including the feed_post core row.
Run: `set -a && source .env.local && set +a && ./.venv/bin/python verify_wave3.py`.

## Residuals / deferred
- Reporter "Reports you filed" **app list screen** is deferred — the backend endpoint
  (`/v1/moderation/reports/mine`) and the per-outcome reporter alert (which lands in the alert
  center) both ship, so reporters DO see outcomes; the dedicated in-app list is a follow-up.
- Report-sheet one-line content descriptor (C11) deferred; expanded success/what-next copy ships
  via the push body.
- Push *delivery* asserts device registration; verify proves the allowlist gate + alert write +
  deep-link (the parts that were broken), not FCM transport.
