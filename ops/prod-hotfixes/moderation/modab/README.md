# MOD-A4..A6 + MOD-B1 — admin triage + 30-day hold + final call + licensing→DMCA

Live prod hotfix, folded here for re-apply. Builds on MOD-A1..A3 (`fe2be40e`): the
non-destructive hide primitive (`moderation_hide.py`), the `moderation_case` state
store + guarded auto-hide, and notify-on-report.

## What shipped

**New services**
- `app/services/moderation_delete.py` — the terminal HARD-DELETE primitive per surface
  (feed_post / feed_comment / feed_media / message / video / video_comment / profile_photo).
  This is the ONLY place content is actually removed; everything upstream is a
  non-destructive flag. `_delete_feed_media` removes just the one offending image and
  restores the rest of the post to visible.
- `app/services/moderation_lifecycle.py` — the case LIFECYCLE ops that the endpoints wrap:
  `admin_dismiss` (un-hide → dismissed), `admin_confirm_hold` (stays hidden → hold,
  `hold_until=now+30d`, notify poster + invite), `admin_final_reinstate` (restore ORIGINAL
  byte-for-byte → reinstated), `admin_final_delete` (hard delete + violation),
  `poster_respond` (hold → awaiting_final), `poster_close` (immediate delete + violation),
  `sweep_expired_holds` (MOD-A6, GSI `ByState` state=hold ∧ hold_until≤now → delete + violation),
  plus `record_violation` and the `start_hold_sweep_task` precise scheduled timer.
  Every DELETE terminal records exactly ONE `content_violation` on `user_enforcement_history`
  and notifies the owner.

**Patched (anchor-based, dev + prod forms — see `apply_modab.py`)**
- `app/services/moderation_case.py` — allow `visible → dismissed` (dismiss a not-yet-hidden report).
- `app/routers/admin_moderation.py` — `POST /v1/admin/moderation/tickets/{id}/dismiss|confirm|final-call`.
  `final-call {action: reinstate|delete, ban, ban_duration_days}` (0/None + ban=true ⇒ permanent,
  senior+dual-approval gated). Tags + closes the linked ticket.
- `app/routers/moderation.py` — MOD-B1: `licensing_ip` report category routes to the DMCA
  auto-hide pipeline (`file_dmca_claim`: hide + notify + strike + counter-notice + admin final
  call) instead of a general ticket. MOD-A5 owner endpoints
  `POST /v1/moderation/holds/{case_id}/respond|close` (+ `/moderation/...` compat).
- `app/core/settings.py` — `moderation_hold_sweep_enabled` (default on) + `_interval_seconds` (900).
- `app/main.py` — register `start_hold_sweep_task` on startup.

## State machine (moderation_case)

```
visible ──report(guarded auto-hide)──▶ under_review ──dismiss──▶ dismissed (UN-HIDDEN)
                                             │
                                          confirm
                                             ▼
                                    hold (hidden, hold_until=+30d)
                             ┌───────────────┼────────────────┐
                       respond            close             30d sweep
                             ▼               ▼                 ▼
                     awaiting_final       deleted           deleted
                        │        │       (+violation)     (+violation)
                   reinstate  delete
                        ▼        ▼
                  reinstated   deleted (+violation [+ban])
```
Illegal skips rejected; transitions idempotent; content stays HIDDEN until the final call;
non-destructive throughout — reinstate restores the intact original.

## Files
- `apply_modab.py <root>` — idempotent anchor-based patcher (dev + prod forms).
- `verify_modab.py` — in-process prod-DDB verify (scenarios A–H).
- `cleanup_modab.py` — deletes the verify test rows.

## Prod deploy (this landing)
- `.bak_modab_1783698000_modab` on the 5 patched files. 2 new services + patcher pushed via SSM base64.
- Restart `restart_backend.sh`; openapi 200. 4 new routes registered.
- **Verify: 42/42 ALL_PASS** in-process on prod DDB (A dismiss→visible; B confirm→hold→respond→
  awaiting_final→reinstate byte-for-byte; C confirm→close→deleted+violation; D confirm→30d
  sweep→deleted+violation, responded case immune; E endpoint confirm→final-call delete+fixed ban;
  F permanent ban enforced; G licensing→DMCA auto-hide+notify+counter+restore; H guards/idempotency).
- Test rows cleaned (~159). `ModerationCases` back to 0.

## Bug found + fixed during verify
`user_enforcement_history` GSI `BySourceTicketCreatedAt` rejects an empty `source_ticket_id`.
`record_violation` now falls back to the `case_id` when a case has no linked ticket
(sweep/close paths). The real report path always supplies a ticket_id.
