# Moderation Smoothing — WAVE 0 (stop the bleeding)

Live prod hotfix (EC2 `i-08f937fc705ebea75`, us-east-2, via SSM) + folded here for re-apply.
Fixes the highest-leverage correctness/safety rough edges of the shipped moderation subsystem:
the 500-on-re-report wedge, the double-strike / illegal-state-delete race, and the api-key
ban bypass. **The moderation core (state machine / byte-for-byte hide-unhide / 30d sweep /
fail-closed ban) is unchanged and still verifies 75/75.**

Plan: `ops/plans/moderation-rough-edges-plan.md` (Wave 0 = MODX-2 → MODX-1; MODX-9 rides along).

## Tickets in this wave

### MODX-2 — act-after-guard ordering + idempotent strikes + api-key ban gate (S)
Covers A2, A10, A14.
- **`moderation_case.py`** — new `transition_result(...) -> (changed, case)` primitive: `changed`
  is True ONLY when THIS call won the DB-conditional state move. `transition(...)` is now a thin
  back-compat wrapper over it. This is the act-AFTER-guard primitive.
- **`moderation_lifecycle._finalize_delete`** — transition FIRST; destroy content + record the
  violation strike + notify + close the ticket ONLY when `changed`. An illegal-state delete
  (visible/under_review/dismissed/reinstated → deleted) now raises `ValueError` from the guard
  **before any content is touched** (content intact, clean 4xx at the router). A lost race /
  already-deleted case is `changed=False` → a clean no-op, so concurrent finalizers/retries
  produce **exactly one** violation strike (no double-strike, no illegal-state hard-delete).
- **`moderation_lifecycle.admin_dismiss`** (A10) — same reorder: move to `dismissed` FIRST;
  un-hide + notify only when `changed`, so a lost race to a concurrent `confirm` (HOLD) can't
  pop confirmed-violation content back into public view.
- **`sessions.require_ui_session`** (A14) — run `is_user_currently_banned` on the **api-key
  principal** before honoring the key & returning (ADMIN/ROOT exempt, mirroring the session
  path). A banned identity acting via an `ak_` key is now blocked exactly like a session.

### MODX-1 — un-freeze terminal cases + close orphaned tickets (M)
Covers A1.
- **`moderation_case.reopen_terminal_case`** — atomically resets a `dismissed`/`reinstated`/
  `deleted` case back to `visible` (clears `hidden`, drops hold/terminal markers, resets
  `report_count`→1 and `categories` to this report's, bumps `reopen_count`, re-points
  `ticket_id` at the new open ticket). Conditional-on-terminal, so concurrent re-reports reopen
  exactly once.
- **`moderation_case.on_report_filed`** — a re-report of terminal content now **reopens** the
  case and re-evaluates the guarded auto-hide (severe re-report re-hides), instead of returning
  early on the frozen terminal state. Admin actions on the freshly-minted re-report ticket now
  act on a live, non-terminal case → **no 500**.
- **`moderation_lifecycle._finalize_delete` + `_close_linked_ticket`** — the NON-admin finalize
  paths (30-day sweep + `poster_close`) now close the linked ticket
  (`status=closed`, `resolution=content_removed`), mirroring the admin path. **No OPEN ticket
  survives a terminal case.** Idempotent + best-effort (admin routes also close their own).
- **`admin_moderation._modab_guard`** — wraps the dismiss/confirm/final-call lifecycle calls so
  a guarded state error surfaces as a clean **HTTP 409**, never an unhandled 500. Final-delete
  also returns a 409 when the case is not in a deletable state (`changed=False`) instead of
  applying a ban / re-closing.

### MODX-9 — offender-history GSI wedge disposition (S, ops)
Covers A15.
- Confirmed on prod: `UserEnforcementHistory.ByOffenderCreatedAt` is stuck **`CREATING`** with a
  **stale key** `['offender_user_id','created_at']`. AWS will not allow deleting a `CREATING`
  index, so `residuals/create_gsi_userid.py` correctly refuses and exits 3 ("retry later").
- **Correctness is NOT affected.** `_query_enforcement_history_by_offender` queries the index by
  **`user_id`**, which does not match the stale index key, so every read falls through to a
  COMPLETE base-table **Query on the `user_id` HASH key** — a partition query (NOT a full-table
  scan) that returns precise, un-truncated recidivism counts. This is proven by the passing
  violation-count assertions in both verifies (`enforcement_rows` / Section E).
- **Self-heal path is ready:** `residuals/create_gsi_userid.py` is idempotent and will
  delete-then-recreate the index with the correct `user_id` HASH + `created_at` RANGE key the
  moment AWS transitions the wedged index to `ACTIVE` (so it becomes deletable). No app change
  is required; the index is purely a latency optimization over the already-correct fallback.

## Deploy (how this wave was applied)
The 4 backend files were byte-for-byte identical prod==dev before the edit, so the edited dev
files were mirrored to prod via SSM (`AWS-RunShellScript`, base64 write + `py_compile`),
`chown ubuntu:ubuntu`, then `sudo -u ubuntu bash /home/ubuntu/restart_backend.sh`; `openapi.json`
→ 200. Re-apply from the patches here (`git apply *.patch`) or from the committed source.

- Backups on prod: `*.bak_modx_1784054102` for all four files.
- Changed files: `app/services/moderation_case.py`, `app/services/moderation_lifecycle.py`,
  `app/services/sessions.py`, `app/routers/admin_moderation.py`.

## Verify (in-process on prod DDB, synthetic, auto-cleaned — 0 residue)
```
# consolidated core regression (no-regression gate)
.venv/bin/python ops/prod-hotfixes/moderation/verify_moderation.py   # 75/75 ALL_PASS
.venv/bin/python ops/prod-hotfixes/moderation/cleanup_moderation.py <TS>
# wave-0 fixes (self-cleaning)
.venv/bin/python ops/prod-hotfixes/moderation-smoothing/wave0/verify_wave0.py  # 33/33 ALL_PASS
```

### Result matrix
- **Core no-regression:** `verify_moderation.py` = **75/75 ALL_PASS** (state machine, hide/unhide,
  sweep, ban, DMCA, guards) — unchanged.
- **Wave-0 `verify_wave0.py` = 33/33 ALL_PASS, RESIDUE_FOR_RUN: 0:**
  - **A (MODX-1)** re-report of a REINSTATED item → fresh case (reopen_count=1) + re-hide + new
    open ticket + admin confirm/delete **no 500** + exactly one strike + both tickets closed.
  - **B (MODX-1)** `poster_close` deletes + records one strike + **closes the linked ticket**
    (no orphan); re-report of the DELETED item reopens fresh + admin action **no 500** + second
    lifecycle strike (2 total, no double per lifecycle).
  - **S (MODX-1)** 30-day sweep deletes the expired hold and **closes the linked ticket** (no orphan).
  - **C (MODX-2)** illegal-state final-delete raises **before** any delete (content intact, **zero**
    strikes, case unchanged); double/retry delete → second is a `changed=False` no-op → **exactly
    one** strike.
  - **K (MODX-2)** banned identity via `ak_` key **blocked (403)**; non-banned allowed; banned ADMIN
    exempt (mirrors session path).
