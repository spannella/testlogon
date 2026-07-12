# Content moderation — non-destructive report → hold → final-call backend (EPIC A + B)

State-machine-critical moderation foundation for TestLogon. Reported content is
**hidden, never destroyed**, and stays recoverable until an explicit final call.
Live prod hotfix (EC2 `i-08f937fc705ebea75`, us-east-2, via SSM), folded here for re-apply.

Backend commits (branch `android-impl`): `fe2be40e` (MOD-A1..A3) + `19dedc24` (MOD-A4..A6 + MOD-B1).

## Layout
- `moda/`  — MOD-A1..A3: the non-destructive hide primitive + `moderation_case` store +
  guarded auto-hide (severity) + notify-on-report. `apply_moda.py`, `verify_moda.py`,
  `prod_create_table.py` (creates the `ModerationCases` table), `cleanup_moda.py`, `README.md`.
- `modab/` — MOD-A4..A6 + MOD-B1: admin triage (dismiss/confirm/final-call), the 30-day
  hold + scheduled sweep, poster respond/close, licensing→DMCA. `apply_modab.py`,
  `verify_modab.py`, `cleanup_modab.py`, `README.md`.
- `verify_moderation.py` — **CONSOLIDATED full state-machine verify** (this doc's matrix).
- `cleanup_moderation.py` — deletes the consolidated-verify test rows (`argv[1]=TS`).

## The state machine (`moderation_case`, keyed to the content ref)
```
visible ──report(guarded auto-hide by severity)──▶ under_review ──admin dismiss──▶ dismissed (UN-HIDDEN)
                                                        │
                                                  admin confirm
                                                        ▼
                                          hold (HIDDEN, hold_until = now+30d)
                              ┌─────────────────────────┼──────────────────────────┐
                        poster respond              poster close              30d sweep (no response)
                              ▼                         ▼                          ▼
                       awaiting_final                deleted                    deleted
                        │          │              (+violation)               (+violation)
                  admin reinstate  admin delete
                        ▼          ▼
                   reinstated    deleted (+violation [+ban])
```
Illegal skips are rejected, transitions are idempotent, content stays HIDDEN until the
final call, and reinstate restores the intact original **byte-for-byte**.

**Guarded auto-hide (D-AUTOHIDE)** — SEVERE `{sexual, violence_threats, hate}` hide on the
1st report; LOWER `{spam, harassment, other}` hide at `report_count>=3` OR a trusted reporter
(`account_state.trusted_reporter`). Admins can always hide/unhide. 6 categories with a legacy
back-compat map (extortion→harassment, criminal→violence_threats, racist→hate).

**Licensing/IP (D-LICENSING / MOD-B1)** — a separate flow: `licensing_ip` reports route to
the DMCA pipeline (auto-hide on submit + notify poster + counter-notice + admin final call),
NOT the general ticket board.

## New DDB table
`ModerationCases` — hash `case_id` (one case per content ref) + GSI `ByState`
[state HASH / hold_until N] for the 30-day sweep. Create on a fresh env with
`moda/prod_create_table.py` (or the AdClicks-pattern registration in
`app/core/tables.py` + `scripts/local-ddb-init.py`). Precise scheduled sweep
(`moderation_lifecycle.start_hold_sweep_task`, 900s) — NOT DDB TTL.

## Run the consolidated verify (in-process on prod DDB, via SSM)
```
# on the dev host — base64-push then run under the app venv/env
B64=$(base64 -w0 verify_moderation.py)
# ... write to /home/ubuntu/testlogon/_v.py, chown ubuntu, then:
su - ubuntu -c "cd /home/ubuntu/testlogon && set -a && source .env.local \
  && export DEV_MODE=1 PYTHONPATH=/home/ubuntu/testlogon && set +a \
  && .venv/bin/python _v.py"
# then: cleanup_moderation.py <TS>   (deletes that run's seeded rows)
```

## Consolidated verify matrix — 75/75 ALL_PASS (prod DDB, real seeded rows)
- **R report→guarded auto-hide**: R1 SEVERE(sexual) auto-hides on 1st report — non-owner
  `get_post`→404 / owner→200, body intact, poster notified; R2 spam×1 stays visible;
  R3 spam×3 distinct reporters hides EXACTLY at the 3rd; R4 trusted reporter hides on 1 spam;
  R5 legacy `racist`→`hate` severe auto-hide; R6 re-report idempotent (no re-hide).
- **M message hide (D-MESSAGE-HIDE)**: `hide_content` resolves the sender as owner, flags the
  row NON-DESTRUCTIVELY (text intact), hides for other members, sender keeps owner-view;
  unhide restores visibility byte-for-byte.
- **A** under_review→dismiss→VISIBLE, body intact.
- **B** confirm→hold(+30d, hidden, notified)→respond→awaiting_final→reinstate byte-for-byte;
  non-owner cannot respond (403).
- **C** confirm→poster-close→deleted + violation + 404.
- **D** confirm→30d elapse→sweep-delete + violation; a responded (awaiting_final) case is immune.
- **E** REAL endpoints: confirm→final-call delete + fixed 7-day ban enforced + ticket closed
  `content_removed`.
- **F** permanent ban enforced (`ban_until=0`).
- **G** licensing→DMCA auto-hide + notify + strike + counter-notice → admin restore.
- **H** guards: visible→deleted / under_review→deleted / terminal deleted→reinstated all
  rejected; dismiss idempotent; respond-on-non-hold rejected.
