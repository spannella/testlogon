# Moderation Smoothing — WAVE 1 (close the abuse vectors)

Live prod hotfix (EC2 `i-08f937fc705ebea75`, us-east-2, via SSM) + folded here for re-apply.
Closes the weaponized-takedown / punitive-expiry / inert-reputation / weak-ban / illegal-content
rough edges. **The moderation core (state machine / byte-for-byte hide-unhide / ban enforcement /
DMCA / guards) is unchanged and still verifies (core 76/76, wave-0 33/33).**

Plan: `ops/plans/moderation-rough-edges-plan.md` (Wave 1 = MODX-3..8).

## Tickets

### MODX-3 — distinct-reporter auto-hide + target protection + per-target velocity
Auto-hide is decided on the DISTINCT `reporter_ids` set (persisted on the case), never raw report
events. A single throwaway account — or one account reporting 3x — can NO LONGER auto-hide anything.
Severe content needs a trusted reporter OR >=2 distinct reporters with >=1 credible (non-burner);
lower needs >=3 distinct with >=1 credible. A burst of fresh/untrusted accounts trips the
per-target VELOCITY guard -> the auto-hide is suppressed and the case is flagged
`needs_human_review` (routed to a human, not hidden). Established/verified targets require
corroboration (protection tier). Admin detail DTO surfaces `distinct_reporter_count` +
`needs_human_review`. **Closes Product Decision #8.**

### MODX-4 — humane expiry + awaiting_final SLA + under_review recourse
Hold-expiry by pure INACTION no longer silently hard-deletes + strikes. It ESCALATES to
`awaiting_final` (safe, reviewable, SLA'd, `expired_no_response`), preserves the content, records
NO strike, and notifies the poster + board. A new `sweep_awaiting_final_sla` escalates any
awaiting_final case past its SLA to a SENIOR mod (still hidden, surfaced with age; never
auto-deleted/auto-reinstated). `poster_dispute` gives auto-hidden `under_review` content a recourse
BEFORE an admin acts (new `POST /v1/moderation/holds/{case_id}/dispute`). `poster_close` is a
poster-initiated removal and carries NO strike.

### MODX-5 — reporter reputation loop + self/COI guards
Dismiss/reinstate DECREMENTS a reporter's trust + bumps `report_false_rate`; confirm/delete
INCREMENTS it — the previously-inert `report_trust_score`/`report_false_rate`/`trusted_reporter`
signals are now real and feed `is_trusted_reporter`. Self-reports (reporter == owner) are dropped
from the distinct set. An admin cannot make the final call on their own content or a case where
they are the sole reporter (COI 403).

### MODX-6 — ban-evasion fingerprinting (device / email / IP seam)
On ban, device/email/IP fingerprints (backfilled from durable signup signals) are LINKED to the
offender under `BANFP#{kind}#{hash}` in the app single-table. `screen_registration(...)` is the
registration seam: a new signup whose fingerprint matches an ACTIVE ban is flagged as likely
evasion (gmail dot/plus aliasing canonicalised; expired bans do not poison the fingerprint).

### MODX-7 — real dual-approval for permanent bans
`moderation_dual_approval_permanent_ban_enabled` defaults ON. The second approver must EXIST, be
DISTINCT from the acting admin, and actually hold `content_moderation_senior` (or be ROOT) —
validated against the users table, not a caller-supplied string — and the approval is recorded as
an auditable action. Fabricated / non-senior / absent approvers are rejected.

### MODX-8 — illegal / CSAM escalation lane
`illegal`/`csam` report topics take a DISTINCT locked lane: IMMEDIATE restricted hide on the 1st
report (no corroboration gate), evidence PRESERVATION record + a mandated-reporting (NCMEC/hotline)
stub event, routed to a senior-only `illegal` queue. Reinstate / dismiss / poster self-delete are
all HARD-BLOCKED on illegal content; any final-call action on an illegal case is senior-only.

## Deploy
Byte-mirror files (prod == dev HEAD pre-edit) were mirrored to prod via SSM (gzip+base64,
`py_compile`, `chown ubuntu:ubuntu`); the two DIVERGENT files (`app/routers/moderation.py`,
`app/core/settings.py`) got the in-place edits in `apply_wave1.py`. Restart:
`sudo -u ubuntu bash /home/ubuntu/restart_backend.sh`; `openapi.json` -> 200.
Backups on prod: `*.bak_modx_1784056641` (services), `*.bak_modx_1784056659` (admin_moderation),
`*.bak_modx_<ts>` (moderation.py, settings.py from the divergent-edit run).

## Verify (in-process on prod DDB, synthetic, auto-cleaned — 0 residue)
```
bash /tmp/vrun.sh ops/prod-hotfixes/moderation/verify_moderation.py            # core 76/76 ALL_PASS
bash /tmp/vrun.sh ops/prod-hotfixes/moderation-smoothing/wave0/verify_wave0.py # 33/33 ALL_PASS
bash /tmp/vrun.sh ops/prod-hotfixes/moderation-smoothing/wave1/verify_wave1.py # 51/51 ALL_PASS
```
(`vrun.sh` = source .env.local + PYTHONPATH + .venv python.)

### Result
- Core no-regression: **76/76 ALL_PASS** (the auto-hide TRIGGER now requires trust/corroboration
  per MODX-3, and hold-expiry escalates per MODX-4 — the R1/R3/R5/C/D scenarios were updated to the
  new intended policy; every state-machine / hide-unhide / ban / DMCA / guard invariant is unchanged).
- Wave-0 regression: **33/33 ALL_PASS** (B/S updated for MODX-4 no-strike self-close + escalate-on-expiry).
- Wave-1: **51/51 ALL_PASS**, RESIDUE_FOR_RUN: 0 — pos/neg matrix for all six tickets.
