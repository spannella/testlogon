# MOD-A1..A3 — Non-destructive hide primitive + moderation_case store + guarded auto-hide + notify-on-report

Backend foundation for content moderation. Live prod hotfix (EC2 `i-08f937fc705ebea75`
via SSM) + mirrored to the `android-impl` dev clone.

## What shipped
- **New table `ModerationCases`** (hash `case_id`; GSI `ByState` [state HASH / hold_until N RANGE]
  for the future 30d sweep). Created on prod; registered in `settings.py` /
  `core/tables.py` / `scripts/local-ddb-init.py`.
- **`app/services/moderation_case.py`** (NEW) — the case store + state machine
  (`visible -> under_review -> hold -> awaiting_final -> {dismissed,reinstated,deleted}`),
  guarded auto-hide by severity (D-AUTOHIDE), the 6 categories + legacy back-compat map,
  trusted-reporter signal, and `on_report_filed` orchestration (aggregate + hide + notify).
- **`app/services/moderation_hide.py`** (NEW) — the NON-DESTRUCTIVE, owner-aware hide
  primitive for every reportable surface (feed post / comment / media / message /
  video / video comment). Writes flags over the intact row — NEVER nulls a body —
  so reinstate restores byte-for-byte. Exposes `is_hidden_for_viewer` (owner+admin see;
  others don't) and `resolve_owner`.
- **`app/routers/moderation.py`** — 6 categories added to `ALLOWED_TOPICS`
  (spam, harassment, hate, sexual, violence_threats, other) keeping the legacy 5;
  `_create_report` now calls `moderation_case.on_report_filed` (aggregate report ->
  guarded auto-hide -> state=under_review -> notify poster). Best-effort; never breaks
  the report write.
- **Owner-aware read paths** (non-owner sees hidden; owner still sees):
  `newsfeed.py` feed lists + `get_post` single-GET (also fixes the pre-existing leak) +
  comments list; `messaging.py` `_filter_message_visible` (sender keeps owner-view);
  `group_feed.py` (adds the previously-missing filter); `video_comments.py` list.
- **4 new category TOPIC# guard rows** seeded on `ContentReports`
  (harassment, hate, violence_threats, other).

## Guarded auto-hide (D-AUTOHIDE)
- SEVERE {sexual, violence_threats, hate} -> hide on the 1st report.
- LOWER {spam, harassment, other} -> hide when report_count>=3 OR a trusted reporter.
- Admins can hide/unhide manually (later ticket). Legacy topics map:
  extortion->harassment, criminal->violence_threats, racist->hate.

## Apply / verify
- `apply_moda.py <REPO_ROOT>` — idempotent anchor-based patcher (dev+prod forms;
  optional edits for env divergence). Writes per-file `.bak_moda_<ts>`.
- `prod_create_table.py` — creates `ModerationCases` + seeds the 4 new TOPIC rows (idempotent).
- `verify_moda.py` — in-process verify on prod DDB (28 assertions).

## Prod state
- .bak: `.bak_moda_1783610277` (13 files, first apply) + `.bak_moda_1783610406` (video_comments prod-form).
- Restart `su - ubuntu -c "bash /home/ubuntu/restart_backend.sh"`; openapi 200.
- **Prod in-process verify 28/28 ALL_PASS** (`verify_moda.py`).

## NOT in this slice (later MOD tickets)
- Admin triage/confirm/final-call endpoints (MOD-A4), poster respond/close (MOD-A5),
  30d sweep (MOD-A6), licensing->DMCA route (MOD-B1), app wiring (C/D/E).
- Message "under review" placeholder for non-sender members (currently filtered out;
  sender owner-view works). Video single-GET + syndicate owner-view filters.
