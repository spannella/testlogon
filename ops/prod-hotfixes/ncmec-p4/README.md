# P4 — NCMEC / CyberTipline mandated-reporting real seam

Closes the STUB in `app/services/moderation_illegal_lane.py:_mandated_report_event`
(previously wrote a `ncmec_stub` audit row + CRITICAL log but transmitted nothing).

## What was built
- **`app/services/ncmec_client.py`** — vendor submission seam, config-gated exactly
  like the EasyPost/Stripe seams. Pure `build_report_payload` (documented, self-
  describing envelope a real integration maps onto the NCMEC partner schema — NOT
  a guessed wire format) + networked `submit_report` (never raises) + `is_enabled`.
- **`_mandated_report_event`** rewritten to be bulletproof record-keeping:
  1. **Idempotent** — one `SUBMISSION` record per case
     (`pk=MANDATEDREPORT#<case_id>`, `sk=SUBMISSION`); replay never re-transmits.
  2. Reserves the record `pending` FIRST (crash-safe intent), conditional put wins
     exactly one racer.
  3. Keyed → POST to the endpoint → `submitted` (+ `external_ref`) or `failed`
     (retry-safe). Unkeyed → stays `pending` (honest-mock-that-records; nothing
     dropped).
  4. Legacy audit `EVENT#` row + CRITICAL runbook log line preserved (unchanged
     tooling contract). CRITICAL line now distinguishes SUBMITTED / REQUIRED /
     ON_RECORD.
- **`app/core/settings.py`** — five go-live flags.

## Go-live flags (settings / env)
| setting | env | default | meaning |
|---|---|---|---|
| `ncmec_reporting_enabled` | `NCMEC_REPORTING_ENABLED` | `false` | master switch |
| `ncmec_api_base` | `NCMEC_API_BASE` | `""` | ESP submission base URL (NCMEC-assigned) |
| `ncmec_api_key` | `NCMEC_API_KEY` | `""` | ESP credential |
| `ncmec_org_id` | `NCMEC_ORG_ID` | `""` | ESP org id (optional) |
| `ncmec_report_timeout_seconds` | `NCMEC_REPORT_TIMEOUT_SECONDS` | `20` | POST timeout |

`is_enabled()` is True only when enabled AND base AND key are all set.

## Record model — `mandated_report_submission`
`pk=MANDATEDREPORT#<case_id>`, `sk=SUBMISSION`; fields: `status`
(pending|submitted|failed), `delivered`, `external_ref`, `attempts`, `channel`
(ncmec), `preserve_id`, `first_reporter_user_id`, `owner_user_id`, `categories`,
`enabled`, `last_error`, `created_at`, `updated_at`. Sits alongside the immutable
`ILLEGALPRESERVE#<case_id>` preservation record and the `EVENT#<ts>` audit rows.

## Verification (all observed)
- `verify_p4b.py` — self-contained harness (moto + seed + REAL uvicorn on :8010),
  drives the csam report over REAL HTTP: **17/17** — pending submission persisted,
  idempotent replay (no double-report), preservation + audit intact.
- `verify_p4_keyed.py` — flags set + local ESP receiver: **10/10** — POST delivered,
  `external_ref` captured, correct Bearer auth + org_id + preservation ref in body,
  unreachable endpoint → `failed` (retry-safe, no raise).
- Prod (`p4_prod_verify.py`, live code, real DDB): **PROD_P4_VERIFY PASS** +
  idempotent replay + `is_enabled=False`.

## Prod mirror
`p4_prod_apply.py` — byte-identical `ncmec_client.py` + `moderation_illegal_lane.py`
(md5 matched dev) via SSM; `settings.py` anchor-patched idempotently. Backup `.bak_ncmec_p4_<ts>`
kept on prod. Restart via `/home/ubuntu/restart_backend.sh`; verified openapi 200 +
single worker.

## Remaining go-live step (USER DECISION)
Point `NCMEC_API_BASE`/`NCMEC_API_KEY` (+`NCMEC_ORG_ID`) at NCMEC's real ESP
CyberTipline endpoint, map `build_report_payload` onto NCMEC's partner schema, and
obtain **legal sign-off** on mandated-report content + retention. Code is seam-ready;
no fake vendor protocol is invented.
