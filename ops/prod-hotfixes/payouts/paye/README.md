# PAY-E (PAY-40) — 1099-NEC tax-reporting integrity (LIVE PROD HOTFIX)

Honest, ledger-true 1099-NEC reporting for the payouts program. Reports what the
platform **actually paid out** per payee from the PAY-A ledger — NOT phantom
credited earnings (that is the separate FIN-008 `tax_form_1099.py`).

## What shipped
- `app/services/tax_1099.py` (NEW) — per-payee, per-tax-year aggregation of REAL
  paid payouts from the PAY-A ledger: `type="debit" reason="payout" state!="reversed"`,
  bucketed by the calendar year of the debit `ts`. Returns/reversals are excluded
  (a reversed payout's debit is flipped to `state="reversed"` by
  `creator_payouts.reverse_payout_debit`, so it never counts toward income).
  - `$600` threshold flag (`S.tax_form_1099_min_reportable_cents=60000`).
  - 24% backup withholding (Box 4) when the payee has NO certified W-9 (PAY-C
    `has_tax_info_on_file`) or a `tin_mismatch` flag — computed + recorded, never
    silently dropped.
  - Per-payee 1099-NEC records with masked TIN (`***-**-1234`, from the KMS store,
    raw TIN NEVER stored/exported) + a correction/supersede path, idempotent per
    `{payee, year}`. A later return that reduces the ledger total supersedes the
    prior record as a correction (prior figures snapshotted to a history row).
  - Admin batch `generate_year_set`, `withholding_gap_report`, CSV/JSON `export_year`.
- `app/routers/tax_1099.py` (NEW) — admin-gated endpoints (`require_admin_or_root`
  -> 403 for non-admin), prefix `/ui/tax-1099`.
- `app/main.py` — registered `tax_1099_router` (2-line insert after the FIN-008
  `tax_form_1099_router` include).

## Storage (co-located in the existing `tax_forms_1099` table, DISTINCT namespace)
- NEC record:   `pk=USER#{sub}  sk=NEC1099#{year}`  GSI `ByTaxYear`: `GSI1PK=NECYEAR#{year}`
- Correction history: `pk=USER#{sub}  sk=NEC1099HIST#{year}#{ts}`
- No infra change (reuses the existing table + `ByTaxYear` GSI). The `NECYEAR#`
  namespace never collides with FIN-008 `YEAR#` rows.

## Endpoints (all admin-gated, 403 for non-admin)
- `POST /ui/tax-1099/admin/year/{year}/generate` — generate/refresh the year set
- `POST /ui/tax-1099/admin/year/{year}/payee/{sub}/generate` — one payee
- `GET  /ui/tax-1099/admin/year/{year}` — list (`?include_under_threshold`)
- `GET  /ui/tax-1099/admin/year/{year}/payee/{sub}` — get one (`?refresh`)
- `GET  /ui/tax-1099/admin/year/{year}/withholding-report` — W-9-gap report
- `GET  /ui/tax-1099/admin/year/{year}/export?format=csv|json` — masked filing export

## Deploy (prod EC2 i-08f937fc705ebea75 via SSM, no SSH)
1. `build_deploy.py` (run on dev host) embeds both source files (base64) into
   `deploy_paye.py`.
2. `python3 ssm_run.py deploy_paye.py` — writes the 2 files, patches `main.py`
   (with `.bak`), chowns ubuntu, syntax-checks.
3. Restart: `sudo -u ubuntu -H bash -lc 'bash /home/ubuntu/restart_backend.sh'`;
   `openapi.json` -> 200; 6 `/ui/tax-1099` routes live.

### .bak
- `app/main.py.bak_paye_20260712_032003` (pre-patch main.py on prod).

## Deep-verify (in-process on prod DDB, synthetic payees `PAYE_TEST_*`, auto-cleaned)
`verify_paye.py` — MATRIX 29/29 PASS, 0 residue (`NECYEAR#2026` PAYE_TEST=0):
- P1 over $600 (400+300=700) + a prior-year 999 that must NOT count -> box1=70000,
  reportable, box4=0 (certified W-9), masked `***-**-6789`.
- P2 under $600 (100) -> reportable=False, still queryable.
- P3 returned/reversed (800 -> reversed) -> box1=0, `reversed_excluded=80000`
  (reconciles to net paid).
- P4 700+500=1200 generated; late return of the 500 AFTER generation -> correction
  box1=70000, status=corrected, correction_count=1, prior_box1=120000; idempotent
  no-op proven.
- P5 no certified W-9, 1000 -> backup_withholding applies, box4=24000 (24%),
  reason=no_certified_w9.
- Export masks TIN (raw TIN absent in CSV+JSON and at rest in the stored record).
- Admin-gate: non-admin -> 403; admin passes (in-process `require_roles`).

## Honesty / compliance invariants
- Aggregates ONLY real paid payouts from the PAY-A ledger; returns/reversals
  excluded from income.
- Raw TIN NEVER stored or exported (KMS-encrypted + last-4 only, PAY-C/SEC-004).
- Idempotent per `{payee, year}`; corrections supersede cleanly.
- No regression to PAY-A/B/C/D (separate namespace + read-only over the ledger;
  withholding recorded in the tax subsystem, not the money ledger, so balances
  are untouched).

## Residuals / notes
- `PLATFORM_EIN` unset on prod -> payer TIN prints fallback `0000`. Set the secret
  to stamp the real platform EIN on exports.
- No W-8/international this pass (US-only, locked). Real off-platform withholding
  remittance is out of scope (PAY-A gate already blocks payout without a certified
  W-9; box4 is the computed reportable figure for any gap payee).
- No PDF render here (JSON/CSV export only); FIN-008 keeps its PDF path.
