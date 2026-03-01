# Internal Dev Log UI (local/dev only)

The Internal Dev Log UI is a **read-only** troubleshooting surface for local development.
It helps developers inspect mock artifacts produced by the local stack in one place:

- Email log view (Gmail-like, read-only)
- SMS log view (iMessage-like, read-only)
- Billing ledger + summary for Stripe/CCBill/PayPal mock traffic (read-only)
- MFA/TOTP helper panel (frontend-only parser + generator)

> Security boundary: this UI is intended for local/dev usage only and should not be enabled for production-facing environments.

## Quickstart

1. Start the local stack:

```bash
scripts/run_dev.sh
```

2. Open the frontend app:

- Main app: `http://localhost:5173`
- Dev Log UI: `http://localhost:5173/dev-tools/log-ui`

`run_dev.sh` auto-enables the route by exporting `VITE_ENABLE_DEVTOOLS_LOG_UI=1` for local runs.

## Data inputs and defaults

The backend reads log files from these environment variables (defaults shown):

- `DEVTOOLS_EMAIL_LOG_PATH` (default: `.logs/dev/emails.log`)
- `DEVTOOLS_SMS_LOG_PATH` (default: `.logs/dev/sms.log`)
- `DEVTOOLS_BILLING_STRIPE_LOG_PATH` (default: `.local/logs/stripe-mock.log`)
- `DEVTOOLS_BILLING_BACKEND_LOG_PATH` (default: `.logs/dev/backend.log`)

`run_dev.sh` sets these defaults automatically if they are unset.

## Read-only behavior

All Email/SMS/Billing views are read-only.

The only interactive write-like action is in-memory/local browser handling for the MFA panel:

- You can paste TOTP configuration input (`otpauth://` URI or raw Base32 secret).
- Optional persistence stores this value in browser `localStorage` only.
- The TOTP secret is not sent to backend APIs by design.

## Troubleshooting

### Dev Log route returns 404

- Confirm frontend flag is enabled: `VITE_ENABLE_DEVTOOLS_LOG_UI=1`
- If using local flow, prefer `scripts/run_dev.sh` (it sets this automatically).

### Page loads but no records appear

- Confirm logs exist at the configured `DEVTOOLS_*` paths.
- Check backend/frontend logs printed by `run_dev.sh` startup output.
- If you used `--no-clean`, old logs may be retained; verify file timestamps and active path values.

### Billing tab is empty

- Ensure Stripe mock/backend logs are being written to configured billing paths.
- Validate provider/status/date filters are not excluding all rows.

### TOTP panel shows invalid config

- Use an `otpauth://totp/...` URI or valid Base32 secret.
- Unsupported URI parameters are ignored with warnings; invalid secrets produce non-blocking errors.

## Known limitations

- This is an internal debugging surface, not a production customer UI.
- Parsed results depend on local log availability and formatting quality.
- Very stale retained logs (especially in `--no-clean` runs) can mix old/new artifacts.
