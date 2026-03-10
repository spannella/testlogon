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
just up
```

2. Open the Dev Tools UI:

- Dev Tools: `http://localhost:3001`

The Dev Tools UI is a standalone Vite server on port 3001. No auth is required.
Start it independently with:

```bash
just devtools
```

The main app runs on port 3000 as usual. The devtools server is started automatically by `just up` / `scripts/dev.sh start`.

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

### Dev Tools page not loading

- Confirm the devtools server is running on port 3001: `just devtools` or check `scripts/dev.sh status`.
- The devtools server is started automatically by `just up` / `scripts/dev.sh start`.

### Page loads but no records appear

- Confirm logs exist at the configured `DEVTOOLS_*` paths.
- Check backend/frontend logs printed by `scripts/dev.sh start` startup output.
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
