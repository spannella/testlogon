#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ENV_FILE=".env.production"
if [[ -f "$ENV_FILE" ]]; then
  echo "$ENV_FILE already exists; refusing to overwrite." >&2
  exit 1
fi

cat <<'VARS' > "$ENV_FILE"
# Required core settings
AWS_REGION=us-east-1
DDB_SESSIONS_TABLE=
DDB_TOTP_TABLE=
DDB_SMS_TABLE=
DDB_EMAIL_TABLE=
DDB_RECOVERY_TABLE=
API_KEYS_TABLE_NAME=api_keys
API_KEYS_USER_INDEX=user_sub-index
API_KEY_PEPPER=
ALERTS_TABLE_NAME=alerts
ALERT_PREFS_TABLE_NAME=alert_prefs
WS_TOKEN_SECRET=

# Optional integrations
# KMS_KEY_ID=
# SES_FROM_EMAIL=
# TWILIO_ACCOUNT_SID=
# TWILIO_AUTH_TOKEN=
# TWILIO_FROM_NUMBER=
# OPENSEARCH_ENDPOINT=
# OPENSEARCH_INDEX=
# OPENSEARCH_REGION=

# Billing (optional)
# BILLING_TABLE_NAME=
# STRIPE_SECRET_KEY=
# STRIPE_PUBLISHABLE_KEY=
# STRIPE_WEBHOOK_SECRET=
# PAYPAL_CLIENT_ID=
# PAYPAL_CLIENT_SECRET=
# PAYPAL_WEBHOOK_ID=
VARS

echo "Wrote $ENV_FILE. Update the values with your production credentials before running scripts/run_prod.sh."
