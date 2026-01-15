Refactored FastAPI security backend (split from the original single-file server).

## Documentation
- [File reference](docs/file-reference.md)
- [Run and deploy](docs/run-deploy.md)

## Run
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Required env vars (minimum)
- AWS_REGION
- DDB_SESSIONS_TABLE
- DDB_TOTP_TABLE
- DDB_SMS_TABLE
- DDB_EMAIL_TABLE
- DDB_RECOVERY_TABLE
- API_KEYS_TABLE_NAME (default: api_keys)
- API_KEYS_USER_INDEX (default: user_sub-index)
- API_KEY_PEPPER
- ALERTS_TABLE_NAME (default: alerts)
- ALERT_PREFS_TABLE_NAME (default: alert_prefs)
- WS_TOKEN_SECRET

## Optional
- KMS_KEY_ID for encrypting TOTP secrets
- SES_FROM_EMAIL for email MFA
- TWILIO_* for SMS MFA
- ALERTS_* for outbound alert fanout
