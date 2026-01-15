# Run and Deploy

This service is a FastAPI application with DynamoDB-backed storage and optional AWS/Twilio integrations.

## Run locally

1. Create and activate a virtualenv.

   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```

2. Install dependencies.

   ```bash
   pip install -r requirements.txt
   ```

3. Export required environment variables.

   ```bash
   export AWS_REGION=us-east-1
   export DDB_SESSIONS_TABLE=your_sessions_table
   export DDB_TOTP_TABLE=your_totp_table
   export DDB_SMS_TABLE=your_sms_table
   export DDB_EMAIL_TABLE=your_email_table
   export DDB_RECOVERY_TABLE=your_recovery_table
   export API_KEYS_TABLE_NAME=api_keys
   export API_KEYS_USER_INDEX=user_sub-index
   export API_KEY_PEPPER=change_me
   export ALERTS_TABLE_NAME=alerts
   export ALERT_PREFS_TABLE_NAME=alert_prefs
   export WS_TOKEN_SECRET=change_me
   ```

   Optional integrations are described in `README.md` (SES, Twilio, KMS, push, and alert fanout).

4. Start the server.

   ```bash
   uvicorn app.main:app --reload
   ```

5. Open the UI at `http://localhost:8000/`.

## Deploy

### Requirements

- **AWS resources**: DynamoDB tables for sessions, MFA, recovery, API keys, alerts, and push devices.
- **Credentials**: Runtime AWS credentials (IAM role, access keys, or environment-based auth) with read/write access to the tables and optional KMS/SES permissions.
- **Secrets**: `API_KEY_PEPPER` and `WS_TOKEN_SECRET` should be set as secrets in your deployment environment.

### Recommended production run command

Use a production ASGI server with multiple workers (e.g., Gunicorn + Uvicorn workers):

```bash
pip install gunicorn

gunicorn \
  -k uvicorn.workers.UvicornWorker \
  -w 2 \
  -b 0.0.0.0:8000 \
  app.main:app
```

### Container deployment (example)

You can containerize the service with a minimal Dockerfile:

```Dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
CMD ["gunicorn", "-k", "uvicorn.workers.UvicornWorker", "-w", "2", "-b", "0.0.0.0:8000", "app.main:app"]
```

Build and run:

```bash
docker build -t security-backend .
docker run --rm -p 8000:8000 --env-file .env security-backend
```

### Notes

- **Authentication**: `app/auth/deps.py` is a placeholder and must be replaced with real auth (e.g., Cognito JWT verification) before production use.
- **Network placement**: deploy behind a load balancer/ingress with HTTPS termination.
- **Observability**: wire your preferred logging/metrics stack (stdout logging is already supported). 
