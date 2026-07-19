# P3 dev-env config additions (gitignored .env.local + DDB-Local + moto)

These are DEV-ONLY config/seed steps required to run the non-money verticals to
green. They are NOT product bugs — the app correctly refuses when unconfigured.
.env.local is gitignored; recorded here for reproducibility.

## .env.local appends (dev backend, restart uvicorn after)
- FILEMGR_SFTP_MOUNTS_TABLE_NAME=filemgr_sftp_mounts
- FILEMGR_SFTP_CREDENTIALS_TABLE_NAME=filemgr_sftp_credentials
- FILEMGR_SFTP_CREDENTIALS_KMS_KEY_ID=<moto KMS key id>
- PLAYBACK_ENTITLEMENT_SECRET=<>=32-char secret>   # else /v1/playback/entitlements/issue + /posts/{id}/video/entitlement 400/500 'secret_not_configured'

(The CI parity flag file scripts/ci-e2e-feature-flags.env sets
FILEMGR_SFTP_MOUNTS_ENABLED=true but NOT the table-name / credentials-table /
KMS / playback-secret values — those must be supplied by the environment.)

## DDB-Local tables created (endpoint :8001, explicit test/test creds)
- filemgr_sftp_mounts (PK, SK)                     # sftp mount CRUD
- filemgr_sftp_credentials (PK, SK)                # sftp credential revoke
- filemgr_mounts (pk, sk, GSI1 gsi_owner_pk/sk)    # S3/generic mount list

## moto (:4566) resources created
- KMS key (Description 'e2e sftp creds') -> id used for FILEMGR_SFTP_CREDENTIALS_KMS_KEY_ID

## devtools UI server (:3001)
- screen -dmS devtools3001 running 'npm run dev:devtools' (vite.devtools.config.ts,
  proxies /internal -> :8000). Serves frontend/devtools.html. Required by
  devtools.spec.ts / devtools-log-ui-smoke.spec.ts / auth-mfa-devtools.spec.ts
  (they navigate to http://localhost:3001). This is a first-class repo dev server
  (package.json 'dev:devtools'), NOT infra-we-lack — starting it turns those
  specs honestly green instead of quarantined.

## Split-brain DDB note (dev only)
The dev backend runs DynamoDB-Local (:8001, DDB_ENDPOINT_URL) for most app tables
and moto (:4566, AWS_ENDPOINT_URL) for a subset. app.core.aws.ddb resolves to
:8001. Seed scripts that write billing/subscriptions/mounts must target the SAME
endpoint the app reads (:8001) with explicit test/test creds. In prod both env
vars point at the same real-AWS endpoint, so this split does not exist.
