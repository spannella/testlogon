# AWS Services Overview

This service primarily uses AWS-managed infrastructure for data storage, encryption, and optional outbound messaging. The exact services you need depend on which features you enable.

## Core services
- **DynamoDB**: persistent storage for sessions, MFA devices, recovery codes, alerts, API keys, billing data, and other state.

## Optional services
- **KMS**: encrypts secrets like TOTP seeds when `KMS_KEY_ID` is configured.
- **SES**: sends email MFA codes when `SES_FROM_EMAIL` and SES credentials are configured.
- **Cognito**: used for JWT validation when `COGNITO_*` env vars are configured (optional for local testing).
- **CloudWatch Logs**: captures stdout/stderr logs when running in AWS (optional, via platform).
- **OpenSearch**: provides scalable full-text message search when `OPENSEARCH_ENDPOINT` is configured.

## Related configuration
- See `docs/dynamodb.md` for table setup details.
- Environment variables for AWS integrations are listed in `README.md` and `docs/run-deploy.md`.
