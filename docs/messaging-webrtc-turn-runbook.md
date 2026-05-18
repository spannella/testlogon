# Messaging WebRTC STUN/TURN Operational Runbook

## Purpose
Operational guidance for deploying and validating STUN/TURN infrastructure for 1:1 WebRTC direct calling.

## Environments
- **Non-prod:** `turn-staging.<domain>`
- **Prod:** `turn.<domain>`
- Both environments must expose:
  - UDP 3478 (TURN/STUN)
  - TCP 3478 (TURN)
  - TLS 5349 (`turns:`)

## Required application settings
- `MESSAGING_WEBRTC_TURN_ENABLED=true`
- `MESSAGING_WEBRTC_TURN_URLS` (comma-separated, e.g. `turn:host:3478?transport=udp,turns:host:5349?transport=tcp`)
- `MESSAGING_WEBRTC_TURN_SECRET` (shared secret for HMAC credentials)
- `MESSAGING_WEBRTC_TURN_TTL_SECONDS` (default 600)

## TLS and certificates
- TLS certs for `turns:` endpoints must be valid and monitored for expiry.
- Certificate rotation is completed at least 14 days before expiry.
- Preferred minimum TLS version: 1.2.

## Auth and secret management
- TURN auth mode: shared-secret HMAC with temporary credentials.
- Username format: `<expires_at>:<user_id>`.
- Credential: Base64(HMAC-SHA1(secret, username)).
- Secret storage: secrets manager (never committed in source or plaintext env files).

## Secret rotation process
1. Generate new TURN shared secret in secret manager.
2. Deploy TURN service with dual-secret validation window (old + new).
3. Update app env `MESSAGING_WEBRTC_TURN_SECRET` to new secret.
4. Validate issuance and media relay in staging then prod.
5. Remove old secret after grace period.

## Firewall / network requirements
- Allow inbound to TURN nodes on:
  - UDP 3478
  - TCP 3478
  - TCP 5349 (TLS)
- Allow relay port range (vendor/config-specific) between TURN and clients.
- Ensure NAT/firewall rules permit outbound relay traffic from TURN nodes.

## Relay capacity assumptions
- Baseline planning assumption for 1:1 calls:
  - Audio-only relay: ~40-80 kbps per participant.
  - Video relay: ~300 kbps to 2 Mbps per participant depending on profile.
- For relay path, allocate capacity for both directions.
- Maintain 30% headroom for burst traffic and failover.

## Staging connectivity validation
Run from staging app/runtime environment:

```bash
MESSAGING_WEBRTC_TURN_URLS="turn:turn-staging.example.com:3478?transport=udp,turns:turn-staging.example.com:5349?transport=tcp" \
python scripts/check_webrtc_turn_readiness.py
```

Expected outcome:
- Script reports `OK` for each endpoint check.
- Exit code `0`.

## Baseline go-live checks
- TURN credential endpoint returns valid short-lived credentials for eligible participants.
- Signaling + invite/accept paths establish media in staging browsers.
- Relay ratio and failure reasons are visible in observability dashboards.
- Kill switch behavior verified (`MESSAGING_WEBRTC_TURN_ENABLED=false` blocks credential issuance).

## Incident response quick actions
- If TURN outage suspected:
  1. Verify DNS + TLS endpoint checks with readiness script.
  2. Check recent cert/secret rotations.
  3. Inspect app metric `messaging_turn_credential_issue_total{outcome,reason}`.
  4. If required, disable issuance via `MESSAGING_WEBRTC_TURN_ENABLED=false` while investigating.

## Validation evidence
- Save readiness script output from staging and production preflight.
- Record date/time, operator, environment, and git SHA in release checklist.
