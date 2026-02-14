# Passwordless Link Hardening Plan

## Goals

Harden passwordless authentication against replay, token theft, and anomalous geolocation activity while preserving current UX.

## Scope

- `POST /ui/passwordless/start`
- `POST /ui/passwordless/verify`
- `app/services/magic_links.py`
- `app/routers/passwordless.py`

## 1) Strict one-time token semantics

### Token record model

Each issued token record should include:

- `token_id` (opaque internal identifier)
- `jti` (random nonce, unique per token)
- `token_hash` (store hash only)
- `target_user_sub`
- `issued_at`
- `expires_at` (short TTL; recommended 5–10 minutes)
- `used` (boolean)
- `used_at` (epoch seconds)
- `consumed_by_ip`
- `consumed_user_agent`
- `consumed_reason` (`success`, `mismatch_stepup`, `replay_denied`, `expired`)

### Validation rules

- Reject if `used=true` regardless of expiration.
- Reject if `expires_at < now`.
- Require compare-and-set update on consume:
  - `ConditionExpression`: token exists AND `used=false` AND not expired.
- On successful consume, set:
  - `used=true`
  - `used_at=now`
  - consumption metadata fields.
- Treat all consume races as replay attempts and audit as `passwordless_replay_denied`.

### UX behavior

- Always return generic 401/invalid token externally.
- Keep detailed reason in audit logs/alerts.

## 2) Short TTL policy

### Recommended defaults

- `PASSWORDLESS_TOKEN_TTL_SECONDS=600` (10 min max)
- optional stronger default for high-risk users: `300` seconds.

### Operational controls

- Add per-user and per-IP issue limits on `/start`.
- Add single active-token policy per user (optional): issue new token revokes prior pending tokens.

## 3) Explicit consumed-at observability

Track and expose (internal only):

- issue-to-use latency (`used_at - issued_at`)
- replay attempts count
- expired token verifies count
- mismatch-triggered step-up count

This improves incident response and anomaly detection quality.

## 4) Geovelocity & impossible-travel heuristics

### Data required

- Coarse geolocation signal from request IP prefix (country/region/city where available).
- Previous successful auth event location + timestamp.

### Practical checks

- **Impossible travel**:
  - If previous successful login was too recent for plausible travel between two far-apart locations, mark high risk.
- **Geovelocity threshold**:
  - Compute distance/time speed estimate (coarse km/h).
  - If estimated speed exceeds threshold (e.g., > 900 km/h with low confidence buffer), flag.
- **Confidence gating**:
  - Only enforce hard actions when both locations have acceptable confidence.
  - Otherwise degrade to soft risk signals.

### Actions when flagged

- Never grant immediate session directly.
- Force step-up with strongest available factors (`totp` + `email` preferred).
- Shorten refresh-token TTL for resulting session.
- Emit unusual sign-in alert event with risk details.

## 5) Suggested event taxonomy

- `passwordless_start`
- `passwordless_verify_success`
- `passwordless_verify_mismatch_stepup`
- `passwordless_replay_denied`
- `passwordless_token_expired`
- `passwordless_impossible_travel`
- `passwordless_geovelocity_flag`

## 6) Rollout sequence

1. Add token record fields + CAS consume semantics.
2. Add consumed-at metadata and replay audit events.
3. Add short TTL config + migration fallback defaults.
4. Add geovelocity/impossible-travel checks in verify path (soft mode).
5. Switch to enforcement mode (step-up + short refresh TTL).
6. Monitor false positives and tune thresholds.

## 7) Test matrix

- token can be used exactly once
- concurrent verify attempts -> one success, others replay denied
- expired token cannot be consumed
- mismatch path consumes token and forces step-up
- impossible-travel flag triggers stronger factors
- high-risk result carries reduced refresh TTL
- alerts generated for unusual sign-ins and replay attempts
