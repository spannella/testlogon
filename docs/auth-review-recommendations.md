# Login & Registration Review (Current State + Recommendations)

## Current setup (what is already good)

- Registration enforces basic password policy, password confirmation, email normalization, and optional SMS/TOTP MFA flags at schema-validation time.
- Registration checks candidate passwords against a breach corpus before creating users.
- Registration and passwordless flows both use lockout + rate limiting + anomaly tracking hooks.
- New sessions are created with per-session CSRF tokens, inactivity checks, and optional device-trust risk checks.
- Session rotation revokes prior sessions and rotates refresh tokens.

## Gaps and risks observed

1. **Dev bypass accounts can return synthetic auth success**
   - In dev mode, matching configured credentials bypass Cognito and return a fixed `"dev-session"` during registration confirm.
   - This is practical for local testing, but risky if dev flags leak into non-dev environments.

2. **Potential account enumeration via registration check and registration errors**
   - `/ui/register/check` exposes explicit availability.
   - Registration creation and error handling can return distinct outcomes (e.g., conflict semantics), which can be used to probe whether an account exists.

3. **Password policy is only baseline-complexity + breach check**
   - Current validation is `>=8` and alphanumeric complexity; this is better than nothing but below modern recommendations for passphrases and deny-lists beyond breach corpus.

4. **Registration challenge keying appears single-slot per user**
   - Registration verification challenge uses a fixed session id (`register_verify`).
   - This simplifies state, but limits support for parallel verification contexts and may make troubleshooting/audit correlation harder.

5. **Magic-link handling can be tightened for replay and context binding**
   - Passwordless verify correctly marks links used and introduces step-up on mismatch, but hardening could include stronger one-time guarantees plus explicit nonce/jti telemetry in audit records.

6. **Auth-mode split is operationally sensitive**
   - Runtime behavior depends on Cognito config and `dev_mode`, with fallback auth via bearer token parsing in dev mode.
   - Misconfiguration risk is non-trivial without strict startup guardrails.

## Recommendations (prioritized)

### P0 (security posture / production safety)

1. **Add startup guardrails that fail fast in unsafe auth configurations**
   - Refuse startup when `dev_mode=true` in production profiles.
   - Refuse startup if Cognito is partially configured (e.g., app client set but issuer/JWKS invalid).
   - Add a health endpoint field that reports active auth mode (`cognito|dev-fallback`) for ops visibility.

2. **Normalize externally visible responses to reduce account enumeration**
   - For registration check/start/resend, return generic success messaging while performing internal audit logging.
   - Keep detailed reasons only in audit events and internal metrics.

3. **Strengthen password policy**
   - Move from character-class requirements to passphrase-oriented policy (e.g., min length 12+, max length sanity cap, optional entropy checks).
   - Add checks against contextual password guesses (email local part, name fragments).

### P1 (workflow hardening)

4. **Use per-attempt registration challenge IDs**
   - Replace fixed `register_verify` with generated challenge IDs and keep a "latest active" pointer if needed.
   - This improves replay resistance and incident analysis while preserving current UX.

5. **Make login anomaly responses adaptive**
   - Today anomalies are audited and may add `email` factor; expand policy to include temporary risk scoring actions:
     - require stronger factors when IP/user thresholds exceed limits,
     - shorten refresh TTL for high-risk sessions,
     - trigger user notifications for unusual sign-ins.

6. **Harden passwordless link claims**
   - Ensure token records include strict one-time nonce semantics with short TTL and explicit consumed-at timestamp.
   - Add geovelocity checks and impossible-travel heuristics where feasible.

### P2 (operability / maintainability)

7. **Consolidate auth flow terminology and rate-limit namespaces**
   - Some registration operations use password-recovery rate-limit buckets; separate namespaces for cleaner observability and safer tuning.

8. **Improve structured audit schema consistency**
   - Standardize event payload fields across register/login/passwordless (`risk_level`, `factor_set`, `challenge_id`, `device_id`, `ip_prefix`).

9. **Add scenario tests for misconfiguration and attack paths**
   - Add tests for dev-mode leakage prevention, generic-response anti-enumeration behavior, challenge replay attempts, and risk-based step-up transitions.

## Suggested implementation order (2 sprints)

- **Sprint 1**: startup guardrails, anti-enumeration response normalization, password policy upgrade.
- **Sprint 2**: per-attempt registration challenge IDs, stronger passwordless token lifecycle metadata, expanded anomaly/risk actions + tests.
