# AD Admin SSO Negative Test Matrix (AD-016)

This matrix captures required regression coverage for token validation, role mapping, and auth bypass scenarios.

## Callback token validation failures

| Scenario | Expected Result | Reason Code |
|---|---|---|
| Malformed JWT segments | Callback rejected (non-200) | `sso_callback_malformed_token` |
| Invalid signature | Callback rejected (non-200) | `sso_callback_invalid_signature` |
| Unsupported algorithm (`alg=none`) | Callback rejected (non-200) | `sso_callback_invalid_algorithm` |
| Issuer mismatch | Callback rejected (non-200) | `sso_callback_invalid_issuer` |
| Audience mismatch | Callback rejected (non-200) | `sso_callback_invalid_audience` |
| Nonce mismatch | Callback rejected (non-200) | `sso_callback_invalid_nonce` |
| Expired token | Callback rejected (non-200) | `sso_callback_token_expired` |
| Missing required identity claims (`sub`, `tid`) | Callback rejected (non-200) | `sso_callback_missing_required_claims` |

## State/nonce and replay defenses

| Scenario | Expected Result | Reason Code |
|---|---|---|
| Reusing a consumed `state` value | Callback rejected (non-200) | `sso_state_already_used` |
| Expired state record | Callback rejected (non-200) | `sso_state_expired` |
| Unknown state value | Callback rejected (non-200) | `sso_state_invalid_or_reused` |

## Role mapping and privilege escalation defenses

| Scenario | Expected Result | Reason Code |
|---|---|---|
| No mapping and no default role | Access denied | `sso_role_mapping_denied` |
| External group mapped to `root` | Access denied | `sso_root_role_forbidden` |
| Default role set to `root` | Access denied | `sso_root_role_forbidden` |

## Authorization guardrails

| Scenario | Expected Result | Reason Code |
|---|---|---|
| Non-root principal invokes config mutation endpoint | Forbidden | `forbidden_insufficient_role` |
| Admin principal without `ad_sso` when enforcement enabled | Forbidden | `forbidden_admin_sso_required` |
| Local `root` principal when enforcement enabled | Allowed | N/A |

## Current automated coverage
- `deployment_initializer/backend/tests/test_admin_sso_unit.py`
- `deployment_initializer/backend/tests/test_admin_sso.py`
- `deployment_initializer/backend/tests/test_admin_sso_config_api.py`
- `deployment_initializer/backend/tests/test_auth.py`

These tests are intended to run in CI as mandatory gating checks for AD-016.
