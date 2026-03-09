# AD Admin SSO Local Key Rotation Drill (AD-021)

## Goal
Validate local Keycloak key-rotation behavior for Admin SSO callback verification:
1. **Success** with existing signing key.
2. **Expected failure** during stale JWKS cache interval.
3. **Recovery** after JWKS cache refresh window.

This drill is designed to require **no manual DB edits**.

## Preconditions
- Host-mode Keycloak started and seeded:
  ```bash
  scripts/local-ad-sso-up.sh
  ```
- Backend dependencies available.
- Local Admin SSO provider setup uses local Keycloak issuer/JWKS metadata.

## Rotation command
Rotate local realm signing keys:

```bash
python3 scripts/local-keycloak-rotate-keys.py
```

Expected output includes old/new active signing `kid` values.

## Integration drill test profile
Run the AD-021 integration test profile:

```bash
RUN_LOCAL_KEYCLOAK_ROTATION=1 \
  PYTHONPATH=deployment_initializer/backend \
  pytest deployment_initializer/backend/tests/test_admin_sso_keycloak_rotation.py
```

## Expected behavior
- First callback succeeds (cache warmed on old key).
- After rotation, callback fails in stale JWKS interval with:
  - `sso_callback_jwks_unreachable`.
- After cache TTL window, callback succeeds again.
- Metrics snapshot shows callback failures and triggers callback-error alert (`admin_sso_callback_errors`) during stale window.
- Audit row records failure reason for stale interval callback failure.

## Notes
- Cache TTL is controlled by `ADMIN_SSO_JWKS_CACHE_TTL_SECONDS` (test profile sets this to `2` seconds for fast drills).
- If rotation script reports unchanged active key, rerun the rotation command.
