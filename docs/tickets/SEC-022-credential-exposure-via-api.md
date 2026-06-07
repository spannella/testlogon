# SEC-022: Stored Credentials Exposed via API Responses

**Ticket**: SEC-022 · **Status**: Open · **Priority**: High · **Date**: 2026-06-04
**Source**: docs/security-audit-2026-06.md (Wave 4)

## Problem
Most credentials are KMS-encrypted at rest and stripped from responses (SSH keys, LLM
keys, OAuth access tokens, GitHub/GitLab tokens, CalDAV passwords — all good). The
exceptions leak secret material to the client:
- **Refresh-token ciphertext exposed**: `provider_oauth.py:314` stores
  `refresh_token_ct_b64` in `metadata`, and `routers/projects.py:352-362` returns the
  whole `metadata` dict (incl. `refresh_token_ct_b64`) to the client. Ciphertext should
  never leave the server (oracle/exfil risk; defense-in-depth).
- **S3 secret returned in plaintext**: `provider_credentials.py:533-543`
  `get_provider_auth_context` returns `secret_access_key` (and copies it into `token`)
  in cleartext — if any caller logs/returns the context, the AWS secret leaks.
- **SFTP secrets in memory**: `routers/filemanager.py:1357-1369` decrypts
  password/private-key/passphrase into a config object with no scrub (memory-dump risk).

## Fix
- Strip `refresh_token_ct_b64` (and any `*_ct_b64`/secret keys) from `metadata` before
  returning; expose only `has_refresh_token: bool`. Filter `ProviderCredentialOut` to an
  allowlist of safe fields.
- Don't return `secret_access_key`/`token`=secret from auth-context; provide a scoped
  signer/helper that uses the secret server-side only.
- Minimize SFTP secret lifetime in memory; avoid logging; scrub where feasible.

## Testing
pytest: GET provider credentials never contains `refresh_token`/`*_ct_b64`/secret;
S3 auth-context doesn't include `secret_access_key` in any client-reachable path.
