# SEC-020: Browser-SSH / SFTP Destination SSRF (default allow-all → metadata/pivot)

**Ticket**: SEC-020 · **Status**: Open · **Priority**: Critical · **Date**: 2026-06-04
**Source**: docs/security-audit-2026-06.md (Wave 4). Related: SEC-001 (SSRF).

## Problem
The browser SSH terminal and SFTP mounts let an authenticated user connect to an
**arbitrary host:port**, and the destination policy is **allow-all by default**:
- `app/routers/browser_ssh_terminal.py:408-488` — `_enforce_destination_policy`
  only blocks when `BROWSER_SSH_ALLOWED_HOSTS`/`BROWSER_SSH_DENIED_HOSTS` are set;
  both default to empty → any host allowed. `ParamikoSshBridge` then dials the
  user-supplied host with user creds.
- `app/services/sftp_destination_policy.py:16,84-97` — mode defaults to `allow_all`.
- No hardcoded denylist for `169.254.169.254` (cloud metadata), `127.0.0.1`/loopback,
  or RFC-1918 ranges.

**Exploit**: open the WS terminal / create an SFTP mount targeting
`169.254.169.254:80` → fetch IAM role creds from instance metadata; or `127.0.0.1`/
internal DB/K8s API → pivot into the private network. SSRF + credential theft + RCE
on the backend's cloud role.

## Fix
- **Deny by default**: refuse connections unless the host matches an explicit
  allowlist; ship a hardcoded denylist (link-local `169.254.0.0/16`, loopback,
  RFC-1918, `::1`, metadata hostnames) enforced **regardless** of config.
- Resolve the hostname and re-check the resolved IP against the denylist
  (DNS-rebinding-safe), for both SSH and SFTP.
- Bound port ranges; log/alert on blocked attempts.

## Testing
pytest: connect/mount to 169.254.169.254 / 127.0.0.1 / 10.x is rejected even with no
allowlist configured; an allowlisted host succeeds; a hostname resolving to a denied IP
is rejected.
