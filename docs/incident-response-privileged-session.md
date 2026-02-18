# Incident Response Playbook: Compromised Admin/Root Session

## Severity
Treat compromised root/admin sessions as **SEV-1** until contained.

## Detection triggers
- Unexpected `admin_role_granted` / `admin_role_revoked` events.
- Impersonation started without approved ticket/reason.
- Root login from unknown/untrusted network source.
- Burst of privileged API writes or repeated `403/429` policy errors.

## Triage (0-15 minutes)
1. Open incident channel and assign commander.
2. Identify impacted principal(s): `actor_sub`, `effective_sub`, IP, request_id.
3. Pull timeline from:
   - `/admin/roles/audit`
   - `/admin/impersonation/audit`
   - `/v1/fs/admin/audit`
   - SIEM stream `security_audit`.

## Containment (15-30 minutes)
1. Revoke all active sessions for suspected principals.
2. Stop active impersonation sessions immediately.
3. Block suspicious source CIDRs at edge/WAF.
4. If root risk suspected:
   - disable root login path at edge,
   - rotate root secrets/MFA recovery materials,
   - verify `ROOT_USER_SUB` integrity.

## Eradication (30-120 minutes)
1. Undo unauthorized admin grants/revokes with documented reason.
2. Revert unauthorized billing/file operations using audit correlation ids.
3. Rotate API keys/tokens accessed during compromise window.
4. Re-run integrity checks on privileged tables and alert channels.

## Recovery
1. Restore minimum required access.
2. Re-enable root login only after security sign-off.
3. Increase alert sensitivity thresholds for 72 hours.
4. Perform targeted regression run:
   - policy matrix tests,
   - root network tests,
   - admin roles/impersonation tests.

## Post-incident review
- Publish timeline with:
  - first detection,
  - containment completion,
  - recovery completion,
  - blast radius summary.
- Capture corrective actions:
  - control gaps,
  - dashboard/alert tuning,
  - runbook updates.

## Required evidence artifacts
- Raw SIEM event export.
- Role/impersonation audit snapshots.
- Session revocation records.
- Change log of all emergency config edits.
