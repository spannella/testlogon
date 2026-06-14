# ADR AND-405: Admin / Agents / Infra out of scope for mobile (pointer)

- **Status:** Accepted (2026-06-05)
- **Backlog:** AND-405 (M8 / E53)

This decision record is co-located with the Android port. The authoritative
content lives at:

`android/docs/decisions/AND-405-scope-admin-agents-infra.md`

Summary: full administration, agents/bots fleet, compute/k8s/EC2, SSH bastion,
VNC, and devtools are OUT OF SCOPE for the native Android app
(`com.testlogon.android`). The only exceptions are the narrow, read-only,
role-gated admin views AND-403 (alerts/dashboards) and AND-404 (email/SMS
dashboards). See the linked record for the classification/evidence table,
enforcement posture, and the superseding-ADR requirement to reverse any exclusion.
