# Broadcast Release Gate Exceptions Policy (BRD-023)

This policy governs temporary waivers for broadcast release gate controls.

## Scope
Applies to `scripts/release_gate_broadcast.py` checks:
- `metrics_wired`
- `critical_alerts`
- `api_contracts`
- `security_checks`

## Rules
1. Exceptions are **time-bound** and must include `expires_at` (UTC ISO8601).
2. Exceptions require:
   - incident or risk ticket reference,
   - approver (service owner + on-call lead),
   - explicit mitigation plan and due date.
3. Expired exceptions are automatically ignored by the gate.
4. Production deploys with active exceptions must be announced in release notes.

## Auditable exception file
Path: `.release-gate-exceptions/broadcast.json`

Example entry:
```json
{
  "api_contracts": {
    "ticket": "INC-12345",
    "approver": "broadcast-owner",
    "expires_at": "2026-04-20T00:00:00Z",
    "reason": "temporary CI instability during dependency upgrade"
  }
}
```

## Enforcement
- Gate output must list failed controls and waived controls.
- If any non-waived control fails, deployment is blocked.
