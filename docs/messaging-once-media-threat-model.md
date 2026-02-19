# Once-Media Threat Model (MOM-042)

## Scope

This threat model covers view-once images/videos and listen-once audio in messaging, including grant issuance, attachment retrieval, consume transitions, and client playback/open flows.

### Assets in scope

- Once-media attachment objects (encrypted at rest)
- Short-lived grant tokens and signed attachment URLs
- Recipient-specific consume state (`pending|consumed|expired|failed`)
- Audit logs and low-cardinality telemetry signals

### Trust boundaries

1. **Client device** (untrusted endpoint; user can attempt extraction/capture)
2. **API service** (authz + consume policy enforcement)
3. **Storage/CDN layer** (signed URL + no-store controls)
4. **Observability systems** (must not receive secrets/content)

---

## Threats and mitigations

| Threat | Description | Primary mitigations | Residual risk |
|---|---|---|---|
| Replay of grant token | Reusing attachment grant token after first open or from copied URL | HMAC-signed short-lived grants, recipient/conversation/message binding checks, server consume checks, strict expiration | Token can be replayed before expiry if exfiltrated from compromised endpoint |
| Multi-device race consume | Two devices attempt consume concurrently | Atomic CAS consume transition + idempotency via `consumption_attempt_id`, conflict handling (`already_consumed`) | Short UX race window until state sync completes |
| Unauthorized recipient access | Non-participant or sender attempts recipient grant/consume flow | Participant checks + recipient-specific consumption row checks, explicit authz errors | None beyond account compromise scenario |
| Sensitive URL/token leakage in logs | Grant URL/token accidentally logged by server/client telemetry | Telemetry contract forbids URLs/tokens/content labels; code paths map to stable error codes | Developer-introduced logging regressions remain possible |
| Client-side persistence of decrypted media | Browser/app stores opened media data for replay | no-store fetch policy, ephemeral blob URL + revoke, avoid persistent cache/storage writes | OS/browser caches and screenshots cannot be fully prevented |
| Forwarding/export vectors | Recipient forwards once-media payload | UI disables forward action for once-media, policy-gated flows | Out-of-band capture (camera, screenshots, recording) remains possible |
| Abuse/scam content with once-media | Malicious content sent as once-media to avoid later review | Report workflow captures message metadata before consume where available, moderation runbook escalation paths | Consumed media may be unavailable to moderators on web-only clients |

---

## Control requirements

1. **Server-authoritative enforcement**
   - Grant and consume decisions are enforced on backend, not only client UI.
2. **Least-data telemetry**
   - Metrics/logs include only stable codes and low-cardinality labels.
   - No media URLs, grant tokens, plaintext content, file paths, or cryptographic secrets.
3. **Deterministic failure semantics**
   - Standard error codes (`already_consumed`, `grant_expired`, `invalid_grant`, `consume_threshold_not_met`) drive support + client behavior.
4. **Rollback readiness**
   - Incident path must include global kill switch + staged re-enable procedure.

---

## Validation checklist

- [x] Grant replay and binding checks reviewed.
- [x] Atomic consume + race/idempotency behavior reviewed.
- [x] Telemetry secrecy constraints documented and linked to observability runbook.
- [x] Residual leakage vectors documented (screen capture/endpoint compromise).
- [x] Incident rollback includes once-media kill switch path.

---

## Sign-off

- Product: **approved**
- Backend: **approved**
- Client: **approved**
- Security: **approved**
- Date: `2026-02-19`
- Ticket: `MOM-042`

Linked docs:
- `docs/messaging-once-media-feature-flags-runbook.md`
- `docs/messaging-once-media-observability.md`
- `docs/messaging-once-media-support-moderation-runbook.md`
