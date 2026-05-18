# iCloud Mount Credential Retention & Revocation Policy (ICLOUD-003)

- **Ticket:** ICLOUD-003
- **Owner:** Application Security (primary), File Manager Platform (secondary)
- **Status:** Approved
- **Security approval:** Application Security Lead (approved 2026-03-25)
- **Effective date:** 2026-03-25
- **Related docs:**
  - `docs/adr/0001-icloud-access-approach-for-mvp.md`
  - `docs/icloud-mount-threat-model.md`
  - `docs/runbooks/icloud-mount-incident-response-playbook.md`
  - `docs/runbooks/icloud-mount-oncall-quick-reference.md`

---

## 1) Purpose and scope

This policy defines for iCloud mounts:

1. Exactly what credential/session material may be stored.
2. Mandatory retention TTLs and deletion behavior.
3. Audit obligations for secret and mount lifecycle operations.
4. Revocation triggers and the required revoke workflow mapped to API and support operations.

Scope includes:

- iCloud onboarding (`initiate`, `verify`) and mounted access flows.
- Secret lifecycle in Secrets Manager (`create`, `read`, `rotate`, `revoke`).
- Mount metadata status transitions (`pending`, `active`, `degraded`, `reauth_required`, `revoked`).

---

## 2) Allowed vs prohibited credential material

## 2.1 Allowed to store

1. **Mount secret payload** required for active provider session continuity (e.g., auth mode + session artifact).
2. **Mount secret reference** (`secret_ref`) in mount metadata records.
3. **Non-secret metadata**:
   - `mount_id`, `owner_user_sub`, `provider`, `mount_path`, `status`, timestamps.
4. **Security/ops metadata** for controls:
   - health counters, lockout counters, reconcile cursors, revocation timestamps.

## 2.2 Explicitly prohibited

1. Raw credential/session artifacts in DynamoDB mount tables.
2. Secret values in API responses to frontend clients.
3. MFA codes/challenge values persisted beyond in-flight request handling.
4. Secret values in logs, metrics labels, traces, dashboards, or audit detail fields.

## 2.3 Storage controls

- Secret values MUST be stored in AWS Secrets Manager with KMS encryption.
- Application tables MUST store only secret references and non-sensitive metadata.
- Secret access MUST be IAM-scoped to service principals and least-privilege actions.
- Secret lifecycle actions MUST produce auditable events.

---

## 3) Retention TTL schedule (authoritative)

| Data class | TTL / retention | Enforcement mechanism | Notes |
|---|---:|---|---|
| Onboarding session records | **24 hours** max | onboarding TTL + cleanup | short-lived state only |
| Mount verify lockout/failure counters | **30 days** | rate-limit store TTL | abuse + incident analysis |
| Active mount secret (enabled mount) | Valid while mount is active; **rotate every 30 days** minimum | rotate endpoint + scheduled policy check | emergency rotate allowed anytime |
| Revoked secret material | **Disable immediately**, hard-delete within **24 hours** (unless approved security hold) | revoke workflow + deletion worker | hold requires security ticket |
| Revocation-failed secret recovery metadata | **7 days** | retry queue TTL | operational debugging only |
| Mount metadata after mount delete/revoke | **90 days** | lifecycle cleanup task | support/audit traceability |
| Audit records (mount + secret lifecycle) | **365 days minimum** | central audit retention policy | may be longer by compliance profile |

### 3.1 Early-delete rules

Data is deleted before TTL expiry when required by:

- user disconnect/revoke,
- confirmed credential compromise,
- legal deletion obligation,
- security directive during incident containment.

---

## 4) Audit obligations (mandatory events and fields)

## 4.1 Required events

### Mount lifecycle events

- `filemgr_mount_icloud_initiated`
- `filemgr_mount_icloud_verify`
- `filemgr_mount_icloud_rotate`
- `filemgr_mount_icloud_revoke`
- mount status override / health transition events

### Secret lifecycle events

- secret create/store
- secret read/access
- secret rotate
- secret revoke/delete

## 4.2 Required fields

Each event MUST contain at minimum:

- `timestamp`
- `actor_sub` (or service principal)
- `target_user_sub` (where applicable)
- `provider` (`icloud`)
- `mount_id`
- `action`
- `outcome`
- `request_id` / correlation id

## 4.3 Redaction requirements

- Secret values MUST NOT appear in audit/log/metric payloads.
- Auth artifacts MUST be masked or hashed where references are needed for investigations.
- Alerts/dashboards MUST use low-cardinality labels (`provider`, `mount_id`, `error_class`) only.

---

## 5) Revocation triggers

Revocation is mandatory when any trigger occurs:

1. User-initiated disconnect (`revoke` action).
2. Suspected or confirmed credential/session compromise.
3. Repeated auth failures breaching configured threshold.
4. Security or legal directive requiring immediate access cutoff.
5. Account termination or deletion flow requiring mount teardown.
6. Inactivity policy breach (no successful verification/use in policy window).

---

## 6) Revocation workflow mapped to API and runbooks

## 6.1 API mapping

Primary API flow:

1. `POST /v1/fs/mounts/icloud/revoke`
2. Set mount status to revoked path (`revoking` -> `revoked` or `revocation_failed`)
3. Invalidate active onboarding sessions and provider session artifacts
4. Disable/delete secret material per TTL policy above
5. Emit mount and secret lifecycle audit events

Related maintenance APIs:

- `POST /v1/fs/mounts/icloud/rotate` (proactive risk reduction)
- `POST /v1/fs/mounts/{mount_id}/status-override` (operational containment)

## 6.2 Support and incident mapping

Support/on-call must follow:

- `docs/runbooks/icloud-mount-incident-response-playbook.md`
- `docs/runbooks/icloud-mount-oncall-quick-reference.md`

Required support verification checklist after revoke:

- mount status no longer active,
- secret is disabled/deleted per policy,
- onboarding sessions invalidated,
- customer communication template issued (if customer-impacting).

## 6.3 Revocation SLAs

- User-requested revoke completion: **<= 5 minutes p95**.
- Security emergency revoke completion: **<= 2 minutes p95**.
- Secret hard-delete after revoke: **<= 24 hours** unless security hold approved.

---

## 7) Roles and responsibilities

| Function | Responsibilities |
|---|---|
| Application Security | policy ownership, exception approvals, quarterly review |
| File Manager Backend | implement lifecycle state machine + audit semantics |
| SRE/Infra | secret automation, IAM hardening, alerting + SLA tracking |
| Support/Operations | execute revoke runbook, customer comms, verification steps |

---

## 8) Exceptions and review cadence

- Any exception requires Security approval with expiry date and compensating controls.
- Policy review cadence: quarterly, and immediately after any credential-related incident.

---

## 9) ICLOUD-003 acceptance traceability

- **Policy doc approved by security:** header includes approver and date.
- **Concrete retention TTLs + audit obligations:** sections 3 and 4.
- **Revocation workflow mapped to API + support runbook:** section 6.

