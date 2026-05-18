# Jira ↔ Internal Ticket Field Mapping Specification (JTS-002)

## 1) Purpose
This specification defines the canonical mapping contract between internal tickets and Jira issues for the initial Jira sync rollout.

It standardizes:
- field-level mapping (internal ↔ Jira),
- data types and required/optional semantics,
- null-handling behavior,
- per-workspace/per-project status and priority mapping strategies.

## 2) Scope
### In scope
- Core fields: summary, description, status, assignee, priority, labels, comments.
- Mapping behavior for both outbound (internal → Jira) and inbound (Jira → internal) sync.
- Conflict-safe transformation rules.

### Out of scope
- Jira custom fields beyond the core set listed here.
- Jira workflow automation replication.
- Full binary attachment mirroring.

## 3) Canonical Mapping Table

| Internal field | Internal type | Jira field | Jira type | Required | Null handling | Notes |
|---|---|---|---|---|---|---|
| `subject` | `string` | `summary` | `string` | Yes | `null`/empty internal value is rejected on outbound create/update; inbound empty summary maps to `"(no summary)"` placeholder with conflict flag | Trim whitespace; max length policy enforced upstream |
| `description` | `string` | `description` | `ADF document` | Optional | Internal `null`/empty maps to empty ADF doc; Jira empty/missing maps to empty string | Requires markdown/plain-text ↔ ADF conversion adapter |
| `status` | enum (`open`, `in_progress`, `waiting_on_user`, `done`, `reopened`) | `status.name` | `string` (workflow state) | Yes | If mapping missing for source value, sync fails with `mapping_missing_status` and enters `degraded/conflict` path | Resolved via mapping table in Section 5 |
| `assigned_to_sub` | `string \| null` | `assignee.accountId` | `string \| null` | Optional | Internal `null` unassigns Jira issue when permitted; Jira unassigned maps to internal `null` | Identity map required (`user_sub` ↔ `accountId`) |
| `priority` | enum/string (`low`,`medium`,`high`,`critical`) | `priority.name` | `string \| null` | Optional | If missing on either side, default mapping rules apply (Section 6) | Resolved via mapping table in Section 6 |
| `labels` | `list[string]` | `labels` | `list[string]` | Optional | `null` treated as empty list on both sides | Normalize lowercase + dedupe |
| `messages[].body` | `string` | `comment.body` | `ADF document` | Optional | Empty comment payloads are ignored (not synced) | Include source metadata to prevent echo loops |

## 4) Type and Validation Rules

### 4.1 Strings
- Trim leading/trailing whitespace before sync.
- Empty-after-trim values are treated as `null` unless field is required.

### 4.2 Enums
- Internal enums are validated before outbound sync.
- Unknown inbound enum values must not be dropped silently; they trigger mapping failure classification.

### 4.3 Lists
- Labels are normalized to lowercase, deduplicated, and sorted for deterministic comparisons.
- `null` list payloads are coerced to `[]`.

### 4.4 Comments
- Each synced comment must include source metadata marker:
  - `source_system` (`internal` or `jira`)
  - `source_message_id` / `source_comment_id`
- Marker is used to avoid sync loops.

## 5) Status Mapping Strategy (Per Workspace/Project)

Status mapping is configured by `(workspace_id, project_key)` pair.

### 5.1 Data model
A status mapping record includes:
- `workspace_id: string`
- `project_key: string`
- `internal_to_jira: map[string]string`
- `jira_to_internal: map[string]string`
- `default_jira_status: string` (optional fallback)
- `default_internal_status: string` (optional fallback)
- `is_strict: bool` (if true, missing mapping fails hard)

### 5.2 Recommended default mapping
- `open` → `To Do`
- `in_progress` → `In Progress`
- `waiting_on_user` → `Waiting for Customer`
- `done` → `Done`
- `reopened` → `Reopened`

### 5.3 Null/unknown handling
- If status is missing/null from source payload:
  - strict mode: fail with `mapping_missing_status`.
  - non-strict mode: apply configured default status if present, otherwise fail.
- If Jira workflow status changes and no mapping exists:
  - mark link `sync_state=conflict` and create actionable event.

## 6) Priority Mapping Strategy (Per Workspace/Project)

Priority mapping is configured by `(workspace_id, project_key)` pair.

### 6.1 Data model
A priority mapping record includes:
- `workspace_id: string`
- `project_key: string`
- `internal_to_jira: map[string]string`
- `jira_to_internal: map[string]string`
- `default_jira_priority: string` (optional)
- `default_internal_priority: string` (optional)
- `is_strict: bool`

### 6.2 Recommended default mapping
- `low` ↔ `Low`
- `medium` ↔ `Medium`
- `high` ↔ `High`
- `critical` ↔ `Highest`

### 6.3 Null/unknown handling
- Null priority inbound/outbound is allowed and treated as “unset” unless strict mode requires a value.
- Unknown values:
  - strict mode: fail with `mapping_missing_priority`.
  - non-strict mode: use configured default, else preserve existing destination value.

## 7) Directional Sync Rules

### Outbound (Internal → Jira)
- Validate required fields and mapping presence.
- Convert internal description/comment to Jira ADF.
- Apply mapped status/priority.
- Send idempotency key and source markers.

### Inbound (Jira → Internal)
- Parse Jira payload and normalize types.
- Map status/priority using workspace/project config.
- Convert ADF to internal text representation.
- Ignore echoed events where source marker indicates self-originated update.

## 8) Conflict Expectations
- A conflict is raised when both systems update the same mapped field between sync checkpoints.
- For mapped fields in this spec, conflict payload must include:
  - `field_name`
  - `internal_candidate_value`
  - `jira_candidate_value`
  - `internal_updated_at`
  - `jira_updated_at`

## 9) Versioning
- This document defines mapping spec version `v1`.
- Any backward-incompatible mapping change must bump spec version and include migration guidance.

## 10) Acceptance Coverage (JTS-002)
This document satisfies JTS-002 by providing:
1. Data types, required/optional flags, and null-handling rules for all requested fields.
2. Explicit status and priority mapping strategies scoped per workspace/project.
