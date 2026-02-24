# Ticketing DynamoDB Schema & Access Patterns (TKT-002)

This document defines the DynamoDB schema for ticket metadata, threaded messages, and activity timeline records, plus index strategy and optimistic concurrency rules.

## Goals
- Support all ticket list/detail query paths without full table scans.
- Support user inbox, admin queue, and assignee queue access patterns.
- Define a versioning strategy for safe concurrent updates.

## Table
- **Env var**: `TICKETS_TABLE_NAME`
- **Table name default**: `tickets`
- **Primary key**:
  - Partition key: `pk` (string)
  - Sort key: `sk` (string)

## Item families

### 1) Ticket header (metadata)
Represents one ticket and carries denormalized queue fields.

- `pk = TICKET#<ticket_id>`
- `sk = META`
- Attributes:
  - `entity_type = ticket_meta`
  - `ticket_id`
  - `owner_sub`
  - `subject`
  - `status` (`open|in_progress|waiting_on_user|done`)
  - `assigned_admin_sub` (nullable)
  - `priority` (optional)
  - `created_at`
  - `updated_at`
  - `last_message_at`
  - `last_message_by_role` (`user|admin`)
  - `version` (integer, starts at `1`)

### 2) Ticket message
Append-only thread entries.

- `pk = TICKET#<ticket_id>`
- `sk = MSG#<created_at_epoch_ms>#<message_id>`
- Attributes:
  - `entity_type = ticket_message`
  - `ticket_id`
  - `message_id`
  - `sender_sub`
  - `sender_role`
  - `body`
  - `created_at`
  - `email_alert_queued_for` (list)

### 3) Ticket activity
Append-only activity log for operational/audit timeline.

- `pk = TICKET#<ticket_id>`
- `sk = ACT#<created_at_epoch_ms>#<activity_id>`
- Attributes:
  - `entity_type = ticket_activity`
  - `ticket_id`
  - `activity_id`
  - `activity_type` (`ticket_opened|ticket_assigned|ticket_replied|ticket_status_changed|...`)
  - `actor_sub`
  - `details` (object)
  - `created_at`

## GSIs

### GSI 1 — User ticket list
For "My tickets" sorted by recent activity.

- **Name**: `TICKETS_OWNER_INDEX_NAME`
- **PK**: `gsi1pk = OWNER#<owner_sub>`
- **SK**: `gsi1sk = UPDATED#<updated_at_epoch_ms>#TICKET#<ticket_id>`
- **Projected fields**: ticket header summary fields.

### GSI 2 — Admin queue by status
For admin dashboard queues filtered by status.

- **Name**: `TICKETS_STATUS_INDEX_NAME`
- **PK**: `gsi2pk = STATUS#<status>`
- **SK**: `gsi2sk = UPDATED#<updated_at_epoch_ms>#TICKET#<ticket_id>`
- **Projected fields**: ticket header summary fields.

### GSI 3 — Assignee queue
For "assigned to me" dashboard view.

- **Name**: `TICKETS_ASSIGNEE_INDEX_NAME`
- **PK**: `gsi3pk = ASSIGNEE#<assigned_admin_sub>`
- **SK**: `gsi3sk = UPDATED#<updated_at_epoch_ms>#TICKET#<ticket_id>`
- **Projected fields**: ticket header summary fields.

## Access patterns

### User flows
1. **Create ticket**
   - Put ticket header (`META`) + initial message (`MSG`) + initial activity (`ACT`).
2. **List user tickets**
   - Query GSI1 by `OWNER#<owner_sub>` descending on updated time.
3. **Ticket detail thread**
   - Query base table where `pk=TICKET#<ticket_id>` and `begins_with(sk, 'MSG#')`.
4. **Ticket activity timeline**
   - Query base table where `pk=TICKET#<ticket_id>` and `begins_with(sk, 'ACT#')`.

### Admin flows
1. **Queue by status**
   - Query GSI2 by `STATUS#open|in_progress|...`.
2. **Assigned-to-me queue**
   - Query GSI3 by `ASSIGNEE#<admin_sub>`.
3. **Assign ticket**
   - Conditional update on header (`META`) with version check.
4. **Reply / status change**
   - Append message/activity rows + conditional header update with version check.

## Optimistic concurrency strategy
Use `version` on ticket header item (`sk=META`).

### Update pattern
- Read current ticket header and capture `version`.
- Update with condition:
  - `ConditionExpression = "version = :expected_version"`
- Set:
  - `version = :expected_version + 1`
  - `updated_at = :now`
  - queue-denormalized fields (status, assignee, last message metadata).

### Conflict behavior
- If condition fails (`ConditionalCheckFailedException`), return conflict response (`409`) and require client refresh + retry.

## Projection guidance
For all GSIs, use projected summary fields to avoid follow-up `GetItem` calls in list views.
Recommended projection:
- `ticket_id`, `owner_sub`, `subject`, `status`, `assigned_admin_sub`, `priority`, `updated_at`, `last_message_at`, `last_message_by_role`, `version`.

## Notes for implementation
- Keep `META` as the only mutable item family.
- Keep `MSG` and `ACT` append-only to preserve timeline integrity.
- For pagination, use DynamoDB `LastEvaluatedKey` cursors in list APIs.
