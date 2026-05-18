# Messaging Drafts — DynamoDB Schema & Migration Plan

## Ticket
- **MSGD-004**
- **Status:** Implemented (2026-04-05)

## Table
- **Name:** `MessageDrafts` (override via `DDB_MESSAGE_DRAFTS`)
- **Billing mode:** `PAY_PER_REQUEST`
- **TTL attribute:** `ttl_epoch` (override via `DRAFTS_TTL_ATTR`)

## Keys
- **Primary key**
  - `owner_user_id` (HASH)
  - `draft_id` (RANGE)

Rationale:
- Enforces user-scoped ownership at partition boundary.
- Prevents cross-user scans for direct draft CRUD by id.

## GSIs
1. **ByConversationUpdatedAt**
   - HASH: `conversation_owner_key` (`{owner_user_id}#{conversation_id}`)
   - RANGE: `updated_at`
   - Purpose: fast list-by-conversation (newest-first query using reverse range scan).

2. **ByOwnerUpdatedAt**
   - HASH: `owner_user_id`
   - RANGE: `updated_at`
   - Purpose: owner-level inspection/cleanup workflows.

## Required attributes
- `draft_id` (string)
- `owner_user_id` (string)
- `conversation_id` (string)
- `conversation_owner_key` (string)
- `text` (string)
- `version` (number)
- `created_at` (number epoch seconds)
- `updated_at` (number epoch seconds)
- `client_updated_at` (optional number epoch seconds)
- `ttl_epoch` (number epoch seconds, optional policy-controlled)
- `tenant_id` (optional string for multi-tenant rollout)

## Security / scoping model
- Read/write access always filtered by authenticated `owner_user_id`.
- Conversation list queries use `conversation_owner_key` to ensure user + conversation scope.
- Draft records never use global conversation-only partition keys to avoid cross-user leakage.

## Migration
- Script: `scripts/migrations/20260405_messaging_drafts_schema.py`
- Idempotent behavior:
  - if table exists, migration does not recreate it.
  - TTL is enabled only if not already enabled with the target attribute.

## Deployment sequence
1. Deploy migration script.
2. Run migration in each environment.
3. Verify table exists and GSIs are ACTIVE.
4. Verify TTL status for `ttl_epoch` is ENABLED.
5. Deploy API layer depending on this table.

## Verification commands (example)
```bash
python scripts/migrations/20260405_messaging_drafts_schema.py
aws dynamodb describe-table --table-name MessageDrafts
aws dynamodb describe-time-to-live --table-name MessageDrafts
```

## Rollback considerations
- Rollback API usage first.
- Keep table intact (data-preserving rollback).
- Do not drop table during rollback unless explicit data migration is approved.
