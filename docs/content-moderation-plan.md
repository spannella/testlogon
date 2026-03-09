# Content Moderation Plan (Newsfeed, Messages, Profile Photos)

## 1. Goals

Implementation breakdown: see `docs/content-moderation-implementation-tickets.md`.
- Let users report problematic content in **newsfeed posts/comments**, **direct/group messages**, and **profile photos**.
- Route every report into a centralized **moderation ticket board**.
- Give admins a consistent decision workflow: **approve/no action**, **reject content (remove)**, **warn user**, or **ban user**.
- Preserve an auditable moderation trail, including prior bans/warnings history.
- Capture structured report context, including a free-text reason and topic tags:
  - `sexual`
  - `extortion`
  - `criminal`
  - `spam`
  - `racist`

---

## 2. Scope and Content Types
### In scope
1. Newsfeed
   - Post
   - Comment
   - Attached image/video
2. Messaging
   - Message text
   - Image/video/file attachment
3. Profile
   - Profile photo

### Out of scope (phase 1)
- Automated ML moderation decisions (allowed later as recommendations only).
- Appeals portal for end users (tracked as phase 2 enhancement).

---

## 3. High-Level Workflow
1. User clicks **Report** on a piece of content.
2. Client opens report modal:
   - Select one or more topics (`sexual`, `extortion`, `criminal`, `spam`, `racist`).
   - Enter optional/required reason text.
3. Backend validates report and creates a **Moderation Ticket**.
4. Ticket appears on moderator board with content snapshot and metadata.
5. Admin reviews and chooses disposition:
   - **No violation** (close ticket, keep content).
   - **Violation – remove content**.
   - Optional enforcement: **warn user** or **ban user**.
6. System executes action atomically (or with compensating retry):
   - Content hidden/removed.
   - Enforcement record created.
   - Ticket status/resolution updated.
   - Audit log entry written.
7. Admin can view offender history (prior warnings/bans) from the ticket before finalizing.

---

## 4. Data Model Proposal

### 4.1 `content_reports`
Represents user-submitted reports (many reports can map to one moderation ticket if deduplicated).

Fields:
- `id` (uuid)
- `reporter_user_id`
- `content_type` (`feed_post`, `feed_comment`, `feed_media`, `message`, `message_media`, `profile_photo`)
- `content_id`
- `content_owner_user_id`
- `topics` (array enum: sexual/extortion/criminal/spam/racist)
- `reason_text`
- `status` (`submitted`, `linked_to_ticket`, `dismissed`)
- `created_at`

### 4.2 `moderation_tickets`
Single moderator work item.

Fields:
- `id` (uuid)
- `queue` (`newsfeed`, `messages`, `profile`)
- `priority` (`low`, `medium`, `high`, `critical`)
- `status` (`open`, `in_review`, `resolved`, `closed`)
- `content_type`
- `content_id`
- `content_owner_user_id`
- `report_count`
- `aggregated_topics` (set)
- `latest_report_at`
- `assigned_admin_user_id` (nullable)
- `resolution` (`no_violation`, `content_removed`, `content_removed_warned`, `content_removed_banned`)
- `resolution_notes`
- `resolved_by_admin_user_id`
- `resolved_at`
- `created_at`
- `updated_at`

### 4.3 `moderation_actions`
Immutable action log for each decision/action.

Fields:
- `id` (uuid)
- `ticket_id`
- `action_type` (`remove_content`, `warn_user`, `ban_user`, `no_action`)
- `target_user_id`
- `target_content_type`
- `target_content_id`
- `metadata` (json; e.g., ban duration, warning template id)
- `performed_by_admin_user_id`
- `created_at`

### 4.4 `user_enforcement_history`
Queryable summary (can be a table or materialized view).

Fields:
- `id`
- `user_id`
- `enforcement_type` (`warning`, `ban`)
- `reason_code/topics`
- `source_ticket_id`
- `active` (for bans)
- `starts_at`
- `ends_at` (nullable for permanent)
- `created_by_admin_user_id`
- `created_at`

### 4.5 `moderation_audit_log`
Security/audit event stream for compliance and incident review.

Fields:
- `id`
- `actor_user_id`
- `actor_role`
- `event_type`
- `entity_type`
- `entity_id`
- `before_state` (json)
- `after_state` (json)
- `ip_hash`
- `user_agent_hash`
- `created_at`

---

## 5. API Contract (Draft)

### User-facing
- `POST /v1/moderation/reports`
  - Input: `content_type`, `content_id`, `topics[]`, `reason_text`.
  - Validations:
    - Content exists and is reportable.
    - Topics subset of allowed taxonomy.
    - Reporter cannot report own content? (product decision; often allowed for compromised-account handling).
  - Output: report + ticket reference.

### Admin-facing board
- `GET /v1/admin/moderation/tickets?status=&queue=&topic=&assigned=`
- `GET /v1/admin/moderation/tickets/{ticket_id}`
  - Includes content preview/snapshot + offender enforcement history.
- `POST /v1/admin/moderation/tickets/{ticket_id}/assign`
- `POST /v1/admin/moderation/tickets/{ticket_id}/resolve`
  - Payload:
    - `resolution` (`no_violation` | `content_removed`)
    - `enforcement` (`none` | `warn` | `ban`)
    - `ban_duration_days` (optional)
    - `resolution_notes`

### Enforcement history
- `GET /v1/admin/moderation/users/{user_id}/history`

---

## 6. Ticketing & Board Behavior
- Default queues: `newsfeed`, `messages`, `profile`.
- Deduplication rule: reports on the same `content_type + content_id` within active window map to one open ticket; `report_count` increments.
- SLA indicators:
  - `critical`: extortion/criminal + repeated reports.
  - `high`: sexual/racist with media evidence.
- Board views:
  - Unassigned
  - Assigned to me
  - Escalated
  - Recently resolved
- Bulk actions (later phase): close as no violation for clear spam waves.

---

## 7. Admin Decision Tree
1. Review content snapshot and context.
2. Review report topics and reason text.
3. Review prior warnings/bans for the content owner.
4. Choose outcome:
   - **No violation** → close ticket, keep content.
   - **Violation** → remove content.
5. Optional enforcement:
   - First/low severity: warning.
   - Repeat/high severity: temporary or permanent ban.
6. Enter required moderation notes.
7. Confirm action; system commits all records and logs.

Guardrails:
- Require second-review for permanent bans (optional policy toggle).
- Prevent resolving already-resolved ticket unless using explicit override workflow.

---

## 8. Content Removal Semantics
- Use **soft delete/hide** first for reversibility:
  - `visibility = removed_by_moderation`
  - Preserve original bytes/text for legal retention policies.
- Message removal behavior:
  - Remove from active conversation UI.
  - Preserve in compliance archive if legal policy requires.
- Profile photo rejection:
  - Revert to previous approved photo or default avatar.

---

## 9. User Notifications
- Reporter:
  - Optional confirmation: “Thanks, your report was received.”
  - Do not expose detailed moderation outcome.
- Offending user:
  - If content removed: notify with policy reason category.
  - If warned: include warning message and next-step guidance.
  - If banned: include duration and appeal/contact route (if enabled).

---

## 10. Permissions & Security
- Only users with moderation/admin roles can access board endpoints.
- Action authorization split:
  - Moderator: remove + warn.
  - Senior admin: permanent bans.
- Full audit logging for every read/write on moderation entities.
- Rate limit report endpoint to reduce abuse.
- Anti-brigading heuristics:
  - Cap weight of duplicate reports from tightly linked accounts.

---

## 11. Analytics & Monitoring
Track:
- Tickets created/day by queue and topic.
- Median time to first review and time to resolution.
- Removal rate, warning rate, ban rate.
- Repeat offender rate (warned/banned users reoffending).
- False report ratio (no_violation outcomes).

Alerts:
- Surge in `extortion` or `criminal` topics.
- Backlog threshold exceeded for high/critical tickets.

---


## 12.1 Evidence Retention and Removal Behavior
- **Feed removals** are soft removals: post/comment records stay in storage with moderation metadata and source ticket reference, while user-facing feed/comment APIs exclude moderated items.
- **Message removals** set moderation-hidden flags and clear user-facing payload fields for removed content/media, but message records remain stored for compliance/legal workflows.
- **Profile-photo removals** revert active profile photo to the previous approved/default value and retain last-removed metadata linked to the source moderation ticket.
- Each removal path writes moderation provenance (`moderation_source_ticket_id`, actor, timestamp) to support audit and replay.

---

## 12. Rollout Plan
### Phase 1 (MVP)
- Report UI for all 3 content surfaces.
- Ticket creation and admin moderation board.
- Remove/warn/ban actions.
- Basic offender history panel.
- Audit logs.

### Phase 2
- Smarter deduplication and auto-priority scoring.
- Appeals workflow.
- Moderator QA sampling and calibration reports.

### Phase 3
- ML-assisted triage recommendations.
- Policy simulation / what-if tooling.

---

## 13. Acceptance Criteria
- Users can report newsfeed posts/messages/profile photos with reason + topics.
- Every report creates or updates a moderation ticket visible on board.
- Admin can reject content and remove it successfully.
- Admin can choose warn or ban during resolution.
- Admin can view previous warnings and bans for the reported user.
- All decisions/actions are captured in auditable logs.

---

## 14. Open Product/Policy Decisions
- Should users be able to report their own content?
- Is `reason_text` required or optional?
- Ban policy matrix by topic/severity/repeat count.
- Whether permanent bans require dual control.
- Retention period for removed content evidence.
