# Newsfeed Scheduling Implementation Tickets

This ticket set translates `newsfeed-scheduling-plan.md` into an executable backlog.

## Epic
**EPIC-NF-SCHED-001 — Scheduled Newsfeed Publishing**

**Goal**
Allow creators to schedule newsfeed posts with timezone-aware release settings, manage scheduled posts (edit/cancel), and publish reliably via an idempotent backend scheduler.

**Success Metrics**
- Scheduled posts do not appear in feed before release.
- Due scheduled posts publish within SLA (e.g., <= 60s lag).
- Cancelled posts never publish.
- Publish path is idempotent (no duplicate feed refs or duplicate publish events).

---

## Ticket 1 — Data Model & Persistence Fields
**ID:** NF-SCHED-101  
**Type:** Backend  
**Priority:** P0  
**Estimate:** 2–3 days

### Scope
Add lifecycle and scheduling fields to post records:
- `status`: `scheduled | published | cancelled`
- `publish_at` (UTC epoch seconds)
- `schedule_timezone` (IANA)
- `scheduled_at_local` (string)
- `published_at` (UTC ISO)

### Tasks
- Update post write/read mapping to include new fields.
- Preserve backward compatibility for existing posts with no `status`.
- Add migration/defaulting behavior in serializers where needed.

### Acceptance Criteria
- New posts can persist these fields without breaking existing CRUD.
- Existing posts without the fields still render and behave correctly.
- Status defaults are deterministic (`published` for immediate create path).

### Dependencies
- None (foundational).

---

## Ticket 2 — Create Post API: Immediate vs Scheduled
**ID:** NF-SCHED-102  
**Type:** Backend API  
**Priority:** P0  
**Estimate:** 2–3 days

### Scope
Extend `POST /posts` with optional schedule inputs:
- `publish_at?: number`
- `schedule_timezone?: string`
- `scheduled_at_local?: string`

### Tasks
- Validate schedule payload when present.
- If no schedule: preserve current immediate publish behavior.
- If scheduled: persist post as `status=scheduled`; do not create feed ref yet.

### Acceptance Criteria
- Immediate posts are visible right away and unchanged in behavior.
- Scheduled posts are created successfully and hidden from normal feed queries.
- Invalid scheduling payload returns clear 4xx errors.

### Dependencies
- NF-SCHED-101.

---

## Ticket 3 — Scheduled Posts Query API
**ID:** NF-SCHED-103  
**Type:** Backend API  
**Priority:** P0  
**Estimate:** 2 days

### Scope
Add owner-only scheduled listing endpoint:
- `GET /posts/scheduled?cursor=...`

### Tasks
- Return only `status=scheduled` posts for authenticated owner.
- Support pagination/cursor.
- Include needed schedule metadata in response.

### Acceptance Criteria
- Endpoint returns only caller’s scheduled posts.
- Pagination is stable and deterministic.
- Non-owner access is denied.

### Dependencies
- NF-SCHED-101.

---

## Ticket 4 — Edit Scheduled Post API
**ID:** NF-SCHED-104  
**Type:** Backend API  
**Priority:** P0  
**Estimate:** 2–3 days

### Scope
Extend `PATCH /posts/{post_id}` for scheduled posts:
- update body/media content
- update schedule fields (`publish_at`, `schedule_timezone`, `scheduled_at_local`)

### Tasks
- Authorize owner-only edits.
- Reject edits when `status != scheduled` for schedule-changing operations.
- Add conditional/version guard for conflict safety (if available).

### Acceptance Criteria
- Scheduled post content and release time are editable before publish.
- Attempts to reschedule published/cancelled posts return expected error.
- Response includes updated schedule metadata.

### Dependencies
- NF-SCHED-101, NF-SCHED-102.

---

## Ticket 5 — Cancel Scheduled Post API
**ID:** NF-SCHED-105  
**Type:** Backend API  
**Priority:** P0  
**Estimate:** 1–2 days

### Scope
Add cancel endpoint:
- `POST /posts/{post_id}/cancel`

### Tasks
- Implement owner authorization.
- Transition `status: scheduled -> cancelled` via conditional update.
- Ensure cancelled posts cannot be published later by scheduler.

### Acceptance Criteria
- Cancelled scheduled posts no longer appear in scheduled list.
- Cancel action is idempotent/safe under retry.
- Cancelled posts are never released to feed.

### Dependencies
- NF-SCHED-101.

---

## Ticket 6 — Schedule Index & Due Query Path
**ID:** NF-SCHED-106  
**Type:** Backend Infra  
**Priority:** P0  
**Estimate:** 2 days

### Scope
Add schedule query index for efficient due-item scans.

### Tasks
- Add GSI design from plan (e.g. `GSI_SCHEDULE_PK/SK`).
- Ensure scheduled posts are written with required index keys.
- Implement query helper for `publish_at <= now` windows.

### Acceptance Criteria
- Query returns due scheduled posts without full table scan.
- Index keys remain correct after schedule edits.

### Dependencies
- NF-SCHED-101.

---

## Ticket 7 — Scheduler Worker Publish Loop
**ID:** NF-SCHED-107  
**Type:** Backend Worker  
**Priority:** P0  
**Estimate:** 3–4 days

### Scope
Build periodic worker that publishes due scheduled posts.

### Tasks
- Poll due posts from schedule index.
- Conditionally transition `scheduled -> published`.
- Set `published_at`, create feed ref, emit metrics/events.
- Handle retries and partial failures safely.

### Acceptance Criteria
- Due posts publish automatically within SLA.
- Duplicate worker runs do not double-publish.
- Observability includes success/failure/lag metrics.

### Dependencies
- NF-SCHED-106, NF-SCHED-102.

---

## Ticket 8 — Metering/Quota on Actual Publish
**ID:** NF-SCHED-108  
**Type:** Backend Billing/Metering  
**Priority:** P1  
**Estimate:** 1–2 days

### Scope
Align billing/metering so scheduled create does not meter until actual publish.

### Tasks
- Move/guard metering to publish transition path.
- Confirm cancelled posts do not produce publish metering events.

### Acceptance Criteria
- Immediate post: metered once.
- Scheduled + published: metered once at publish.
- Scheduled + cancelled: not metered for publish.

### Dependencies
- NF-SCHED-107.

---

## Ticket 9 — Frontend Types & Endpoint Clients
**ID:** NF-SCHED-201  
**Type:** Frontend API Layer  
**Priority:** P0  
**Estimate:** 1–2 days

### Scope
Update FE request/response types and endpoint wrappers.

### Tasks
- Extend `CreatePostReq`, `EditPostReq`, `FeedPost` with schedule metadata.
- Add API wrappers for:
  - `getScheduledPosts`
  - `cancelScheduledPost`

### Acceptance Criteria
- FE compiles with updated types.
- New endpoints are available to UI layers.

### Dependencies
- NF-SCHED-102, NF-SCHED-103, NF-SCHED-105.

---

## Ticket 10 — Create Post Schedule Controls
**ID:** NF-SCHED-202  
**Type:** Frontend UI  
**Priority:** P0  
**Estimate:** 2–3 days

### Scope
Add schedule UX to Create Post composer.

### Tasks
- Add datetime-local input + timezone selector.
- Add “remove schedule” action.
- Display schedule preview in selected timezone.
- Reuse/extract shared timezone conversion utility from messaging flow.

### Acceptance Criteria
- User can create immediate or scheduled post from same form.
- Schedule payload is accurate UTC + timezone metadata.
- DST/timezone transitions handled consistently with messaging.

### Dependencies
- NF-SCHED-201.

---

## Ticket 11 — Scheduled Posts Management Panel
**ID:** NF-SCHED-203  
**Type:** Frontend UI  
**Priority:** P0  
**Estimate:** 2–3 days

### Scope
Build scheduled posts list UI with actions.

### Tasks
- Add “Scheduled Posts” panel/sheet in feed area.
- Render post preview + scheduled release time.
- Add actions for Edit and Cancel.
- Wire query invalidation after mutations.

### Acceptance Criteria
- Users can view all upcoming scheduled posts.
- Cancel removes item from list.
- Edit opens scheduled edit flow and persists changes.

### Dependencies
- NF-SCHED-201, NF-SCHED-103, NF-SCHED-104, NF-SCHED-105.

---

## Ticket 12 — Edit Dialog Support for Scheduled Metadata
**ID:** NF-SCHED-204  
**Type:** Frontend UI  
**Priority:** P0  
**Estimate:** 2 days

### Scope
Extend post edit dialog to update schedule for scheduled posts.

### Tasks
- Add schedule fields (datetime/timezone) in edit dialog when applicable.
- Validate schedule changes client-side.
- Keep published-post edit behavior unchanged.

### Acceptance Criteria
- Scheduled posts can be rescheduled from edit dialog.
- Published posts continue using existing edit UX without regressions.

### Dependencies
- NF-SCHED-201, NF-SCHED-104.

---

## Ticket 13 — Backend Test Coverage
**ID:** NF-SCHED-301  
**Type:** QA/Tests  
**Priority:** P0  
**Estimate:** 2–3 days

### Scope
Add/extend backend tests for schedule lifecycle.

### Required Scenarios
- Immediate create unchanged.
- Scheduled create hidden from feed.
- Scheduled list returns owner items.
- Edit scheduled content/time.
- Cancel scheduled post.
- Worker idempotent publish.

### Acceptance Criteria
- All new tests pass in CI.
- No regressions in existing feed/post tests.

### Dependencies
- NF-SCHED-102 through NF-SCHED-107.

---

## Ticket 14 — Frontend Unit Tests
**ID:** NF-SCHED-302  
**Type:** QA/Tests  
**Priority:** P0  
**Estimate:** 2 days

### Scope
Add FE tests for scheduling UI and client behavior.

### Required Scenarios
- Create composer schedule input payload.
- Timezone conversion and DST edge cases.
- Scheduled list loading/empty/populated states.
- Edit/cancel mutation cache invalidation.

### Acceptance Criteria
- All new FE tests pass.
- Existing feed/message tests remain green.

### Dependencies
- NF-SCHED-202, NF-SCHED-203, NF-SCHED-204.

---

## Ticket 15 — End-to-End Workflow Test
**ID:** NF-SCHED-303  
**Type:** E2E  
**Priority:** P1  
**Estimate:** 1–2 days

### Scope
Automate full scheduling journey.

### Required Scenario
- Schedule near-future post.
- Verify hidden before due time.
- Verify visible after due time/scheduler run.

### Acceptance Criteria
- E2E is stable and non-flaky under expected scheduler latency.

### Dependencies
- NF-SCHED-107, NF-SCHED-202, NF-SCHED-203.

---

## Ticket 16 — Feature Flag + Rollout Controls
**ID:** NF-SCHED-401  
**Type:** Release/Operations  
**Priority:** P1  
**Estimate:** 1–2 days

### Scope
Gate new functionality and support staged rollout.

### Tasks
- Add backend and frontend feature flags.
- Add rollout config docs/checklist.
- Add dashboards/alerts for publish lag and failure rates.

### Acceptance Criteria
- Can enable scheduling for internal cohort first.
- Can disable quickly if issue detected.

### Dependencies
- NF-SCHED-102, NF-SCHED-107, NF-SCHED-202.

---

## Recommended Implementation Order
1. NF-SCHED-101
2. NF-SCHED-102, NF-SCHED-103, NF-SCHED-105
3. NF-SCHED-106, NF-SCHED-107, NF-SCHED-108
4. NF-SCHED-201, NF-SCHED-202
5. NF-SCHED-203, NF-SCHED-204
6. NF-SCHED-301, NF-SCHED-302, NF-SCHED-303
7. NF-SCHED-401

## Suggested Milestones
- **Milestone A (Backend Ready):** Tickets 101–108
- **Milestone B (Frontend Ready):** Tickets 201–204
- **Milestone C (Quality + Rollout):** Tickets 301–303, 401
