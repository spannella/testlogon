# Newsfeed Scheduled Posting Plan

## Objective
Enable users to create a newsfeed post and choose when it should be published, with timezone-aware scheduling and a management UI to update or remove scheduled posts before release.

## Current State Summary
- Newsfeed posts publish immediately via `POST /posts`; there is no schedule field in request or persistence path.
- Existing post APIs support edit/delete for already-created posts.
- Frontend feed create/edit flows do not expose schedule controls today.
- Messaging already implements timezone-aware scheduling UX and scheduled-item management patterns that can be reused.

## Scope
### In scope
- Schedule-on-create for newsfeed posts.
- Edit scheduled post content.
- Edit scheduled release date/time/timezone.
- Remove/cancel scheduled posts.
- Backend scheduler path to publish due posts.
- Frontend scheduled-post management UI.

### Out of scope (initial phase)
- Recurring/smart schedules.
- Bulk scheduling operations.
- Cross-account delegated scheduling.

## Backend Design

### 1) Data model and lifecycle
Add explicit post lifecycle fields:
- `status`: `scheduled | published | cancelled`
- `publish_at`: UTC epoch seconds (authoritative release time)
- `schedule_timezone`: IANA timezone chosen by user
- `scheduled_at_local`: optional local datetime string for audit/display
- `published_at`: UTC ISO when actually published
- `created_at`: time record was first created

State transitions:
- create immediate: `published`
- create scheduled: `scheduled`
- scheduled + cancel: `cancelled`
- scheduled + due: `published`

### 2) API changes
1. **Create post** (`POST /posts`)
   - Extend request with optional:
     - `publish_at?: number`
     - `schedule_timezone?: string`
     - `scheduled_at_local?: string`
   - Behavior:
     - no `publish_at`: publish immediately (existing behavior)
     - future `publish_at`: persist scheduled post only, do not create feed ref yet

2. **List scheduled posts (owner)**
   - `GET /posts/scheduled?cursor=...`
   - Returns current user’s `status=scheduled` posts

3. **Edit scheduled post**
   - Extend `PATCH /posts/{post_id}` to allow updating:
     - content fields
     - image/file metadata (if supported by current edit policy)
     - `publish_at`, `schedule_timezone`, `scheduled_at_local`
   - Reject edits after publish/cancel.

4. **Cancel scheduled post**
   - Add `POST /posts/{post_id}/cancel` (preferred explicit action)
   - Marks post as `cancelled`.

5. **Internal publish operation**
   - Worker-invoked transition for due posts:
     - conditional update (`status == scheduled`)
     - set `status=published`, `published_at=now`
     - create feed reference item

### 3) Scheduling execution
Recommended approach: periodic worker polling DynamoDB index for due scheduled posts.

- Add a schedule-oriented query index (example):
  - `GSI_SCHEDULE_PK = "SCHEDULED"`
  - `GSI_SCHEDULE_SK = "{publish_at}#POST#{post_id}"`
- Scheduled post refs under owner partition should use a deterministic sortable key:
  - `sk = "SCHEDULEDPOST#{publish_at_zero_padded_12_digits}#{post_id}"`
  - Example: `SCHEDULEDPOST#000000012345#post_abc`

Worker loop:
1. query due window (`publish_at <= now`)
2. publish with conditional write for idempotency
3. create feed ref and emit metrics
4. retry transient failures safely

### 4) Validation and security
- `publish_at` must be sufficiently in the future (e.g., >= now + 5s/30s).
- `schedule_timezone` must be valid IANA timezone.
- Authorization: only post owner can list/edit/cancel.
- Reject schedule updates for non-scheduled states.
- Ensure scheduled posts are excluded from normal feed reads until published.

### 5) Metering/quota behavior
- Apply publish metering when post actually publishes (not when scheduled).
- Keeps behavior aligned with cancel semantics (cancelled scheduled posts should not consume publish event billing).

## Frontend Design

### 1) Create post UI
Add schedule controls to composer:
- datetime-local picker
- timezone selector (default browser timezone)
- summary preview (`Publishes: ... TZ`)
- remove schedule action

Implementation note:
- Reuse messaging timezone parse approach by extracting shared utility to avoid divergence.

### 2) Scheduled posts management UI
Add “Scheduled Posts” panel/sheet in feed area:
- list upcoming scheduled posts with content preview + publish time
- actions:
  - Edit scheduled post
  - Cancel scheduled post

### 3) Edit dialog updates
For scheduled posts, allow:
- content edits
- release datetime/timezone edits
- save action with clear status messaging

For published posts, retain current edit behavior.

## API/Type updates (frontend)
- Extend `CreatePostReq` and `EditPostReq` with schedule fields.
- Add scheduled post DTO shape fields in `FeedPost` (status/publish metadata).
- Add endpoint wrappers:
  - `getScheduledPosts`
  - `cancelScheduledPost`

## Testing Plan

### Backend tests
- Create immediate post: still visible immediately.
- Create scheduled post: not visible in feed before due time.
- List scheduled posts: owner sees item.
- Edit scheduled content/time: persists and returns updated values.
- Cancel scheduled post: removed from scheduled list and never published.
- Worker publishes due posts exactly once (idempotent transition).

### Frontend tests
- Create Post schedule controls set expected payload.
- Timezone conversion and DST edge cases.
- Scheduled Posts list rendering states (loading/empty/populated).
- Cancel and edit actions invalidate react-query caches.

### E2E
- Schedule post for near-future.
- Verify absent from feed until publish time.
- Verify appears after scheduler run/publish window.

## Rollout Strategy
1. Backend fields/endpoints behind feature flag.
2. Deploy scheduler in dry-run/metrics mode.
3. Enable internal users for scheduled create.
4. Enable scheduled management UI.
5. Gradually roll out to all users and monitor publish lag/error rates.

## Risks and Mitigations
- **Risk:** duplicate publish due to retries.
  - **Mitigation:** conditional updates + idempotent worker logic.
- **Risk:** timezone confusion.
  - **Mitigation:** store canonical UTC `publish_at` and explicit timezone metadata; preview in UI.
- **Risk:** feed ordering regressions.
  - **Mitigation:** order by `published_at` for released items.

## Suggested PR Breakdown
1. Backend model + API contract changes.
2. Scheduler worker + index + idempotent publish path.
3. Frontend create/edit scheduling controls.
4. Scheduled posts management panel.
5. Tests + rollout flag plumbing.
