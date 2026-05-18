# Newsfeed Locked-Post Unlock-Limit Implementation Plan

## Goal
Allow locked newsfeed posts to define an **unlock cap** (`N`) so only the first `N` users can unlock via tip/payment. After cap is reached (or lock expires), remaining users can no longer unlock the post and should receive a clear product message.

## Scope and assumptions
- Applies only to **locked posts** (`locked=true`, `unlock_price_cents>0`).
- Unlock cap is optional; when absent, unlocks remain unlimited until post expiration/deletion.
- Existing unlock records (`pk=UNLOCK#<user_id>`, `sk=POST#<post_id>`) remain source of truth for per-user unlock state.
- Existing payment flow (`/newsfeed/posts/unlock`) remains in place; cap enforcement is added around it.

## Phase 1 — Data model and API contract
1. **Post schema additions** in `app/routers/newsfeed.py` request/response models:
   - `unlock_limit: Optional[int]` (min 1).
   - `unlock_count: int` (default 0, server-managed).
   - `unlock_limit_reached: bool` derived in responses.
2. **Create/update validation rules**:
   - Reject `unlock_limit` when post is not locked.
   - Reject `unlock_limit` lower than current `unlock_count` on edits.
3. **Response shape updates**:
   - Include `unlock_limit`, `unlock_count`, `unlock_limit_reached` in post payloads.
   - Preserve backwards compatibility by making new fields optional/defaulted.

## Phase 2 — Concurrency-safe cap enforcement
1. **Atomic unlock slot reservation** in unlock endpoint:
   - Before charging, attempt conditional increment of `unlock_count` using DynamoDB condition:
     - `attribute_not_exists(unlock_limit) OR unlock_count < unlock_limit`.
   - If condition fails, return `409` or `402` with code `unlock_limit_reached`.
2. **Idempotency path**:
   - If caller already unlocked, short-circuit without increment.
   - Ensure retries after successful unlock don’t double-increment.
3. **Compensation strategy** for payment failure after slot reserve:
   - Option A (preferred): Authorize/charge first with payment idempotency key, then conditional increment + unlock write in a best-effort transaction pattern.
   - Option B: Reserve first, then on payment failure decrement with guarded rollback (`unlock_count > 0`).
   - Choose one path and document invariants to avoid drift.
4. **(Optional but recommended) transactional write**:
   - Use `TransactWriteItems` to combine increment + unlock record write where feasible.

## Phase 3 — Expiry behavior and lifecycle
1. Reuse current lock-expiration checks (if present) so users cannot unlock expired content.
2. Define precedence rules:
   - Expired lock => `post_lock_expired` regardless of remaining cap.
   - Non-expired + cap exhausted => `unlock_limit_reached`.
3. Background reconciliation job (optional):
   - Periodically verify `unlock_count` equals number of unlock records for capped posts.

## Phase 4 — UI/UX changes (frontend)
1. Post composer/edit form:
   - Add “Limit unlocks to N users” toggle + numeric input.
2. Post cards/details:
   - Display remaining slots (`N - unlock_count`) when viewer has not unlocked.
   - Show sold-out state (“Unlock limit reached”).
3. Unlock CTA behavior:
   - Disable button when sold out/expired.
   - Surface distinct errors from backend (`unlock_limit_reached`, `post_lock_expired`).
4. Author analytics display:
   - Show `unlock_count / unlock_limit` progress.

## Phase 5 — Notifications, telemetry, and abuse controls
1. Emit events/metrics:
   - `unlock_attempt`, `unlock_success`, `unlock_limit_reached`, `unlock_payment_failed`, with post/user ids.
2. Notification policy:
   - Optional author notification when cap is reached.
3. Abuse/race safeguards:
   - Keep existing rate limits.
   - Add short-lived lock or dedupe key per `(user_id, post_id)` for rapid repeated attempts.

## Phase 6 — Testing strategy
1. **Backend unit tests** (`app/routers/newsfeed.py` / related tests):
   - Post create/edit validation for limit fields.
   - Unlock success path with cap.
   - Cap reached failure.
   - Already-unlocked idempotency behavior.
   - Expired-vs-cap precedence.
2. **Concurrency tests**:
   - Simulate `N+K` parallel unlock attempts for cap `N`; assert exactly `N` successes.
3. **Frontend tests**:
   - Composer validation for unlock-limit inputs.
   - CTA disabled state and error banners.
4. **E2E**:
   - Author creates capped locked post, first N users unlock, next user blocked.

## Phase 7 — Rollout and migration
1. **No destructive migration required** if fields are optional.
2. Add feature flag (e.g., `NEWSFEED_UNLOCK_LIMIT_ENABLED`) to stage rollout.
3. Rollout sequence:
   - Backend read/write support (dark launch).
   - Frontend hidden behind flag.
   - Enable for internal users, then percentage rollout.
4. Monitor dashboards for payment failures, unlock conflicts, and user-facing errors.

## Suggested ticket breakdown
- T1: Add schema fields + validation + response serialization.
- T2: Implement cap enforcement in unlock flow with concurrency safety.
- T3: Add UI composer/display updates.
- T4: Add unit/concurrency/e2e coverage.
- T5: Add metrics + rollout flag + docs/runbook.

## Acceptance criteria
- Locked posts can optionally specify `unlock_limit`.
- At most `N` distinct users can unlock a capped post.
- Unlock attempts beyond cap are rejected deterministically with explicit error code.
- No double-charge/double-increment under retries or races.
- UI reflects remaining slots and sold-out state accurately.
