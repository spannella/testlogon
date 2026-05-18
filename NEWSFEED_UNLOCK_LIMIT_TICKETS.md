# Newsfeed Unlock-Limit — Implementation Tickets

This ticket set turns `NEWSFEED_UNLOCK_LIMIT_PLAN.md` into execution-ready engineering work for capped unlocks on locked posts.

---

## Epic NF-UL-1: Data Contract & Model Foundations

### NF-UL-101 — Add unlock-cap fields to post write/read models
**Type:** Feature  
**Priority:** P0  
**Dependencies:** None
**Status:** ✅ Implemented (2026-03-24)

**Scope**
- Extend post create/edit request models with `unlock_limit` (optional, integer >= 1).
- Extend post response serialization with:
  - `unlock_limit` (nullable)
  - `unlock_count` (int, default 0)
  - `unlock_limit_reached` (derived bool)
- Ensure fields are included in single-post and feed-list payloads.

**Deliverables**
- Updated Pydantic models and `_post_to_dict` mapping logic.
- Backward-compatible API behavior for existing clients.

**Acceptance Criteria**
- Creating a locked post with no `unlock_limit` behaves as unlimited unlocks.
- Creating a locked post with `unlock_limit=N` returns `unlock_limit=N` and `unlock_count=0`.
- Existing consumers that ignore new fields continue working.

---

### NF-UL-102 — Validation rules for unlock limits on create/edit
**Type:** Feature  
**Priority:** P0  
**Dependencies:** NF-UL-101
**Status:** ✅ Implemented (2026-03-24)

**Scope**
- Reject `unlock_limit` if post is not locked.
- Enforce integer bounds (`>=1`, and optional max guard if product wants upper bound).
- On edit, reject lowering `unlock_limit` below existing `unlock_count`.
- Standardize error payload shape and error codes for validation failures.

**Deliverables**
- Validation logic in create/update routes.
- Error code constants and API docs updates.

**Acceptance Criteria**
- Non-locked posts cannot save `unlock_limit`.
- Locked post edits cannot set `unlock_limit < unlock_count`.
- Error responses are deterministic and documented.

---

## Epic NF-UL-2: Unlock Flow Enforcement & Payments Safety

### NF-UL-201 — Concurrency-safe unlock-cap enforcement in unlock endpoint
**Type:** Feature  
**Priority:** P0  
**Dependencies:** NF-UL-101
**Status:** ✅ Implemented (2026-03-24)

**Scope**
- In `/newsfeed/posts/unlock`, enforce cap with DynamoDB condition:
  - allow if no cap OR `unlock_count < unlock_limit`
- Increment `unlock_count` exactly once per new unlocking user.
- Return explicit code (e.g., `unlock_limit_reached`) when cap is exhausted.

**Deliverables**
- Conditional update / write path for capped unlocks.
- API error mapping for exhausted-cap outcome.

**Acceptance Criteria**
- At most `N` distinct users can unlock a post capped at `N`.
- `N+1` unlock attempt returns expected error code and does not charge user.

---

### NF-UL-202 — Idempotency and retry safety for unlock attempts
**Type:** Feature  
**Priority:** P0  
**Dependencies:** NF-UL-201

**Scope**
- Preserve fast-path for already-unlocked users (`already_unlocked`/`not_required`).
- Prevent double increment/double charge for duplicate client retries.
- Add/update idempotency key strategy for payment + unlock operation.

**Deliverables**
- Idempotency key decision and implementation notes in code comments/docs.
- Deterministic retry behavior tests.

**Acceptance Criteria**
- Repeated unlock requests from same user for same post are side-effect free after first success.
- `unlock_count` is stable under repeated network retries.

---

### NF-UL-203 — Payment failure compensation strategy implementation
**Type:** Feature  
**Priority:** P0  
**Dependencies:** NF-UL-201

**Scope**
- Implement one chosen strategy from plan:
  - charge-first then reserve+write, OR
  - reserve first with guarded rollback on payment failure
- Ensure no leaked slot when payment fails.
- Add audit logs/metrics for compensation events.

**Deliverables**
- Production implementation with invariants documented.
- Failure-path tests for payment gateway failures/timeouts.

**Acceptance Criteria**
- Failed payment never leaves user unlocked.
- Failed payment does not permanently consume unlock capacity.

---

### NF-UL-204 — Optional transactional write hardening
**Type:** Tech Debt / Reliability  
**Priority:** P1  
**Dependencies:** NF-UL-201

**Scope**
- Evaluate/implement DynamoDB `TransactWriteItems` to atomically:
  - create unlock record
  - increment post `unlock_count`
- Keep fallback logic if transaction is not feasible for all paths.

**Deliverables**
- Transactional write helper or ADR documenting decision.

**Acceptance Criteria**
- Unlock record and `unlock_count` cannot diverge under concurrent success paths.

---

## Epic NF-UL-3: Expiry, State Precedence, and Integrity

### NF-UL-301 — Lock-expiry and cap-exhaustion precedence
**Type:** Feature  
**Priority:** P0  
**Dependencies:** NF-UL-201

**Scope**
- Enforce deterministic precedence in unlock endpoint:
  1) expired lock => `post_lock_expired`
  2) not expired but cap exhausted => `unlock_limit_reached`
- Ensure feed/detail endpoint state reflects same precedence.

**Deliverables**
- Shared helper used by unlock and read surfaces.

**Acceptance Criteria**
- Expired posts are not unlockable even with remaining slots.
- Non-expired capped posts surface sold-out state once exhausted.

---

### NF-UL-302 — Reconciliation and integrity check job (optional)
**Type:** Ops / Reliability  
**Priority:** P2  
**Dependencies:** NF-UL-201

**Scope**
- Implement periodic checker comparing `unlock_count` with unlock-record cardinality.
- Emit anomaly metric + log for mismatches.
- Optional auto-repair mode behind admin-only flag.

**Deliverables**
- Script/worker and runbook entry.

**Acceptance Criteria**
- Drift is detectable and visible via metrics/logging.

---

## Epic NF-UL-4: Frontend UX & Product Surface

### NF-UL-401 — Composer/edit UI for unlock-limit configuration
**Type:** Feature  
**Priority:** P0  
**Dependencies:** NF-UL-101, NF-UL-102

**Scope**
- Add toggle/checkbox and numeric input for “Limit unlocks to N users”.
- Validate input client-side (positive integer, required when enabled).
- Support edit experience with existing values loaded.

**Deliverables**
- Updated form components and API payload wiring.

**Acceptance Criteria**
- Users can create/edit locked posts with optional unlock cap.
- Invalid values are blocked pre-submit with clear messaging.

---

### NF-UL-402 — Feed/detail sold-out and remaining-slot states
**Type:** Feature  
**Priority:** P0  
**Dependencies:** NF-UL-101, NF-UL-201

**Scope**
- Display `remaining = unlock_limit - unlock_count` for locked posts where applicable.
- Show “Unlock limit reached” state when sold out.
- Handle unlocked-by-me, not-locked, and unlimited variants cleanly.

**Deliverables**
- Post card and post detail UI updates.

**Acceptance Criteria**
- Remaining slots are accurate and never negative.
- Sold-out posts show consistent label in all relevant views.

---

### NF-UL-403 — Unlock CTA behavior and backend error mapping
**Type:** Feature  
**Priority:** P0  
**Dependencies:** NF-UL-402, NF-UL-301

**Scope**
- Disable/hide unlock CTA when post is sold out or expired.
- Map backend errors to user-friendly messages:
  - `unlock_limit_reached`
  - `post_lock_expired`
- Keep retry affordance for transient failures only.

**Deliverables**
- Error-state handling in unlock flow UI.

**Acceptance Criteria**
- Users see accurate message for sold-out vs expired cases.
- No misleading “try again” prompt for deterministic business-rule errors.

---

## Epic NF-UL-5: Observability, Notifications, and Controls

### NF-UL-501 — Metrics/events for unlock lifecycle
**Type:** Feature  
**Priority:** P1  
**Dependencies:** NF-UL-201

**Scope**
- Emit events: `unlock_attempt`, `unlock_success`, `unlock_limit_reached`, `unlock_payment_failed`.
- Include dimensions (post_id, author_id, unlocker_id masked as needed, reason codes).

**Deliverables**
- Structured logs + counters and dashboard annotations.

**Acceptance Criteria**
- Events emitted for all major unlock outcomes.
- Dashboard can segment cap failures vs payment failures.

---

### NF-UL-502 — Optional “cap reached” author notification
**Type:** Feature  
**Priority:** P2  
**Dependencies:** NF-UL-201

**Scope**
- Send one-time notification to author when capped post first reaches limit.
- De-duplicate notification for repeated blocked attempts.

**Deliverables**
- Notification event wiring and dedupe guard.

**Acceptance Criteria**
- Author receives at most one cap-reached notification per post.

---

### NF-UL-503 — Abuse/rate guard for rapid repeated unlock attempts
**Type:** Security / Reliability  
**Priority:** P1  
**Dependencies:** NF-UL-202

**Scope**
- Add dedupe/rate-limiting layer for repeated `(user_id, post_id)` attempts.
- Prevent tight-loop unlock calls from noisy clients.

**Deliverables**
- Server-side guard and telemetry for throttled attempts.

**Acceptance Criteria**
- Excessive repeated attempts are throttled without degrading normal unlocks.

---

## Epic NF-UL-6: Test Coverage & Rollout

### NF-UL-601 — Backend unit + integration tests for capped unlocks
**Type:** Test  
**Priority:** P0  
**Dependencies:** NF-UL-201, NF-UL-301

**Scope**
- Add tests for:
  - create/edit validation
  - unlock success under cap
  - cap exhausted rejection
  - already unlocked idempotency
  - expiry precedence
  - payment failure compensation

**Deliverables**
- Test suite updates under backend test modules.

**Acceptance Criteria**
- All core business paths and failure paths are covered.

---

### NF-UL-602 — Concurrency test harness for `N+K` attempts
**Type:** Test / Reliability  
**Priority:** P0  
**Dependencies:** NF-UL-201

**Scope**
- Create stress test that executes parallel unlock attempts against capped post.
- Assert exactly `N` successful unlocks for cap `N`.

**Deliverables**
- Repeatable test harness runnable in CI or gated nightly job.

**Acceptance Criteria**
- Results are deterministic and no over-cap unlock success occurs.

---

### NF-UL-603 — Frontend tests + E2E happy/pathological flows
**Type:** Test  
**Priority:** P1  
**Dependencies:** NF-UL-401, NF-UL-402, NF-UL-403

**Scope**
- Component/integration tests for composer and sold-out states.
- E2E scenario: first N users unlock successfully, next user blocked.

**Deliverables**
- Frontend unit/integration + E2E specs.

**Acceptance Criteria**
- UI behavior matches backend state across normal and edge flows.

---

### NF-UL-604 — Feature flag + phased rollout plan execution
**Type:** Release  
**Priority:** P1  
**Dependencies:** NF-UL-601

**Scope**
- Add `NEWSFEED_UNLOCK_LIMIT_ENABLED` flag handling.
- Define dark-launch, internal-only, and progressive rollout steps.
- Add rollback playbook and SLO watchpoints.

**Deliverables**
- Runtime flag plumbing and ops checklist.

**Acceptance Criteria**
- Feature can be enabled/disabled safely without deployment rollback.

---

## Suggested sequencing (critical path)
1. NF-UL-101 → NF-UL-102  
2. NF-UL-201 → NF-UL-202 → NF-UL-203  
3. NF-UL-301  
4. NF-UL-401 → NF-UL-402 → NF-UL-403  
5. NF-UL-601 + NF-UL-602 + NF-UL-603  
6. NF-UL-501 + NF-UL-604  
7. NF-UL-204 / NF-UL-302 / NF-UL-502 / NF-UL-503 as hardening.

## Release gate checklist
- [ ] Unlock cap cannot be bypassed in concurrent attempts.
- [ ] No double-charge or leaked slot on retries/failures.
- [ ] Sold-out and expired states are distinguishable in UI.
- [ ] Metrics and alarms are live before broad rollout.
- [ ] Feature flag rollback validated in staging.
