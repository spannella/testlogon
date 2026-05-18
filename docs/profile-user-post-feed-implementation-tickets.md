# Profile User-Posts Feed — Implementation Tickets

This ticket set converts `docs/profile-user-post-feed-plan.md` into delivery-ready engineering work. It is designed to maximize reuse of the existing general newsfeed system while adding profile-scoped aggregation, search, filtering, and pagination.

---

## Epic PUF-A — API & Data Layer Reuse

### PUF-001 — Confirm and document reusable newsfeed contract for author-scoped queries
- **Type:** Backend / API
- **Priority:** P0
- **Size:** S
- **Dependencies:** None
- **Status:** ✅ Implemented (2026-03-24) — see `docs/profile-user-post-feed-contract-decision.md`

**Description**
- Audit existing newsfeed list endpoint and parameter support.
- Decide whether to extend current endpoint or add a thin profile alias that maps to the same service path.
- Document final request/response contract for profile mode.

**Deliverables**
- Contract decision record in docs.
- Updated API contract examples including `author_id`, `q`, filters, and pagination.

**Acceptance Criteria**
- Engineering and frontend agree on one stable contract for profile feed mode.
- Contract preserves existing general feed envelope.
- Backward compatibility is explicitly called out.

---

### PUF-002 — Add author-scoped query support to feed service/repository
- **Type:** Backend
- **Priority:** P0
- **Size:** M
- **Dependencies:** PUF-001
- **Status:** ✅ Implemented (2026-03-25) — service filter module + handler wiring

**Description**
- Extend feed query builder with author predicate (`author_id`).
- Ensure profile mode enforces author scoping first, then applies other predicates.
- Keep response shape consistent with general newsfeed.

**Deliverables**
- Service/repository changes for author-scoped retrieval.
- Updated API handler/controller wiring.

**Acceptance Criteria**
- Requests with `author_id=<user>` return only posts authored by that user.
- Non-author posts are excluded even when they match search/filter terms.
- Response schema matches existing feed list schema.

---

### PUF-003 — Implement profile feed search and simple filtering
- **Type:** Backend
- **Priority:** P0
- **Size:** M
- **Dependencies:** PUF-002
- **Status:** ✅ Implemented (2026-03-25) — combined predicates + malformed filter validation

**Description**
- Add support for search (`q`) within author scope.
- Add simple filters: `from`, `to`, `has_media` (and optional existing category/tag filter if already supported globally).
- Reuse existing normalization/validation logic for query params.

**Deliverables**
- Query predicate composition for author + search + filters.
- Validation and error responses for malformed filter params.

**Acceptance Criteria**
- Search works only against posts in selected author scope.
- Date/media filters combine correctly with search.
- Invalid filter input returns clear 4xx validation errors.

---

### PUF-004 — Preserve pagination semantics and deterministic ordering
- **Type:** Backend
- **Priority:** P0
- **Size:** M
- **Dependencies:** PUF-002
- **Status:** ✅ Implemented (2026-03-25) — multi-page fill + deterministic sort tiebreakers

**Description**
- Reuse existing feed pagination model (cursor or page-based).
- Ensure stable sort and tiebreakers (e.g., `created_at desc, id desc`) to prevent duplicates/skips.
- Validate consistency across repeated queries under mutation.

**Deliverables**
- Pagination logic updates for author-scoped path.
- Deterministic ordering tests.

**Acceptance Criteria**
- Paginated results do not duplicate or skip records under normal traversal.
- Page/cursor metadata remains compatible with existing frontend utilities.
- Sorting behavior is documented and deterministic.

---

### PUF-005 — Add/verify indexes for author-scoped feed performance
- **Type:** Backend / Data
- **Priority:** P1
- **Size:** S
- **Dependencies:** PUF-002, PUF-003, PUF-004
- **Status:** ✅ Implemented (2026-03-26) — author timeline index path + backfill migration + perf notes

**Description**
- Review query plans for author + sort + search usage.
- Add composite indexes where needed (e.g., `author_id`, `created_at`).
- Validate read-path latency at expected page sizes.

**Deliverables**
- DB migration(s) for index changes if required.
- Query-plan evidence and before/after latency notes.

**Acceptance Criteria**
- Profile feed query meets agreed latency target.
- No major regression to global feed query performance.
- Index changes are safe for rollout.

---

## Epic PUF-B — Frontend Profile Feed Integration

### PUF-101 — Add profile "Posts" surface using shared feed components
- **Type:** Frontend
- **Priority:** P0
- **Size:** M
- **Dependencies:** PUF-001

**Description**
- Add a `Posts` tab/section on the profile page.
- Render existing feed list/card components in profile mode via `authorId` (or equivalent context prop).
- Reuse existing loading, empty, and error states.

**Deliverables**
- Profile route/tab integration.
- Shared feed component usage in profile context.

**Acceptance Criteria**
- Profile page exposes a visible posts feed section.
- Rendering uses shared feed UI components (no parallel card implementation).
- Empty/loading/error states match global feed behavior.

---

### PUF-102 — Wire profile feed data hook and cache key strategy
- **Type:** Frontend
- **Priority:** P0
- **Size:** M
- **Dependencies:** PUF-101, PUF-002
- **Status:** ✅ Implemented (2026-03-26) — shared hook + feed key utility with author/filter isolation

**Description**
- Reuse or extend existing feed query hook for profile mode.
- Build cache keys from `authorId + search/filter + pagination`.
- Keep profile and global caches isolated while sharing fetch logic.

**Deliverables**
- Query hook update for profile mode.
- Cache key utility updates.

**Acceptance Criteria**
- Profile feed caches independently from global feed.
- Query refetches correctly when author/search/filter/pagination changes.
- No stale data bleed from global feed into profile context.

---

### PUF-103 — Add simple search + filter controls on profile feed
- **Type:** Frontend
- **Priority:** P0
- **Size:** M
- **Dependencies:** PUF-101, PUF-003
- **Status:** ✅ Implemented (2026-03-26) — toolbar + URL query param wiring for q/from/to/has_media

**Description**
- Reuse feed toolbar controls for search and simple filters.
- Support text search, date range, and media-only toggle.
- Keep UX intentionally minimal and aligned with general newsfeed.

**Deliverables**
- Profile feed toolbar integration.
- Control state wiring to query params.

**Acceptance Criteria**
- Search/filter controls update feed results correctly.
- Combined filters behave consistently with backend contract.
- Control layout remains responsive and accessible.

---

### PUF-104 — Persist profile feed state in URL parameters
- **Type:** Frontend
- **Priority:** P1
- **Size:** S
- **Dependencies:** PUF-103
- **Status:** ✅ Implemented (2026-03-26) — URL state parser/writer + profile hydration + cursor sync

**Description**
- Serialize search/filter/pagination state into URL query params.
- Restore state on hard refresh, shared link open, and browser back/forward.

**Deliverables**
- URL-state sync utilities.
- Profile feed state hydration logic.

**Acceptance Criteria**
- Deep links reopen profile feed with same search/filter/pagination context.
- Back/forward navigation restores prior feed state without manual reset.
- Malformed query params fail gracefully to defaults.

---

### PUF-105 — Reuse global pagination UX pattern for profile feed
- **Type:** Frontend
- **Priority:** P0
- **Size:** S
- **Dependencies:** PUF-101, PUF-004
- **Status:** ✅ Implemented (2026-04-04) — shared infinite-scroll + inter-page skeleton + boundary dedupe

**Description**
- Apply the same pagination experience used by global feed (infinite scroll or page controls).
- Ensure consistent skeleton/loading inter-page behavior.

**Deliverables**
- Pagination control/infinite loader integration.
- UI polish for page transitions.

**Acceptance Criteria**
- Profile feed pagination behavior matches global feed pattern.
- Loading next page does not visually regress compared to general feed.
- No duplicated items across pagination boundaries.

---

## Epic PUF-C — Security, Permissions, and Correctness

### PUF-201 — Enforce visibility and authorization in profile feed responses
- **Type:** Backend / Security
- **Priority:** P0
- **Size:** M
- **Dependencies:** PUF-002
- **Status:** ✅ Implemented (2026-04-04) — centralized view-policy checks + visibility permutation tests

**Description**
- Ensure profile feed obeys existing post visibility rules.
- Confirm no unauthorized post visibility through results or metadata.
- Reuse centralized policy checks from general feed stack.

**Deliverables**
- Authorization integration in profile query path.
- Tests for public/followers/private permutations.

**Acceptance Criteria**
- Viewer only sees posts allowed by existing policy.
- Hidden/blocked/private posts are excluded where required.
- Metadata/counts do not leak unauthorized record existence.

---

### PUF-202 — Mutation invalidation for global + profile feed caches
- **Type:** Frontend
- **Priority:** P1
- **Size:** S
- **Dependencies:** PUF-102
- **Status:** ✅ Implemented (2026-04-04) — shared invalidation helper + mutation/offline-queue wiring + unit tests

**Description**
- Update invalidation strategy for post create/edit/delete so both global and affected profile feeds refresh.
- Centralize invalidation helper to avoid drift.

**Deliverables**
- Cache invalidation helper updates.
- Mutation hook integration.

**Acceptance Criteria**
- Post mutations update both general feed and relevant profile feed views.
- No stale entries remain after mutation completion.
- Invalidation behavior is covered by tests.

---

## Epic PUF-D — Observability, QA, and Rollout

### PUF-301 — Add profile feed metrics and structured logging
- **Type:** Backend / Observability
- **Priority:** P1
- **Size:** S
- **Dependencies:** PUF-002, PUF-003, PUF-004
- **Status:** ✅ Implemented (2026-04-04) — profile/global feed metrics + structured query logs + dashboard panel guidance

**Description**
- Add metrics for profile feed latency, errors, search/filter usage, and pagination depth.
- Add structured logs with `author_id`, `viewer_id`, and query metadata (sanitized).

**Deliverables**
- Metrics instrumentation.
- Log schema updates and dashboard panel additions (if dashboards exist).

**Acceptance Criteria**
- Profile feed requests are measurable independently from general feed.
- Error paths emit actionable telemetry.
- Search/filter usage is observable for future UX tuning.

---

### PUF-302 — Test suite for profile feed behavior and regressions
- **Type:** QA (Backend + Frontend)
- **Priority:** P0
- **Size:** M
- **Dependencies:** PUF-105, PUF-201, PUF-202
- **Status:** ✅ Implemented (2026-04-04) — backend visibility/order regression tests + profile posts UI integration coverage

**Description**
- Add unit tests for param serialization, cache keys, and pagination helpers.
- Add integration/API tests for author scoping, search/filter combinations, and pagination determinism.
- Add frontend integration/E2E coverage for profile posts tab interaction.

**Deliverables**
- Unit tests.
- Integration/API tests.
- UI integration/E2E tests for core user path.

**Acceptance Criteria**
- Tests prove profile feed only contains selected author's posts.
- Search/filter/pagination combinations are validated end-to-end.
- Access-control scenarios are covered for visibility edge cases.

---

### PUF-303 — Feature-flagged rollout and post-release verification
- **Type:** Release / Ops
- **Priority:** P1
- **Size:** S
- **Dependencies:** PUF-301, PUF-302
- **Status:** ✅ Implemented (2026-04-04) — profile posts flag + kill switch + rollout checklist + post-release validation report

**Description**
- Introduce feature flag gating profile posts feed if rollout controls are available.
- Stage rollout from internal/staging to production.
- Verify telemetry and user-facing behavior during ramp.

**Deliverables**
- Rollout checklist.
- Flag configuration + enablement plan.
- Post-release validation report.

**Acceptance Criteria**
- Feature can be enabled/disabled without redeploy (when flag infra exists).
- Rollout includes clear halt/rollback criteria.
- Production health is confirmed with telemetry after launch.

---

## Suggested Delivery Sequence
1. **Foundation:** PUF-001 → PUF-002 → PUF-003 → PUF-004
2. **Frontend Core:** PUF-101 → PUF-102 → PUF-103 → PUF-105
3. **Hardening:** PUF-201 → PUF-202 → PUF-301 → PUF-302
4. **Release:** PUF-303

## Definition of Done (Overall)
- Profile posts feed is available on profile page and returns only selected user's posts.
- Search, filtering, and pagination are functional and consistent with general feed behavior.
- Shared feed building blocks are reused across backend and frontend.
- Security/visibility, telemetry, and automated tests meet release quality standards.
