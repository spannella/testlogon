# Profile User-Posts Feed Plan

## Goal
Build a profile-level posts feed that aggregates only the selected user's posts, while reusing the existing general newsfeed stack (query patterns, feed UI cards, sorting/filter controls, pagination model, and caching strategy).

## Success Criteria
- Profile page shows a dedicated "Posts" timeline for the profile owner.
- Timeline includes only posts authored by that user.
- Users can search within that profile feed.
- Users can filter by simple dimensions (date range, media-only, and optional tag/category if already supported globally).
- Feed supports pagination with consistent UX and API semantics compared to the general newsfeed.
- Shared feed components are reused instead of introducing parallel implementations.

## Scope
### In scope
- Backend query path for "posts by author" with search/filter/pagination.
- API contract extension (or reuse of existing endpoint with author filter).
- Frontend profile page integration.
- Reuse of existing feed list components, loading states, and empty states.
- Basic analytics and observability parity with general newsfeed.

### Out of scope (initial iteration)
- Cross-author/global search changes.
- New ranking models.
- Complex filter builder UI.
- Bulk moderation workflows.

## Proposed Architecture

## 1) Data/API Layer
Prefer extending the current newsfeed listing endpoint with an `author_id` filter and existing pagination envelope to maximize reuse.

### Request model
- `author_id` (required for profile mode)
- `q` (search query)
- `from` / `to` (optional date filters)
- `has_media` (boolean)
- `page` and `page_size` (or cursor equivalent if the global feed already uses cursor pagination)
- `sort` (reuse existing values, default same as newsfeed)

### Response model
Reuse the same response shape as global feed:
- `items: Post[]`
- pagination metadata (`next_cursor` or `page`, `total`, etc.)
- any existing facets/counts if already provided

### Backend implementation notes
- Reuse feed repository/query-builder path and add author predicate.
- Apply search predicate only within author-scoped rows.
- Ensure stable sort + pagination key to avoid duplicates/skips.
- Add index support for common query pattern: `(author_id, created_at DESC)` and search companion index as needed.

## 2) Frontend/UI Layer

### Profile page integration
- Add a `Posts` tab/section on profile page.
- Mount existing feed list component with a `mode="profile"` or `authorId` prop.
- Reuse existing post card/actions permissions logic.

### Search + filters UX
- Reuse existing feed toolbar/search input where possible.
- Keep filters intentionally simple:
  - Search text
  - Date range
  - Media-only toggle
- Persist controls in URL query params for shareable links and back/forward navigation.

### Pagination UX
- Reuse current pattern used by general feed:
  - Infinite scroll if global feed is infinite.
  - Page buttons if global feed is paged.
- Match skeleton/loading placeholders and empty-state visuals.

## 3) State Management + Caching
- Reuse existing query hooks and key strategy.
- Derive profile feed cache key from `authorId + search/filter + pagination`.
- Keep global feed and profile feed caches isolated to avoid stale bleed-over.
- Support optimistic updates for create/edit/delete by invalidating both:
  - global feed keys
  - affected author profile feed keys

## 4) Security + Authorization
- Respect existing visibility model (public/followers/private).
- Profile feed should only return posts viewer is allowed to see.
- Ensure no leakage through counts/metadata in pagination payload.

## 5) Observability
- Add/extend metrics:
  - profile feed load latency
  - query error rate
  - search usage
  - filter usage
  - pagination depth
- Add structured logs with `author_id`, `viewer_id`, and query params (excluding sensitive content).

## Delivery Plan

## Phase 0 — Discovery and Contract Alignment (0.5–1 day)
- Inventory reusable global feed modules (API client, hooks, components, toolbar).
- Confirm whether existing endpoint already supports author filtering.
- Finalize API contract and URL parameter schema.

**Output:** short tech design note + endpoint contract update.

## Phase 1 — Backend Author-Scoped Feed (1–2 days)
- Implement author filter in feed query path.
- Add search/filter constraints within author scope.
- Validate pagination stability and total/count behavior.
- Add/adjust DB indexes if needed.

**Output:** backend endpoint ready for profile use.

## Phase 2 — Frontend Profile Feed Integration (1–2 days)
- Add profile Posts tab/section.
- Wire existing feed list component with `authorId` context.
- Reuse search/filter toolbar with URL-state sync.
- Hook pagination behavior to existing shared feed mechanism.

**Output:** functional profile posts feed with search/filter/pagination.

## Phase 3 — Testing and Hardening (1 day)
- Unit tests:
  - API param mapping
  - query key generation
  - filter serialization/deserialization
- Integration tests:
  - profile feed returns only selected user posts
  - search + filter combination behavior
  - pagination next/prev or infinite load behavior
- Access-control tests for visibility permutations.

**Output:** confidence suite + bug fixes.

## Phase 4 — Rollout and Monitoring (0.5 day)
- Feature flag (if applicable).
- Roll out to internal/staging first.
- Monitor latency, error rate, and usage.
- Iterate on filter defaults based on usage.

**Output:** controlled production release.

## Acceptance Test Checklist
- Profile `Posts` feed shows only authored posts.
- Search term narrows results correctly within that profile.
- Date/media filters combine correctly with search.
- Pagination returns deterministic, non-duplicated ordering.
- Empty state appears when no matching posts exist.
- Unauthorized/hidden posts are excluded per policy.
- Performance at parity with global feed for similar page size.

## Risks and Mitigations
- **Risk:** Query slowdown from author+search combinations.
  - **Mitigation:** Composite indexes and query-plan verification.
- **Risk:** Divergent UX between global and profile feeds.
  - **Mitigation:** Strict component reuse and shared toolbar.
- **Risk:** Cache invalidation misses after post mutation.
  - **Mitigation:** centralize invalidation helper for both feed contexts.

## Reuse Matrix (What to Reuse First)
- Existing feed endpoint/pagination envelope.
- Existing feed query hook and cache policy.
- Existing post list/card renderer.
- Existing search input/filter controls.
- Existing loading, empty, and error states.

## Nice-to-Have Follow-Ups
- Saved profile feed filters.
- Author feed sort presets (Newest, Most Liked).
- Highlight matched search terms in post previews.
