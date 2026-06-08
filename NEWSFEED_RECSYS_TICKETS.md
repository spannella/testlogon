# Newsfeed Recommendations ("For You") — Implementation Tickets

This ticket set turns the newsfeed from a reverse-chronological own+following feed (`GET /feed`, `app/routers/newsfeed.py:5151`) into a ranked "For You" experience, reusing the DynamoDB-native recommendation patterns already proven for videos (`app/services/recommendations.py`). The core architectural gap is candidate generation: the feed index (`GSI1PK=FEED#{user_id}`) only surfaces posts the viewer authored or that were fanned out from followings — there is no source of out-of-network candidates, and no global "popular posts" index exists today.

## Milestone 1 — Foundations (signals, config, telemetry)

### NRS-001: Ranking config block + feature flag + safe fallback contract
**Type:** Chore  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Add a newsfeed-recsys settings block to `app/core/settings.py` (mirror the existing `reco_*` block at `app/core/settings.py:1948-1955` and the `newsfeed_feed_*` block at `app/core/settings.py:1069-1075`): `newsfeed_recsys_enabled` (default `false`, env `NEWSFEED_RECSYS_ENABLED`), `newsfeed_recsys_refresh_interval_hours`, `newsfeed_recsys_max_for_you_results`, `newsfeed_recsys_candidate_followed_limit`, `newsfeed_recsys_candidate_popular_limit`, `newsfeed_recsys_candidate_affinity_limit`, `newsfeed_recsys_signal_retention_days`, plus ranking-weight knobs consumed by NRS-005.
- Define the fallback contract: when `newsfeed_recsys_enabled` is false OR ranking produces zero items, the For You request must return the existing chronological feed unchanged (the code path at `app/routers/newsfeed.py:5234-5241`, `GSI1PK=FEED#{user_id}`) — no behavior change for existing `GET /feed` callers.
- Document the flag + env vars in `CLAUDE.md` feature-flags table (alongside `NEWSFEED_MARKDOWN_ENABLED`, settings at `app/core/settings.py:1105`).

**Acceptance Criteria**
- `S.newsfeed_recsys_enabled` defaults to `false`; all knobs are overridable via env.
- With the flag off, `GET /feed` responses are byte-identical to current behavior (regression test).
- Settings load with no env present (defaults applied) and unit test asserts every new attribute exists.

**Dependencies**
- None.

---

### NRS-002: Define ranking signals + scoring model (spec doc)
**Type:** Spike  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Produce a short in-repo design note (top of the new service file from NRS-005, as a module docstring like `app/services/recommendations.py:1-12`) enumerating the ranking signals and how each maps to data already on the post item: **recency** (`created_at`, parsed via `app/services/newsfeed_feed_query.py:20`), **engagement velocity** (`like_count`, `comment_count`, `tip_total_cents`, `reactions_counts` — written/read at `app/routers/newsfeed.py:2280-2284` and incremented at `:4670`, `:4760`, `:5636`), **author affinity** (follows via `get_following` at `app/services/social.py:187`; per-user post-engagement signals from NRS-003), **content type** (has-media via `post_has_media` at `app/services/newsfeed_feed_query.py:48`; locked posts via `post.get("locked")` at `app/routers/newsfeed.py:5330`; video posts), and **personal history** (viewer's prior reactions/comments/unlocks on this author).
- Specify the score formula and per-day recency decay, reusing the decay approach in `app/services/recommendations.py:42` (`DECAY_FACTOR=0.95`) and the watch/like weights at `:35-40`.
- Define exclusions parity with the chronological path: blocked set (`app/routers/newsfeed.py:5183-5184`), snoozed followings (`:5188-5194`), hidden (`is_hidden`, `:5312`), moderation-removed (`:5310`), unpublished (`:5308`), and locked visibility (`can_view_post`, `:5327`).

**Acceptance Criteria**
- Design note lists every signal with the exact post field / service call it derives from (file:line).
- Score formula and decay are written as pseudocode that NRS-005 can implement directly.
- Exclusion rules explicitly match the eight filters in the existing feed loop.

**Dependencies**
- None.

---

### NRS-003: Post-engagement signal recording (reactions, comments, tips, unlocks, follows)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add post-engagement signal persistence reusing the recommendations table single-table layout (`SIGNAL#{user_id}` / item per content) from `app/services/recommendations.py:92-145`. Use a distinct sort-key namespace so video and post signals never collide, e.g. `SIGNAL#{user_id}` / `POST#{post_id}` with an `author_id` attribute for affinity rollups.
- Record signals (best-effort `try/except`, never block the request) at the existing engagement write sites in `app/routers/newsfeed.py`: like (`:4670`), unlike (`:4706`), reaction add (`_reaction_summaries` area / `:4909`), comment create (`:5636`), post tip (`:5927`), comment tip (`:4760`), and unlock (search the unlock handler). Mirror the fire-and-forget pattern used for `advance_progress` achievement hooks (`:4909`, `:5643`).
- Store `last_engaged_at` + a per-author affinity counter so NRS-005 can compute author affinity cheaply; carry a TTL (`newsfeed_recsys_signal_retention_days`) exactly like `_signal_ttl()` at `app/services/recommendations.py:52`.

**Acceptance Criteria**
- Each engagement type writes/updates a `SIGNAL#{user_id}` / `POST#{post_id}` item with weighted contribution and `author_id`.
- Signal writes are wrapped so a DDB failure never changes the 2xx outcome of like/comment/tip/unlock.
- Unit tests (moto) assert each engagement endpoint emits the correct signal item; signals carry a TTL.

**Dependencies**
- NRS-001, NRS-002.

---

### NRS-004: Feed-engagement telemetry / metrics
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Extend `app/metrics.py` with For-You metrics mirroring the existing `record_newsfeed_feed_*` family (`app/metrics.py:1774-1805`): `record_newsfeed_recsys_request(mode, source)` (source ∈ `for_you|chronological_fallback|cold_start`), `record_newsfeed_recsys_latency`, `record_newsfeed_recsys_candidate_counts(followed, popular, affinity)`, and `record_newsfeed_recsys_refresh(outcome)`.
- Add structured logging parity with `_build_feed_query_log_extra` (`app/routers/newsfeed.py:5079-5117`): log viewer_id, source, candidate counts, served count, ranked-vs-chronological.
- Emit a feed-engagement event when a served For-You post is subsequently engaged (hook into NRS-003 signal writes) so served→engaged conversion is measurable.

**Acceptance Criteria**
- New metric helpers exist and are unit-callable without a metrics backend.
- For-You endpoint (NRS-006) records request/latency/source/candidate-count metrics on every call.
- Log line includes source + candidate breakdown; redacts post bodies (only counts/ids).

**Dependencies**
- NRS-001.

---

## Milestone 2 — Candidate generation & ranking service

### NRS-005: Post-ranking service (scoring + decay)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Create `app/services/newsfeed_recsys.py` reusing helpers/patterns from `app/services/recommendations.py`: `_days_ago`/`_decay` (`:66-73`), `compute_affinity_scores` shape (`:171-195`), and the pre-compute+store+get pattern (`compute_for_you`/`_store_for_you`/`get_for_you` at `:202-323`).
- Implement `score_post(post, viewer_signals, follow_set, viewer_id, now)` using NRS-002's formula: combine recency decay, engagement velocity (normalize `like_count`+`comment_count`+`reactions` per `created_at` age), author affinity (from NRS-003 signals + `follow_set`), content-type weights, and a personal-history boost. Pull engagement counts from the post item exactly as `_post_to_dict` does (`app/routers/newsfeed.py:2280-2284`).
- Implement `rank_candidates(viewer_id, candidates) -> ordered post_ids` that scores, applies all exclusions from NRS-002, dedupes, and caps at `newsfeed_recsys_max_for_you_results`.
- Pure/​deterministic given inputs; no network in `score_post` (all I/O lives in candidate generation / signal fetch) for cheap unit testing.

**Acceptance Criteria**
- `score_post` is deterministic; unit tests cover recency-only, high-engagement, followed-author, and locked/has-media variants.
- `rank_candidates` excludes blocked/snoozed/hidden/unpublished/moderation-removed/locked-not-viewable posts (parity with `app/routers/newsfeed.py:5302-5328`).
- Ranking is stable (tie-break by `created_at` then `post_id`, reusing `sort_posts_deterministically` at `app/services/newsfeed_feed_query.py:88`).

**Dependencies**
- NRS-002, NRS-003.

---

### NRS-006: Candidate generation — followed + popular + affinity (the fan-out gap)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- This is the core architectural gap: the existing feed index `GSI1PK=FEED#{user_id}` (`app/routers/newsfeed.py:5236-5241`) holds only the viewer's own posts + posts fanned out from followings (`fan_out_post_to_followers`, `app/services/newsfeed_fanout.py:42`). It contains **no** out-of-network candidates and there is **no global popular-post index** today (only `GSI1` FEED, `GSI2` POST_AUTHOR at `:3649`, `GSI3` notifications, `GSI4` drafts, `GSI5` followers). Build a three-source candidate generator `generate_candidates(viewer_id)`:
  1. **Followed authors** — read the viewer's existing fan-out refs (`GSI1PK=FEED#{viewer_id}`) and/​or recent posts per followed author via `GSI2PK=POST_AUTHOR#{author}` (`:5223`), bounded by `newsfeed_recsys_candidate_followed_limit`. Reuse `get_following` (`app/services/social.py:187`).
  2. **Popular** — out-of-network engagement-velocity candidates. Add a sparse global popularity index (NRS-007) and read its top-N (`newsfeed_recsys_candidate_popular_limit`); this is the source of posts beyond the viewer's own/followed set.
  3. **Affinity** — collaborative: from NRS-003 post-engagement signals find co-engaged authors (mirror `compute_for_you`'s similar-user step at `app/services/recommendations.py:223-257` but keyed on post signals) and pull their recent posts via `GSI2`.
- Merge/dedupe candidates, batch-hydrate post items via `batch_get_item` exactly as the feed does (`app/routers/newsfeed.py:5264`), then hand to `rank_candidates` (NRS-005).
- Bound total candidate count and DDB calls to respect the existing feed query budget (`_feed_query_budget_limits`, `:5120`).

**Acceptance Criteria**
- `generate_candidates` returns a deduped pool drawn from all three sources, with per-source caps from config.
- At least one served post can originate beyond the viewer's own + followed set (popular source) — covered by a moto test with a non-followed popular author.
- Candidate generation respects max-call/elapsed budgets; metrics (NRS-004) record per-source counts.

**Dependencies**
- NRS-005, NRS-007.

---

### NRS-007: Global popularity index (sparse engagement-velocity index)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Introduce a sparse global popularity index so out-of-network candidates exist (the missing piece for NRS-006 source 2). Reuse the recommendations table single-table pattern (`pk`/`sk`, `app/services/recommendations.py:286-296`): maintain a small set of bucket rows, e.g. `pk="POPULAR#GLOBAL"` / `sk="{score:020d}#{post_id}"` (or time-windowed `POPULAR#{yyyymmddhh}`), updated as engagement accrues. Carry a TTL so stale popular rows expire (like `_reco_ttl()` at `:56`).
- Update popularity on the same engagement write sites instrumented in NRS-003 (`app/routers/newsfeed.py` like/comment/tip/reaction), computing a velocity score (engagement / age) — best-effort, public published posts only (respect `status=="published"` and not locked/moderation-removed, mirroring `app/routers/newsfeed.py:5308-5310`).
- Provide `get_popular_post_ids(limit)` reading top rows; gate inclusion to public, non-locked posts at read time.
- Avoid a hot-partition write storm: only upsert popularity when an engagement threshold is crossed or sample writes (document the tradeoff in the module docstring).

**Acceptance Criteria**
- Engaging with a public post makes it retrievable via `get_popular_post_ids` ranked by velocity (moto test).
- Locked/private/unpublished/moderation-removed posts never appear in popularity reads.
- Popularity rows carry a TTL; write path is best-effort and never blocks the engagement request.

**Dependencies**
- NRS-001, NRS-003.

---

### NRS-008: Pre-compute + background refresh loop + on-demand recompute
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add `compute_for_you_posts(viewer_id)` (candidate gen → rank → store) storing the ordered post_ids at `pk=RECO#{viewer_id}` / `sk=FOR_YOU_POSTS` with a 24h TTL — mirror `_store_for_you`/`get_for_you` at `app/services/recommendations.py:287-323` (namespaced sk to avoid clashing with the video `FOR_YOU` row).
- Add `start_newsfeed_recsys_refresh_task()` mirroring `_reco_refresh_loop`/`start_reco_refresh_task` (`app/services/recommendations.py:563-585`), gated on `S.newsfeed_recsys_enabled`, and register it in `app/main.py` next to `start_reco_refresh_task` (`app/main.py:131`, `:712`).
- Add an internal recompute endpoint mirroring `POST /internal/recommendations/refresh` (`app/routers/recommendations.py:338-355`) for a single viewer or all viewers-with-signals (reuse the `_list_all_signal_users` scan at `app/services/recommendations.py:518-535`, filtered to post signals).

**Acceptance Criteria**
- Pre-computed For-You row is written with a TTL and read back by the endpoint (NRS-009).
- Background loop registered on startup only when flag is on; logs disabled state otherwise (parity with `:579-583`).
- `POST /internal/...refresh` recomputes for a given viewer; unit test asserts the stored row updates.

**Dependencies**
- NRS-006.

---

## Milestone 3 — API & cold start

### NRS-009: For You feed endpoint with chronological fallback
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add `GET /feed/for-you` to `app/routers/newsfeed.py` (or a `feed` param `?sort=for_you|following|latest`). Read the pre-computed row (NRS-008), hydrate post items via `batch_get_item` + `_post_to_dict` exactly as the chronological loop (`app/routers/newsfeed.py:5264-5340`) so every post carries the same flags (`liked_by_me`, `unlocked`, `is_bookmarked`, `source`, repost attribution, sponsored/boost injection at `:5366-5379`).
- Return `{ items, next_cursor, source }` where `source ∈ for_you|chronological_fallback|cold_start` — matching the video `ForYouResponse.source` contract (`app/routers/recommendations.py:50-53`).
- Fallback: when flag off, no stored row, or zero ranked items, delegate to the existing chronological feed code so the endpoint always returns posts (the `trending_fallback` pattern at `app/routers/recommendations.py:177-184`).

**Acceptance Criteria**
- Flag on + stored row → ranked items with `source="for_you"`; flag off → identical to `GET /feed` with `source="chronological_fallback"`.
- Returned post dicts are shape-identical to `GET /feed` items (same flags, sponsored/boost injection applied).
- Pagination via `next_cursor` works; viewer never sees blocked/snoozed/hidden/locked-not-viewable posts.

**Dependencies**
- NRS-008.

---

### NRS-010: Cold-start handling
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- For viewers with no post-engagement signals and few/no followings, define cold-start ranking: blend popular (NRS-007) with followed-author recency, weighting recency higher (mirror the new-content boost in `compute_for_you` at `app/services/recommendations.py:259-274` and the trending fallback at `app/routers/recommendations.py:190-214`).
- Return `source="cold_start"` so the UI (NRS-011) can show a "Showing popular posts — engage to personalize" hint, parity with the video ForYouTab fallback note (`frontend/src/pages/videos/ForYouTab.tsx:55-59`).

**Acceptance Criteria**
- A brand-new viewer (no signals, no follows) gets a non-empty For-You feed sourced from popularity with `source="cold_start"`.
- As the viewer engages (NRS-003 signals accrue), subsequent recomputes shift `source` toward `for_you` (moto test simulating signal growth).

**Dependencies**
- NRS-006, NRS-007.

---

## Milestone 4 — Frontend & tests

### NRS-011: Feed tabs — "For You" / "Following" / "Latest"
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add a tab bar to `frontend/src/pages/feed/NewsFeed.tsx` (`frontend/src/pages/feed/NewsFeed.tsx:5-12`) for "For You" / "Following" / "Latest", reusing `FeedTimeline` (`frontend/src/pages/feed/FeedTimeline.tsx`, infinite query at `:86`). Following/Latest map to the current chronological endpoint; For You hits NRS-009. Reuse the tab + source-hint UX from `frontend/src/pages/videos/ForYouTab.tsx`.
- Add a `getForYouFeed` wrapper to `frontend/src/api/endpoints/newsfeed.ts` (next to `getFeed` at `:31`) and a distinct React Query key (e.g. `["feed", "for-you"]`) so tabs cache independently.
- Gate the For You tab behind a frontend feature flag (mirror `newsfeedSchedulingUiEnabled` usage at `frontend/src/pages/feed/NewsFeed.tsx`), defaulting to chronological so removing the flag reverts cleanly.
- Show the cold-start / fallback hint when `source !== "for_you"`.

**Acceptance Criteria**
- Tabs render; switching tabs swaps the query source without losing the composer.
- For You tab shows the source hint for `cold_start`/`chronological_fallback`.
- With the UI flag off, only the existing chronological feed renders (no behavior change).

**Dependencies**
- NRS-009.

---

### NRS-012: Backend tests — ranking, candidate generation, fallback, cold start
**Type:** Chore  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add `tests/test_newsfeed_recsys.py` (offline/moto, following the in-memory-table + frozen-handle pattern noted in `CLAUDE.md`): unit-test `score_post`/`rank_candidates` (NRS-005), `generate_candidates` three-source merge incl. a non-followed popular author (NRS-006), popularity index read/write + exclusions (NRS-007), pre-compute/store/get + refresh (NRS-008), the endpoint's `for_you`/`chronological_fallback`/`cold_start` source branches (NRS-009/010), and signal emission from each engagement endpoint (NRS-003).
- Assert the flag-off regression: `GET /feed` and `/feed/for-you` both return the chronological feed unchanged.

**Acceptance Criteria**
- All new unit tests pass offline (no real AWS/network), runnable via `just test`.
- Tests cover: ranked ordering, every exclusion rule, popular out-of-network surfacing, cold start, and flag-off fallback.
- A test asserts For-You item shape equals `GET /feed` item shape.

**Dependencies**
- NRS-009, NRS-010.

---

### NRS-013: E2E tests — For You feed UI + tabs
**Type:** Chore  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Add `frontend/e2e/feed-for-you.spec.ts` (follow existing patterns in `frontend/e2e/feed.spec.ts` and `frontend/e2e/recommendations.spec.ts`): seed posts + engagement via session-auth `page.request` with CSRF header, enable the flag, assert the For You tab renders ranked posts and that a popular non-followed author's post can appear.
- Cover tab switching (For You / Following / Latest) and the cold-start hint copy.

**Acceptance Criteria**
- Spec passes under `just e2e` config (1 worker, 1 retry, Chromium).
- Asserts ranked-vs-chronological ordering difference and source-hint visibility for cold start.
- Tab switch preserves composer and loads the correct source.

**Dependencies**
- NRS-011, NRS-012.

---
