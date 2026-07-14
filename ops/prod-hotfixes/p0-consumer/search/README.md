# P0 Consumer — GLOBAL SEARCH (VERIFY-ONLY; already built end-to-end)

Backlog item "global search: MISSING" (docs/feature-improvements-backlog.md, 2026-05-29) is STALE.
Global search is fully built and LIVE on all three surfaces. No code change / no hotfix was
required. This fold is the parity + deep-verify record.

## Backend (LIVE on prod, no patch needed)
- app/routers/search.py (907 lines): APIRouter(prefix="/ui/search"), ThreadPoolExecutor fan-out
  across up to 9 domains (users/posts/catalog/files + extended messages/tickets/contacts/videos/
  calendar), 5s/2s timeouts w/ `partial` flag, 30 req/60s rate-limit, search-history w/ 90d TTL.
  Committed at cbcddd67 ("GAP-0358/0359/0360: repost notif + search rate-limit + profile block").
- Registered: app/main.py:106 import, :860 include_router(search_router).
- Auth: Depends(require_ui_session) — UI-session consumer surface, NOT an API-key product.
  Correctly ABSENT from app/services/api_key_route_scope_registry.py => fail-closed to keys
  (no #118 regression). Do NOT add to the registry.
- Post index: body_plain_lc is written inline at post-create in app/routers/newsfeed.py:3845 &
  :4616 and app/services/sponsored_creator_posts.py:200, so all newly-created posts are findable.

## PROD PARITY — CONFIRMED via https://tl-api.bitbazaar.cc/openapi.json (2026-07-14)
Routes present on prod i-08f937fc705ebea75:
  GET    /ui/search                     (q required, types default=all 9 domains, limit 1..20 def 5)
  GET    /ui/search/history             (limit 1..50 def 20)
  POST   /ui/search/history
  DELETE /ui/search/history
  DELETE /ui/search/history/{item_id}
The default `types` on prod = "calendar,catalog,contacts,files,messages,posts,tickets,users,videos"
=> GLOBAL_SEARCH_EXTENDED_DOMAINS is effectively ON on prod (all 9 domains live). No deploy needed.
Auth-gating verified live: GET /ui/search?q=test -> 401 without a session cookie.

## ON-DEVICE DEEP-VERIFY — A15 (R5CX821TA9R / 192.168.0.238), against PROD, 2026-07-14
Path: Discover tab -> top-bar Search icon -> Global Search screen.
- Typed "test" (debounced): GET /ui/search?q=test&limit=10 -> 200 (232ms).
  Rendered tabs: All / Posts (7) / Videos (8) / Catalog (2), "17 results". Real cards, e.g.
  Posts: "vid test", "smoke-test post from verification", "Hello+from+Chrome+mobile+web+test+2026";
  Videos: "Playback Test Clip", "ADV-B2 preroll test"; Catalog: "E2E Ebook (digital)".
- History persistence: POST /ui/search/history -> 200, GET /ui/search/history?limit=20 -> 200.
- Result deep-link: tapping a post card navigated to PostDetail -> GET /posts/{id} -> 403
  "Subscription required" (correct subscription-gating render; deep-link routing works).
- Empty-query handling: clearing the field fires NO empty-q call (no 400); instead shows
  "Recent searches" (GET /ui/search/history -> 200) with the prior "test" query + "Clear all".
- Crash buffer EMPTY throughout.

## Android surface (built, wired, committed clean on branch android-impl)
- data/discover/: SearchApi.kt, SearchDtos.kt, SearchDomain.kt, SearchRepository.kt,
  SearchHistoryRepository.kt, DiscoverDataModule.kt (Hilt).
- feature/discover/: GlobalSearchScreen.kt (MultiSearchRoute) + GlobalSearchViewModel.kt.
- navigation/DiscoverNavigation.kt: MultiSearchDest.ROUTE="search/global", multiSearchDestination(),
  openSearchResult()/toInAppRoute() deep-linking to PublicProfile/PostDetail/VideoDetail/TagPage.
  Registered in navigation/AuthenticatedGraph.kt:169.
- Entrypoint: feature/discover/DiscoverScreen.kt search IconButton -> onOpenSearch ->
  feature/shell/AuthedShell.kt:173 onOpenRoute(MultiSearchDest.ROUTE).

## Web SPA (built)
- frontend/src/pages/search/SearchPage.tsx, frontend/src/api/endpoints/search.ts (sends limit=10),
  frontend/e2e/global-search.spec.ts.

## Residual (non-blocking)
- Pre-existing posts created BEFORE the body_plain_lc field was added lack the field and are not
  matched by _search_posts until a one-time DDB backfill runs on prod. New posts are indexed on
  create. Backfill requires prod DDB access (aws/ssm not available from the dev host / this shell).
  Impact: posts-domain recall is partial for legacy posts only; all other domains unaffected.
