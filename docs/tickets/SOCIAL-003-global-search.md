# SOCIAL-003: Global Search

**Ticket**: SOCIAL-003
**Author**: Engineering
**Status**: Implemented
**Date**: 2026-05-27
**Priority**: P0 — Core User Experience
**Estimated effort**: 14-18 days

---

## 1. Executive Summary

The platform has search capabilities scattered across individual modules, each with its own endpoint, query syntax, and UI. Users searching for "photography" must separately check the user discovery page, the catalog, the file manager, and their alerts. <!-- NOTE: This ticket's "current state" description is OUTDATED. Global search has been FULLY IMPLEMENTED:
  - Backend: app/routers/search.py — registered at main.py:73,395
  - Aggregator: _search_aggregator function (search.py:618) fans out to users, posts, videos, catalog, files, messages, tickets, contacts, calendar
  - Search history: POST/GET/DELETE /ui/search/history endpoints (search.py:820-855)
  - Frontend: SearchPage at frontend/src/pages/search/SearchPage.tsx, route at App.tsx:153
  - API client: frontend/src/api/endpoints/search.ts
  All "Files to Create" listed in section 13 already exist.
-->

There is no unified search experience, no `/search` route, and no search results page. The existing command palette (`Header.tsx`) only navigates to pages by name -- it does not search content.

This feature introduces a unified search endpoint `GET /ui/search` that aggregates results from existing per-module search functions, a new `/search` page with tabbed results (Posts, Videos, Users, Files, Catalog), and an enhanced header search bar that triggers content search in addition to page navigation. The backend fans out a single query to multiple search services in parallel, merges results, and returns a unified response with type-tagged results.

Global search is fundamental UX -- every major platform has it. Without it, users cannot find content they know exists but cannot locate. Discovery is limited to following/browsing, which does not scale as content volume grows.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| User | I want to search across all content types with one query. | Type in header search bar; see results from posts, users, videos, files. |
| User | I want to filter search results by type. | Tabs on search page: All, Posts, Users, Videos, Files, Catalog. |
| User | I want to use keyboard shortcut to open search. | Ctrl+K / Cmd+K opens search (already wired). |
| User | I want search results to link to the actual content. | Clicking a user result navigates to profile; clicking a post opens the post. |
| User | I want search suggestions as I type. | Header search shows top 3-5 results per category in a dropdown before navigating to full results page. |
| Admin | I want to search for users by email for support. | User search includes email matching. |

### 2.2 Pain Points

1. **Fragmented search**: Each module has its own search endpoint and UI. Users must know which module to search in.
2. **No content search**: Posts have no search at all. There is no endpoint to search post bodies.
3. **Poor discoverability**: New users cannot find interesting content or creators without browsing manually.
4. **Command palette is page-only**: The existing `CommandDialog` in `Header.tsx` (lines 364-386) only searches page names from the `SEARCH_PAGES` array (lines 70-90). It does not search actual content.

### 2.3 Existing Per-Module Search Endpoints

| Module | Endpoint | Function | File:Line |
|--------|----------|----------|-----------|
| Users | `GET /ui/discover/search?q=...` | `search_users()` | `app/routers/discovery.py:19-27` |
| Catalog | `GET /ui/catalog/items/search?q=...` | `search_items()` | `app/routers/catalog.py:379-408` |
| Contacts | `GET /messaging/contacts/search?q=...` | User search in messaging | `app/routers/messaging.py` |
| Files (name) | `GET /v1/fs/search?prefix=...` | `search_prefix()` | `app/services/filemanager.py:947` |
| Files (content) | `GET /v1/fs/search-text?q=...` | `search_text()` | `app/services/filemanager.py:1861` |
| Alerts | `GET /ui/alerts/search?q=...` | Alert text search | `app/routers/alerts.py:124-125` |
| Purchases | `/ui/purchase-history/transactions/search` | Transaction search | `frontend/src/api/endpoints/purchases.ts:20-24` |

<!-- NOTE: Post search now exists in app/routers/search.py:113 (_search_posts). Video search at search.py:490 (_search_videos). Newsfeed.py is 5954 lines, not 4998. -->
**Missing search**: Posts/newsfeed has NO search endpoint at all (`app/routers/newsfeed.py` has 4998 lines, none with search). Videos have no text search endpoint.

---

## 3. Current State Analysis

### 3.1 Header Command Palette

`Header.tsx` (lines 105, 138-148, 364-386) implements a command palette using `CommandDialog` from cmdk/shadcn:

- Opens on Ctrl+K / Cmd+K (lines 138-148)
- `searchOpen` state controls visibility (line 105)
- `CommandInput` placeholder is "Search pages..." (line 366)
- `CommandList` renders items from `SEARCH_PAGES` array, grouped by "Pages" and "Account" (lines 369-383)
- Each `CommandItem` navigates to a route on select (lines 375-378)

The command palette has no content search. The `SEARCH_PAGES` constant (defined around line 70) is a static list of page labels and paths.

### 3.2 Discovery Service

`app/services/discovery.py` provides `search_users()` (line 99) which:
- Tokenizes the query
- Queries a discovery index for matching user profiles
- Scores results using `_score_search_result()` (line 335)
- Returns enriched results with follow status

The frontend client is `searchDiscoverUsers()` in `frontend/src/api/endpoints/discovery.ts:34-37`.

### 3.3 Catalog Search

`app/routers/catalog.py:379-408` implements `search_items()`:
- Accepts `q` query parameter
- Tokenizes query with `_catalog_tokens()`
- Table-scans catalog items and matches tokens
- Returns `CatalogItemListOut`

### 3.4 File Search

`app/services/filemanager.py` has two search functions:
- `search_prefix()` (line 947): prefix-based filename search
- `search_text()` (line 1861): content text search within files

### 3.5 Route Configuration

`App.tsx` (lines 84-154) defines all routes. There is no `/search` route. The `discover` route exists at line 115 but only shows the user discovery page.

### 3.6 Frontend API Clients

Existing search API clients (`frontend/src/api/endpoints/`):
- `discovery.ts:34-37`: `searchDiscoverUsers()`
- `cart.ts:77-78`: `searchCatalogItems()`
- `files.ts:19-26`: `searchFiles()`, `searchText()`
- `messaging.ts:491-494`: `searchUsers()`
- `alerts.ts:12-13`: `searchAlerts()`

No unified search client exists.

---

## 4. Technical Architecture

### 4.1 System Diagram

```
Header SearchBar / SearchPage          Backend Aggregator                Per-Module Services
  |                                       |                                |
  |-- GET /ui/search?q=...&types=... -->  |                                |
  |                                       |-- fan-out (parallel) -------->|
  |                                       |   search_users(q)              | discovery.py:99
  |                                       |   search_posts(q)              | (NEW in newsfeed.py)
  |                                       |   search_videos(q)             | (NEW in video_listing.py)
  |                                       |   search_catalog(q)            | catalog.py:379
  |                                       |   search_files(q)              | filemanager.py:947,1861
  |                                       |                                |
  |                                       |<-- merge + rank results -------|
  |                                       |                                |
  |<-- { users: [...],                   |                                |
  |      posts: [...],                    |                                |
  |      videos: [...],                   |                                |
  |      catalog: [...],                  |                                |
  |      files: [...] }                   |                                |
  |                                       |                                |
SearchPage                               |                                |
  |-- Tabs: All | Posts | Users | ...     |                                |
  |-- Results grid/list                   |                                |
  |-- "View all X results" links          |                                |
```

### 4.2 Data Flow

1. User types query in header search bar or navigates to `/search?q=photography`
2. Frontend debounces input (300ms) and calls `GET /ui/search?q=photography&types=users,posts,videos,catalog,files&limit=5`
3. Backend `search_aggregator()` fans out to per-module search functions using `asyncio.gather()`:
   - `search_users(q, limit=limit)` -- existing
   - `search_posts(q, user_id, limit=limit)` -- NEW function
   - `search_videos(q, limit=limit)` -- NEW function
   - `search_catalog_items(q, limit=limit)` -- existing (via internal call)
   - `search_files_prefix(q, user_id, limit=limit)` -- existing
4. Results merged into typed sections: `{ users: [...], posts: [...], ... }`
5. Each result includes `type`, `id`, `title`, `snippet`, `thumbnail_url`, `url` for uniform rendering

### 4.3 New Search Functions Needed

**Post search** (`app/routers/newsfeed.py`): No post search exists. Implementation:
- Scan `app_single_table` for items where `pk` starts with `POST#`, `sk=META`
- Apply `FilterExpression` matching query tokens against `body_plain` or `body`
- Alternative (better): Add search tokens to post items on write (same pattern as file search)

**Video search** (`app/routers/video_listing.py`): The gallery has category/tag filters but no text search endpoint.
- Query `VideoMetadata` table, filter on `title` and `description` containing query tokens
- Or scan with `FilterExpression` on title/description

---

## 5. Data Model

### 5.1 No New DynamoDB Tables

Global search is a query aggregator that calls existing tables. No new DDB tables or entities are required.

### 5.2 Post Search Tokens (Enhancement to Existing Posts)

To enable efficient post search without full table scans, add search tokens to post items on write:

| Field | Type | Description |
|-------|------|-------------|
| `search_tokens` | SS | Set of lowercased word tokens from post body | `{"photography", "tips", "camera"}` |
| `GSI3PK` | S | `POSTSEARCH` (fixed value for all searchable posts) |
| `GSI3SK` | S | `{created_at}#POST#{post_id}` |

The `app_single_table` already has GSI3 defined (`scripts/local-ddb-init.py:223`). Currently GSI3 may be used by other entities; if so, use a dedicated search scan approach instead.

Alternative approach (simpler, no GSI): Use DynamoDB `scan()` with `FilterExpression` containing `contains()` on `body_plain`. This is acceptable for platforms with <100K posts. For scale, move to OpenSearch/ElasticSearch.

### 5.3 Search Result Model

Unified search result returned to frontend:

```json
{
  "type": "post",
  "id": "p_abc123",
  "title": "10 Photography Tips",
  "snippet": "Here are my top photography tips for beginners...",
  "thumbnail_url": "/mock/s3/uploads/photo.jpg",
  "url": "/posts/p_abc123",
  "author": {
    "user_id": "bob@test.local",
    "display_name": "Bob"
  },
  "created_at": "2026-05-27T10:00:00Z",
  "score": 0.85
}
```

---

## 6. API Contract Design

### 6.1 Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/search` | `require_ui_session` | Unified search across modules |
| GET | `/ui/search/posts` | `require_ui_session` | Full post search with pagination |
| GET | `/ui/search/videos` | `require_ui_session` | Full video search with pagination |

### 6.2 GET `/ui/search`

**Query parameters:**
- `q` (string, required, min 1, max 200): Search query
- `types` (string, optional, default "users,posts,videos,catalog,files"): Comma-separated content types to search
- `limit` (int, optional, default 5, max 20): Results per type (for preview/dropdown mode)

**Response (200):**
```json
{
  "query": "photography",
  "results": {
    "users": {
      "items": [
        {
          "type": "user",
          "id": "bob@test.local",
          "title": "Bob the Photographer",
          "snippet": "Professional photographer and creator",
          "thumbnail_url": "/mock/s3/avatars/bob.jpg",
          "url": "/discover",
          "meta": { "follower_count": 1234, "is_following": false }
        }
      ],
      "total_estimate": 3,
      "has_more": true
    },
    "posts": {
      "items": [
        {
          "type": "post",
          "id": "p_abc123",
          "title": "10 Photography Tips",
          "snippet": "Here are my top photography tips...",
          "thumbnail_url": null,
          "url": "/posts/p_abc123",
          "meta": { "author_id": "bob@test.local", "like_count": 42 }
        }
      ],
      "total_estimate": 15,
      "has_more": true
    },
    "videos": {
      "items": [],
      "total_estimate": 0,
      "has_more": false
    },
    "catalog": {
      "items": [],
      "total_estimate": 0,
      "has_more": false
    },
    "files": {
      "items": [
        {
          "type": "file",
          "id": "/photos/sunset.jpg",
          "title": "sunset.jpg",
          "snippet": "photos/sunset.jpg",
          "thumbnail_url": null,
          "url": "/files",
          "meta": { "size": 2048000 }
        }
      ],
      "total_estimate": 1,
      "has_more": false
    }
  }
}
```

### 6.3 GET `/ui/search/posts`

Full paginated post search for the "Posts" tab on SearchPage:

**Query parameters:**
- `q` (string, required)
- `limit` (int, default 20, max 50)
- `cursor` (string, optional)

**Response (200):**
```json
{
  "posts": [
    {
      "post_id": "p_abc123",
      "author_id": "bob@test.local",
      "body_snippet": "Here are my top photography tips...",
      "image_urls": ["..."],
      "like_count": 42,
      "comment_count": 5,
      "created_at": "2026-05-27T10:00:00Z"
    }
  ],
  "next_cursor": "...",
  "total_estimate": 15
}
```

### 6.4 Error Codes

| Status | Condition |
|--------|-----------|
| 200 | Success (even if no results) |
| 400 | Query too short or too long |
| 401 | Not authenticated |
| 429 | Rate limited (max 30 searches per minute) |
| 504 | Search timeout (one or more modules timed out; partial results returned) |

---

## 7. Frontend Component Design

### 7.1 New Files

| File | Purpose |
|------|---------|
| `frontend/src/pages/search/SearchPage.tsx` | Full search results page with tabs |
| `frontend/src/api/endpoints/search.ts` | Unified search API client |

### 7.2 SearchPage Component

```
SearchPage
  |-- Search input (pre-filled from URL query param)
  |-- Tabs: All | Posts | Users | Videos | Catalog | Files
  |-- TabsContent "all"
  |     |-- UserResults (top 3 with "View all" link)
  |     |-- PostResults (top 3 with "View all" link)
  |     |-- VideoResults (top 3 with "View all" link)
  |     |-- CatalogResults (top 3 with "View all" link)
  |     |-- FileResults (top 3 with "View all" link)
  |-- TabsContent "posts"
  |     |-- Full paginated PostCard list
  |-- TabsContent "users"
  |     |-- Full paginated user cards with Follow button
  |-- ... (each type has its own tab)
  |-- EmptyState when no results
```

### 7.3 Header Search Enhancement

Modify the existing `CommandDialog` in `Header.tsx` (lines 364-386):

1. Add a debounced API call to `GET /ui/search?q=...&limit=3` as the user types
2. Show content results below the existing page navigation results
3. Add a "View all results" option at the bottom that navigates to `/search?q=...`
4. Keep existing page navigation functionality intact

```tsx
// Header.tsx - enhanced CommandDialog
<CommandDialog open={searchOpen} onOpenChange={setSearchOpen}>
  <CommandInput
    placeholder="Search content and pages..."
    value={searchQuery}
    onValueChange={setSearchQuery}
  />
  <CommandList>
    {/* Existing page navigation */}
    <CommandGroup heading="Pages">
      {SEARCH_PAGES.filter(...).map(...)}
    </CommandGroup>

    {/* NEW: Content search results */}
    {searchResults?.users?.items?.length > 0 && (
      <CommandGroup heading="Users">
        {searchResults.users.items.map(user => (
          <CommandItem onSelect={() => navigate(`/discover?q=${searchQuery}`)}>
            {user.title}
          </CommandItem>
        ))}
      </CommandGroup>
    )}

    {searchResults?.posts?.items?.length > 0 && (
      <CommandGroup heading="Posts">
        {searchResults.posts.items.map(post => (
          <CommandItem onSelect={() => navigate(post.url)}>
            {post.snippet}
          </CommandItem>
        ))}
      </CommandGroup>
    )}

    {/* View all results */}
    {searchQuery.length > 0 && (
      <CommandGroup>
        <CommandItem onSelect={() => { navigate(`/search?q=${searchQuery}`); setSearchOpen(false); }}>
          View all results for "{searchQuery}"
        </CommandItem>
      </CommandGroup>
    )}
  </CommandList>
</CommandDialog>
```

### 7.4 Route Configuration

Add to `App.tsx` (after the `discover` route at line 115):
```tsx
<Route path="search" element={<SearchPage />} />
```

### 7.5 API Client

```typescript
// frontend/src/api/endpoints/search.ts
export interface SearchResultItem {
  type: "user" | "post" | "video" | "catalog" | "file";
  id: string;
  title: string;
  snippet: string;
  thumbnail_url?: string;
  url: string;
  meta?: Record<string, unknown>;
  created_at?: string;
}

export interface SearchResultSection {
  items: SearchResultItem[];
  total_estimate: number;
  has_more: boolean;
}

export interface SearchResponse {
  query: string;
  results: {
    users: SearchResultSection;
    posts: SearchResultSection;
    videos: SearchResultSection;
    catalog: SearchResultSection;
    files: SearchResultSection;
  };
}

export const globalSearch = (q: string, types?: string, limit = 5) => {
  const params: Record<string, string> = { q, limit: String(limit) };
  if (types) params.types = types;
  return api.get<SearchResponse>("/ui/search", params);
};

export const searchPosts = (q: string, limit = 20, cursor?: string) => {
  const params: Record<string, string> = { q, limit: String(limit) };
  if (cursor) params.cursor = cursor;
  return api.get("/ui/search/posts", params);
};

export const searchVideos = (q: string, limit = 20, cursor?: string) => {
  const params: Record<string, string> = { q, limit: String(limit) };
  if (cursor) params.cursor = cursor;
  return api.get("/ui/search/videos", params);
};
```

### 7.6 React Query Hook

```typescript
export const useGlobalSearch = (query: string, limit = 5) =>
  useQuery({
    queryKey: ["search", query, limit],
    queryFn: () => globalSearch(query, undefined, limit),
    enabled: query.length >= 2,
    staleTime: 60_000,
    keepPreviousData: true,
  });
```

---

## 8. Security & Privacy

### 8.1 Authorization

- All search endpoints use `require_ui_session` (cookie auth + CSRF for non-GET is N/A since these are GET endpoints).
- File search is scoped to the requesting user's files only (enforced by `search_prefix()` and `search_text()` which require `user` parameter).
- Post search only returns published, public posts. Scheduled/draft posts excluded.
- Catalog search respects visibility settings (subscription-gated catalogs hidden from non-subscribers).
- User search does not expose email addresses to non-admin users. Admin search includes email matching.

### 8.2 Privacy

- Search queries are not logged to DynamoDB (only standard access logs via metrics.py).
- Search does not expose locked post content (body shown as `"[Locked]"` in snippets).
- Blocked users' content is filtered from search results (uses `get_blocked_set()` from blocking service).
- File names/content are never exposed to other users (file search is strictly user-scoped).

### 8.3 Rate Limiting

- 30 search requests per minute per user. Uses existing `check_rate_limit()` from `app/services/rate_limiter.py`.
- Query length: 1-200 characters. Queries shorter than 2 characters skip module fan-out (only page navigation returned).
- Backend applies per-module timeouts (2 seconds each) to prevent a slow module from blocking the entire search.
- Failed modules do not leak error details to the client (generic "partial results" flag).

### 8.4 Input Sanitization

```python
def _sanitize_search_query(q: str) -> str:
    """Remove control characters and excessive whitespace."""
    q = re.sub(r"[\x00-\x1f\x7f]", "", q)  # Remove control chars
    q = re.sub(r"\s+", " ", q).strip()
    return q[:200]  # Hard cap at 200 chars
```

### 8.5 curl Examples

```bash
# Unified search (all types)
curl -s -b cookies.txt \
  "http://localhost:8000/ui/search?q=photography&limit=5" | jq .

# Search with type filter
curl -s -b cookies.txt \
  "http://localhost:8000/ui/search?q=photography&types=users,posts&limit=10" | jq .

# Full post search with pagination
curl -s -b cookies.txt \
  "http://localhost:8000/ui/search/posts?q=photography&limit=20" | jq .

# Video search
curl -s -b cookies.txt \
  "http://localhost:8000/ui/search/videos?q=tutorial&limit=10" | jq .
```

---

## 9. Performance & Scalability

### 9.1 DynamoDB Read/Write Estimates

| Operation | RCU (per module) | Total RCU (5 modules) | Latency |
|-----------|-----------------|----------------------|---------|
| User search | 5-10 RCU (indexed query) | - | <200ms |
| Post search (scan, 100K posts) | 200-400 RCU (scan pages) | - | <500ms |
| Video search (scan, 10K videos) | 20-40 RCU | - | <300ms |
| Catalog search (scan) | 20-40 RCU | - | <200ms |
| File search (prefix query) | 5-10 RCU | - | <300ms |
| **Total per search request** | - | ~300-500 RCU | ~500ms (parallel) |

### 9.2 Latency Budget

The aggregated search must return within 3 seconds. Per-module timeout is 2 seconds. Modules that time out return empty results; the response includes a `partial: true` flag.

| Module | Expected Latency | Strategy |
|--------|-----------------|----------|
| Users | <200ms | Existing indexed search (GSI on display_name tokens) |
| Posts | <500ms | Token filter on scan (short-term); search token GSI (long-term) |
| Videos | <300ms | Scan VideoMetadata table with title/description filter |
| Catalog | <200ms | Existing `_catalog_matches()` scan + filter |
| Files | <300ms | Existing `search_prefix()` (PK query) / `search_text()` (token query) |

### 9.3 Parallelization

The backend uses `concurrent.futures.ThreadPoolExecutor` (since DDB calls via boto3 are synchronous) to execute all module searches in parallel:

```python
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError

async def search_aggregator(q: str, user_id: str, types: List[str], limit: int) -> dict:
    results = {}
    timeout_sec = S.search_per_module_timeout_ms / 1000

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {}
        if "users" in types:
            futures[executor.submit(search_users, q, viewer_id=user_id, limit=limit)] = "users"
        if "posts" in types:
            futures[executor.submit(_search_posts, q, user_id=user_id, limit=limit)] = "posts"
        if "videos" in types:
            futures[executor.submit(_search_videos, q, limit=limit)] = "videos"
        if "catalog" in types:
            futures[executor.submit(_search_catalog_internal, q, limit=limit)] = "catalog"
        if "files" in types:
            futures[executor.submit(_search_files, q, user_id=user_id, limit=limit)] = "files"

        for future in as_completed(futures, timeout=timeout_sec):
            module_name = futures[future]
            try:
                results[module_name] = future.result()
            except TimeoutError:
                results[module_name] = {"items": [], "total_estimate": 0, "has_more": False}
            except Exception:
                results[module_name] = {"items": [], "total_estimate": 0, "has_more": False}

    return results
```

Total latency equals the slowest module (plus overhead), not the sum.

### 9.4 Caching

- React Query caches search results for 60 seconds (`staleTime: 60_000`). This prevents re-fetching on tab switches within the SearchPage.
- `keepPreviousData: true` ensures smooth UX when typing (old results stay visible while new query loads).
- Backend does not cache search results (each search is fresh).
- For high-traffic deployments, consider a Redis/ElastiCache layer for popular queries (cache key = `search:{q}:{types}:{user_id}`, TTL = 30s).

### 9.5 Post Search Scaling Path

DynamoDB scan for post search is O(table_size). For <100K posts, this completes in <500ms. For larger scale:

| Phase | Approach | Post Count | Latency |
|-------|----------|------------|---------|
| 1 (MVP) | Scan + FilterExpression on `body_plain` | <100K | <500ms |
| 2 | Search token GSI (`GSI3PK=POSTSEARCH`) | 100K-1M | <200ms |
| 3 | DynamoDB Streams -> OpenSearch | >1M | <100ms |

Phase 1 implementation:
```python
def _search_posts(q: str, user_id: str, limit: int = 5) -> dict:
    tokens = q.lower().split()[:5]  # Cap at 5 search terms
    filter_expr = " AND ".join(f"contains(body_plain, :t{i})" for i, _ in enumerate(tokens))
    expr_values = {f":t{i}": tok for i, tok in enumerate(tokens)}
    expr_values[":meta"] = "META"
    expr_values[":post_prefix"] = "POST#"

    matches = []
    last_key = None
    pages = 0
    while len(matches) < limit and pages < 4:  # Cap at 4 scan pages
        kwargs = {
            "FilterExpression": f"sk = :meta AND begins_with(pk, :post_prefix) AND {filter_expr}",
            "ExpressionAttributeValues": expr_values,
            "Limit": 500,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.app_single.scan(**kwargs)
        for item in resp.get("Items", []):
            if item.get("visibility") != "public":
                continue
            matches.append(_post_to_search_result(item))
            if len(matches) >= limit:
                break
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        pages += 1

    return {"items": matches, "total_estimate": len(matches), "has_more": last_key is not None}
```

---

## 10. Migration & Rollback

### 10.1 Feature Flag

`GLOBAL_SEARCH_ENABLED` (default `true`). When false:
- `/ui/search` endpoint returns 404
- Header search bar only shows page navigation (existing behavior)
- `/search` route hidden

### 10.2 Rollback

- Set `GLOBAL_SEARCH_ENABLED=false`. Reverts to per-module search only.
- No data changes needed. No new DDB entities are created by this feature (it only reads).

---

## 11. Testing Strategy

### 11.1 Unit Tests (pytest)

**File:** `tests/test_global_search.py`

| # | Test | Assertion |
|---|------|-----------|
| 1 | Aggregator returns results from all 5 modules | Response has keys: users, posts, videos, catalog, files |
| 2 | Type filter `types=users` queries only users | Only `users` key has items; others are empty |
| 3 | Type filter `types=posts,catalog` queries two modules | Only posts and catalog have items |
| 4 | Module timeout returns partial results | Mock slow module; response has `partial: true` |
| 5 | Post search finds matching post body | Post with "photography" in body appears in results.posts |
| 6 | Post search excludes unpublished posts | Scheduled post not in results |
| 7 | Post search excludes locked post body | Locked post snippet is "[Locked]" |
| 8 | File search scoped to requesting user | Alice's files not in Bob's search results |
| 9 | Empty query returns 400 | `q=""` -> 400 status |
| 10 | Query too long returns 400 | 201-char query -> 400 |
| 11 | Video search finds by title match | Video with "tutorial" in title appears in results.videos |
| 12 | Video search finds by description match | Video with "photography" in description appears |
| 13 | Catalog search finds by item name | Item "Headphones" found by "head" query |
| 14 | User search finds by display name | User "Alice" found by "ali" query |
| 15 | Blocked user filtered from results | Alice blocks Bob; search for Bob returns empty users |
| 16 | Search result shape is correct | Each item has type, id, title, snippet, url keys |
| 17 | Limit parameter respected | `limit=2` returns at most 2 per module |

```python
class TestSearchAggregator:
    def test_all_modules(self, client, auth_headers, seeded_content):
        resp = client.get("/ui/search?q=test&limit=5", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "results" in data
        for key in ("users", "posts", "videos", "catalog", "files"):
            assert key in data["results"]
            assert "items" in data["results"][key]
            assert "total_estimate" in data["results"][key]
            assert "has_more" in data["results"][key]

    def test_type_filter(self, client, auth_headers):
        resp = client.get("/ui/search?q=test&types=users&limit=5", headers=auth_headers)
        data = resp.json()
        # Only users should have items; others should be empty
        assert len(data["results"]["posts"]["items"]) == 0
        assert len(data["results"]["videos"]["items"]) == 0

    def test_empty_query(self, client, auth_headers):
        resp = client.get("/ui/search?q=", headers=auth_headers)
        assert resp.status_code in (400, 422)

    def test_limit_respected(self, client, auth_headers, many_posts):
        resp = client.get("/ui/search?q=test&types=posts&limit=2", headers=auth_headers)
        data = resp.json()
        assert len(data["results"]["posts"]["items"]) <= 2


class TestPostSearch:
    def test_finds_by_body(self, client, auth_headers, post_with_keyword):
        resp = client.get("/ui/search/posts?q=photography&limit=5", headers=auth_headers)
        assert resp.status_code == 200
        posts = resp.json()["posts"]
        assert any("photography" in p.get("body_snippet", "").lower() for p in posts)

    def test_excludes_locked_body(self, client, auth_headers, locked_post):
        resp = client.get("/ui/search/posts?q=secret&limit=5", headers=auth_headers)
        posts = resp.json()["posts"]
        locked = [p for p in posts if p["post_id"] == locked_post["post_id"]]
        if locked:
            assert locked[0]["body_snippet"] == "[Locked]"

    def test_pagination(self, client, auth_headers, many_posts):
        resp1 = client.get("/ui/search/posts?q=test&limit=3", headers=auth_headers)
        data1 = resp1.json()
        assert len(data1["posts"]) == 3
        cursor = data1["next_cursor"]
        assert cursor is not None
        resp2 = client.get(f"/ui/search/posts?q=test&limit=3&cursor={cursor}", headers=auth_headers)
        data2 = resp2.json()
        ids1 = {p["post_id"] for p in data1["posts"]}
        ids2 = {p["post_id"] for p in data2["posts"]}
        assert ids1.isdisjoint(ids2)  # No overlap
```

### 11.2 E2E Tests

**Test File:** `frontend/e2e/global-search.spec.ts`

**Section 1: Unified Search API (7 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | Search returns results across types | 200; response.results has users/posts/videos/catalog/files keys |
| 2 | At least one module returns items | Seeded data ensures users module returns Alice/Bob |
| 3 | Type filter restricts results | `types=users` -> only users.items non-empty |
| 4 | Empty query returns 400 | 400 response with detail |
| 5 | Search results have correct shape | Each item has type, id, title, url fields |
| 6 | Post search finds seeded post | Create post with unique body; search returns it in results.posts |
| 7 | File search scoped to user | Upload Alice file; Bob search same name -> file not in Bob's results.files |

**Section 2: Post Search API (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 8 | Full post search with pagination | `GET /ui/search/posts?q=keyword&limit=3` returns 3 posts |
| 9 | Post search cursor works | Second page has different post_ids (no overlap with first) |
| 10 | Locked post body hidden in results | Post with `lock_price_cents=100`; snippet is "[Locked]" |
| 11 | Unpublished post not in results | Post with `send_at` in future not returned |
| 12 | Search is case-insensitive | Query "PHOTOGRAPHY" finds post with "photography" in body |

**Section 3: Video Search API (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 13 | Video search finds by title | `GET /ui/search/videos?q=tutorial` returns video with "tutorial" in title |
| 14 | Video search returns correct shape | Each result has type="video", id, title, url |
| 15 | Video search with no matches | Gibberish query returns `{ videos: [] }` |

**Section 4: Search Page UI (6 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 16 | Search page loads from URL param | Navigate to `/search?q=test`; input pre-filled with "test"; results shown |
| 17 | Tab switching works | Click "Users" tab; only user results section visible |
| 18 | "All" tab shows all types | "All" tab shows at least 2 result sections |
| 19 | "View all" link navigates to typed tab | Click "View all posts"; Posts tab becomes active |
| 20 | Clicking user result navigates to profile | Click user result; navigates to `/discover` or profile page |
| 21 | Empty results shows empty state | Search for `zzz_xyznonexist_${TS}`; "No results found" message visible |

**Section 5: Header Search Integration (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 22 | Ctrl+K opens search dialog | `page.keyboard.press("Control+k")`; CommandDialog visible |
| 23 | Page navigation still works | Type "Messages"; "Messages" page item visible; click navigates to `/messages` |
| 24 | Typing shows content results below pages | Type "alice"; "Users" group heading visible with matching result |
| 25 | "View all results" navigates to search page | Click "View all results for ..."; URL becomes `/search?q=alice`; page renders |

---

## 11.3 Pydantic Models

### Request (Query Parameters)

```python
class GlobalSearchParams(BaseModel):
    q: str = Field(..., min_length=1, max_length=200)
    types: str = Field(default="users,posts,videos,catalog,files")
    limit: int = Field(default=5, ge=1, le=20)

    @field_validator("types")
    @classmethod
    def validate_types(cls, v: str) -> str:
        allowed = {"users", "posts", "videos", "catalog", "files"}
        requested = {t.strip() for t in v.split(",")}
        if not requested.issubset(allowed):
            raise ValueError(f"Invalid types: {requested - allowed}")
        return v
```

### Response Models

```python
class SearchResultItem(BaseModel):
    type: str  # "user", "post", "video", "catalog", "file"
    id: str
    title: str
    snippet: Optional[str] = None
    thumbnail_url: Optional[str] = None
    url: str
    meta: Dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[str] = None

class SearchResultSection(BaseModel):
    items: List[SearchResultItem]
    total_estimate: int
    has_more: bool

class GlobalSearchOut(BaseModel):
    query: str
    results: Dict[str, SearchResultSection]
    partial: bool = False  # True if any module timed out

class PostSearchOut(BaseModel):
    posts: List[Dict[str, Any]]
    next_cursor: Optional[str] = None
    total_estimate: int
```

### TypeScript (already defined in section 7.5, cross-reference)

The TypeScript interfaces are in `frontend/src/api/endpoints/search.ts`. Key types: `SearchResultItem`, `SearchResultSection`, `SearchResponse`.

---

## 11.4 Component Tree

### SearchPage (`/search`)

```
SearchPage
  |-- PageHeader
  |     |-- h1: "Search"
  |     |-- SearchInput (controlled, pre-filled from URL ?q= param)
  |           |-- useSearchParams() to read/write q
  |           |-- onSubmit updates URL and triggers useGlobalSearch
  |-- Tabs (shadcn Tabs)
  |     |-- TabsList
  |     |     |-- TabsTrigger "All"
  |     |     |-- TabsTrigger "Posts" (with count badge)
  |     |     |-- TabsTrigger "Users" (with count badge)
  |     |     |-- TabsTrigger "Videos" (with count badge)
  |     |     |-- TabsTrigger "Catalog" (with count badge)
  |     |     |-- TabsTrigger "Files" (with count badge)
  |     |-- TabsContent "all"
  |     |     |-- SearchSectionCard "Users" (top 3)
  |     |     |     |-- UserSearchResult[]
  |     |     |     |-- "View all N users" link (onClick -> switch to Users tab)
  |     |     |-- SearchSectionCard "Posts" (top 3)
  |     |     |     |-- PostSearchResult[]
  |     |     |     |-- "View all N posts" link
  |     |     |-- SearchSectionCard "Videos" (top 3)
  |     |     |-- SearchSectionCard "Catalog" (top 3)
  |     |     |-- SearchSectionCard "Files" (top 3)
  |     |-- TabsContent "posts"
  |     |     |-- PostSearchResult[] (full list, useInfiniteQuery)
  |     |     |-- LoadMore button
  |     |-- TabsContent "users" / "videos" / "catalog" / "files" (similar)
  |-- EmptyState (when all sections empty)
        |-- SearchX icon
        |-- "No results found for '{query}'"
```

### Enhanced Header CommandDialog

```
CommandDialog (existing, enhanced)
  |-- CommandInput (placeholder "Search content and pages...")
  |-- CommandList
        |-- CommandGroup "Pages" (existing)
        |     |-- CommandItem[] (from SEARCH_PAGES array)
        |-- NEW: CommandGroup "Users" (if searchResults?.users?.items?.length > 0)
        |     |-- CommandItem[] (user avatar + display_name)
        |-- NEW: CommandGroup "Posts" (if searchResults?.posts?.items?.length > 0)
        |     |-- CommandItem[] (post title or snippet)
        |-- NEW: CommandGroup "Catalog" (if results)
        |     |-- CommandItem[] (item name + price)
        |-- NEW: CommandSeparator
        |-- NEW: CommandGroup
              |-- CommandItem "View all results for '{query}'" -> navigate(/search?q=...)
```

---

## 12. Open Questions & Risks

### 12.1 Unresolved Decisions

1. **Search ranking algorithm**: How to rank results across different types? Recommendation: each module scores its own results; the aggregator interleaves by score in the "All" tab, or groups by type.
2. **Post search implementation**: Scan-based (simple, slow at scale) vs. token-indexed (complex, fast)? Recommendation: scan-based for Phase 1; add search token GSI in Phase 2 if post count exceeds 50K.
3. **Search history**: Should we save recent searches? Recommendation: Phase 2. Store client-side in localStorage first.
4. **Video search**: Videos have `title` and `description` fields but no text search endpoint. Add a simple scan-based search or reuse the gallery filter.

### 12.2 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Post search scan too slow | Medium | High | 2-second timeout per module; fall back to empty with partial flag; add search index in Phase 2 |
| One slow module blocks response | Low | Medium | asyncio.gather with per-module timeout; return partial results |
| Search result relevance poor | Medium | Medium | Module-specific scoring; user can switch tabs for focused search |
| GSI3 conflict for post search tokens | Medium | Low | Check GSI3 usage; if conflicted, use table scan instead |

---

## 13. Files to Create

| File | Purpose |
|------|---------|
| `app/routers/search.py` | Unified search endpoint + post/video search |
| `app/services/search_aggregator.py` | Fan-out to per-module searches, merge results |
| `frontend/src/pages/search/SearchPage.tsx` | Search results page with tabs |
| `frontend/src/api/endpoints/search.ts` | API client for unified search |
| `frontend/e2e/global-search.spec.ts` | E2E tests |

## 14. Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register search router |
| `app/core/settings.py` | Add `global_search_enabled: bool`, `search_per_module_timeout_ms: int` |
| `frontend/src/App.tsx` | Add `/search` route (after line 115) |
| `frontend/src/components/layout/Header.tsx` | Enhance CommandDialog with content search results (lines 364-386) |
| `frontend/src/api/types.ts` | Add `SearchResultItem`, `SearchResponse` interfaces |
| `frontend/src/components/layout/Sidebar.tsx` | No change needed (search is accessed via header, not sidebar) |

---

## 15. Dependencies

- **Discovery service (existing)**: `app/services/discovery.py:99` -- `search_users()` provides user search.
- **Catalog router (existing)**: `app/routers/catalog.py:379-408` -- `search_items()` provides catalog search.
- **File manager (existing)**: `app/services/filemanager.py:947,1861` -- `search_prefix()` and `search_text()` provide file search.
- **Alerts router (existing)**: `app/routers/alerts.py:124-125` -- `search_alerts()` (optional inclusion).
- **cmdk/shadcn (existing)**: `cmdk` is already installed and used for the command palette in Header.tsx.

---

## 16. Acceptance Criteria

1. `GET /ui/search?q=photography` returns results across users, posts, videos, catalog, and files.
2. Each result type is in its own section with `items`, `total_estimate`, and `has_more`.
3. Type filter (`types=users,posts`) restricts which modules are searched.
4. `/search` page shows tabbed results with All, Posts, Users, Videos, Catalog, Files tabs.
5. Ctrl+K / Cmd+K opens enhanced search that shows content results alongside page navigation.
6. "View all results" in header search navigates to `/search?q=...`.
7. Post search only returns published, public posts; locked post bodies are redacted.
8. File search is scoped to the requesting user's files.
9. Search completes within 3 seconds; modules that time out return empty with `partial: true`.
10. Rate limit of 30 searches per minute per user is enforced.

---


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_global_search.py`

| # | Function | Assertion |
|---|----------|-----------|
| 1 | `test_aggregator_returns_results_from_all_modules` | Aggregator returns results from all modules verified |
| 2 | `test_type_filter_users_only` | Type filter users only verified |
| 3 | `test_type_filter_posts_and_catalog` | Type filter posts and catalog verified |
| 4 | `test_module_timeout_returns_partial_results` | Module timeout returns partial results verified |
| 5 | `test_post_search_finds_matching_body` | Post search finds matching body verified |
| 6 | `test_post_search_excludes_unpublished` | Post search excludes unpublished verified |
| 7 | `test_post_search_excludes_locked_body` | Post search excludes locked body verified |
| 8 | `test_file_search_scoped_to_requesting_user` | File search scoped to requesting user verified |
| 9 | `test_empty_query_returns_400` | Empty query returns 400 verified |
| 10 | `test_query_too_long_returns_400` | Query too long returns 400 verified |

**Mocking**: All DynamoDB tables mocked via `moto`; profile lookups patched via `unittest.mock.patch`.

### Integration Tests

1. Search aggregator fans out to users + posts + files in parallel; results merged within 3s timeout
2. Post search finds post by body keyword across app_single_table scan
3. File search scoped to authenticated user — Alice's files not in Bob's results
4. Locked post body redacted as [Locked] in search results

### E2E Tests (Playwright)

**File**: `frontend/e2e/global-search.spec.ts`
**Sections**: 1-5 (25 tests)

**Auth pattern**: `injectAuth(page, identity)` for cookie auth; `x-csrf-token` header for POST/PUT/DELETE mutations.

| # | Test | Assertion |
|---|------|-----------|
| 1 | Search returns results across types | 200; results has users/posts/videos/catalog/files |
| 2 | Type filter restricts results | types=users -> only users non-empty |
| 3 | Empty query returns 400 | 400 response |
| 4 | Post search finds seeded post | Unique body keyword found in results.posts |
| 5 | File search scoped to user | Alice file not in Bob's results |
| 6 | Full post search with pagination | limit=3 returns 3 posts + cursor |
| 7 | Search page loads from URL param | /search?q=test; input pre-filled; results shown |
| 8 | Tab switching works | Click Users tab; only user results visible |
| 9 | Ctrl+K opens search dialog | CommandDialog visible |
| 10 | View all results navigates to search page | URL becomes /search?q=... |

**Negative tests**: 400 empty query, 400 query >200 chars, 401 unauthenticated, 429 rate limited (30/min), 504 partial results on module timeout

**Edge cases**: Module timeout returns partial flag, search with special characters, blocked users filtered from results

### Test Data Requirements

- **DDB seeds**: Seeded posts with unique keywords; uploaded files for Alice; catalog items; user profiles
- **Test users**: Alice (searcher), Bob (content author)

### CI/Pipeline Considerations

- **Feature flags**: GLOBAL_SEARCH_ENABLED=true (default)
- **Serial execution**: Post search tests depend on seeded posts being indexed
- **Retry safety**: All tests are idempotent; use unique per-run identifiers (`TS` suffix) to avoid cross-run conflicts.

---

## Dependencies & Merge Safety

### Depends On

| Ticket/Component | Reason |
|------------------|--------|
| Discovery service (existing) | search_users() for user search results |
| Catalog router (existing) | search_items() for catalog search |
| File manager (existing) | search_prefix() and search_text() for file search |

### Depended On By

| Ticket | Reason |
|--------|--------|
| SOC-005 | Profile discovery through search results |

### Merge Strategy: **Independent**

Aggregates existing search endpoints. No schema changes. Safe to merge independently.

### Merge Checklist

- [ ] All unit tests pass (`just test`)
- [ ] All E2E tests pass (`just e2e`)
- [ ] Feature flag defaults to enabled in `.env.local.example`
- [ ] No breaking changes to existing API contracts
- [ ] DynamoDB table/GSI changes added to `scripts/local-ddb-init.py`
- [ ] Frontend types in `api/types.ts` match backend `models.py`
- [ ] New routes registered in `app/main.py` and `frontend/src/App.tsx`

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| No /search route in App.tsx | `frontend/src/App.tsx` | 153 | **OUTDATED** — `/search` route exists, lazy-loaded at line 54 |
| Search router registered | `app/main.py` | 73, 395 | **ALREADY IMPLEMENTED** |
| Search aggregator endpoint | `app/routers/search.py` | 797 (GET ""), 618 (_search_aggregator) | **ALREADY IMPLEMENTED** |
| Search history endpoints | `app/routers/search.py` | 820 (POST), 833 (GET), 843 (DELETE item), 855 (DELETE all) | **ALREADY IMPLEMENTED** |
| Per-module search: users | `app/routers/search.py` | 86 (_search_users) | **ALREADY IMPLEMENTED** |
| Per-module search: posts | `app/routers/search.py` | 113 (_search_posts) | **ALREADY IMPLEMENTED** |
| Per-module search: videos | `app/routers/search.py` | 490 (_search_videos) | **ALREADY IMPLEMENTED** |
| Per-module search: catalog | `app/routers/search.py` | 188 (_search_catalog) | **ALREADY IMPLEMENTED** |
| Per-module search: files | `app/routers/search.py` | 237 (_search_files) | **ALREADY IMPLEMENTED** |
| Per-module search: messages | `app/routers/search.py` | 262 (_search_messages) | **ALREADY IMPLEMENTED** |
| Per-module search: tickets | `app/routers/search.py` | 374 (_search_tickets) | **ALREADY IMPLEMENTED** |
| Per-module search: contacts | `app/routers/search.py` | 441 (_search_contacts) | **ALREADY IMPLEMENTED** |
| Per-module search: calendar | `app/routers/search.py` | 555 (_search_calendar) | **ALREADY IMPLEMENTED** |
| SearchPage frontend | `frontend/src/pages/search/SearchPage.tsx` | — | **ALREADY IMPLEMENTED** |
| Search API client | `frontend/src/api/endpoints/search.ts` | — | **ALREADY IMPLEMENTED** (per MEMORY.md search E2E tests) |
| Discovery search endpoint | `app/routers/discovery.py` | 19-27 | VERIFIED |
| Catalog search endpoint | `app/routers/catalog.py` | 379-408 | VERIFIED |
| app_single_table GSI3 exists | `scripts/local-ddb-init.py` | 223 | VERIFIED |
| Newsfeed router line count | `app/routers/newsfeed.py` | — | VERIFIED: 5954 lines (not 4998 as stated in ticket) |
