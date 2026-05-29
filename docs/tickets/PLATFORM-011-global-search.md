# PLATFORM-011: Unified Global Search — Cross-Domain Search with Categorized Results

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-28  
**Priority**: High  
**Estimated effort**: 10-14 days

---

## 1. Overview & Motivation

### The Gap

The platform currently has a two-tier search system: a lightweight command palette in the header (`frontend/src/components/layout/Header.tsx`, line 451) <!-- VERIFIED: Header.tsx:451 --> and a dedicated search page (`frontend/src/pages/search/SearchPage.tsx`). The backend aggregator (`app/routers/search.py`, line 248) <!-- VERIFIED: search.py:248 --> fans out across four domains --- users, posts, catalog, and files --- using a `ThreadPoolExecutor` with a 5-second timeout. However, critical content domains are missing from the search surface:

1. **Messages**: The messaging system has its own search infrastructure (`build_message_search_tokens` at `app/routers/messaging.py`, line 2646 <!-- VERIFIED: messaging.py:2646 -->; `_MSG_SEARCH_MAX_PREFIX_LEN = 8` at line 2657 <!-- VERIFIED: messaging.py:2657 -->; `MessageSearch` DynamoDB table at line 166 <!-- VERIFIED: messaging.py:166 -->) but it is not wired into the global search aggregator. Users must navigate to a specific conversation to search within it.

2. **Tickets**: Support tickets (`app/routers/tickets.py`) have title, description, and comment fields, but no search endpoint. Users must scroll through the ticket list to find past issues.

3. **Contacts**: Contact records have names, emails, and notes, but the contact search is not surfaced through the global search bar.

4. **Videos/VOD**: Video content (`app/routers/vod.py`) has titles and descriptions, but no integration with global search.

5. **Calendar events**: Calendar events have titles and descriptions but are not searchable from the header.

6. **Recent searches**: The command palette stores recent *commands* in `useUiStore` (`frontend/src/stores/uiStore.ts`, `recentCommands` at line 27) <!-- CORRECTED: was "line 28", actually line 27 -->, but does not persist or display recent *search queries*. Users cannot revisit previous searches.

7. **Search suggestions**: There is no autocomplete or typeahead for search queries. The current debounce-based content search (`Header.tsx`, line 139) <!-- VERIFIED: Header.tsx:139-141 --> fires after 300ms but returns raw results without ranking or suggestions.

### Why This Is Needed

1. **Discoverability**: Users currently need to know which page to visit before they can search within it. A unified search bar that covers all domains reduces cognitive load and speeds up navigation.
2. **Keyboard-first workflow**: Power users expect Cmd+K / Ctrl+K to be a single entry point for everything. The current command palette (`Header.tsx`, line 79 `SEARCH_PAGES`) only navigates to pages or executes fixed actions; it does not search content across domains.
3. **Engagement**: Cross-domain search increases content discovery. A user searching for "invoice" should find the relevant message, the billing ledger entry, and the related ticket --- all from one query.
4. **Parity with modern apps**: Slack, Notion, and Discord all offer unified global search. This is expected by users.

<!-- VERIFIED: SEARCH_PAGES at Header.tsx:79 contains 15 page entries -->

### Architecture After This Change

```
User types in search bar (Cmd+K or click)
    |
    v
CommandDialog (enhanced)
    |
    |--- Query length < 2: show recent searches + page navigation
    |--- Query length >= 2: debounce 300ms, then:
    |       |
    |       v
    |     GET /ui/search?q=...&types=users,posts,catalog,files,messages,tickets,contacts,videos
    |       |
    |       v
    |     _search_aggregator (ThreadPoolExecutor, max_workers=8)
    |       |--- _search_users()        [existing]
    |       |--- _search_posts()        [existing]
    |       |--- _search_catalog()      [existing]
    |       |--- _search_files()        [existing]
    |       |--- _search_messages()     [NEW: cross-conversation message search]
    |       |--- _search_tickets()      [NEW: ticket title + body]
    |       |--- _search_contacts()     [NEW: contact name + email + notes]
    |       |--- _search_videos()       [NEW: VOD title + description]
    |       |
    |       v
    |     Categorized results returned, rendered in CommandDialog tabs
    |
    |--- "View all results" link -> /search?q=...&tab=<type>
    |       |
    |       v
    |     SearchPage (enhanced)
    |       |--- Tab per domain (All, Users, Posts, Files, Messages, ...)
    |       |--- Paginated results per tab
    |       |--- Search history sidebar
```

### Request / Response Flow — Sequence Diagram

```
Browser                       FastAPI                         DynamoDB
   |                             |                               |
   |-- GET /ui/search?q=foo ---->|                               |
   |                             |-- validate session cookie ---->|
   |                             |<-- session record ------------|
   |                             |                               |
   |                             |-- ThreadPoolExecutor -------->|
   |                             |   |-- _search_users(foo) ---->|  (discovery table)
   |                             |   |-- _search_posts(foo) ---->|  (app_single_table scan)
   |                             |   |-- _search_catalog(foo) -->|  (catalog table)
   |                             |   |-- _search_files(foo) ---->|  (filemanager table)
   |                             |   |-- _search_messages(foo) ->|  (MessageSearch table)
   |                             |   |-- _search_tickets(foo) -->|  (tickets table)
   |                             |   |-- _search_contacts(foo) ->|  (contacts table)
   |                             |   |-- _search_videos(foo) --->|  (vod table)
   |                             |   |-- _search_calendar(foo) ->|  (calendar table)
   |                             |<-- all futures resolved ------|
   |                             |                               |
   |<-- JSON: {results, partial}-|                               |
   |                             |                               |
   |-- POST /ui/search/history ->|                               |
   |                             |-- put_item (TTL 90d) -------->|
   |<-- {ok: true, id: ...} -----|                               |
```

---

## 2. Current State Analysis

### 2.1 Backend Search Aggregator (`app/routers/search.py`)

The existing global search endpoint is at `GET /ui/search` <!-- VERIFIED: search.py -->. It accepts `q`, `types`, and `limit` query parameters. The `ALLOWED_TYPES` set (line 37) <!-- VERIFIED: search.py:37 --> contains `{"users", "posts", "catalog", "files"}` plus extended types (messages, tickets, contacts, videos, calendar) added at line 39.

The aggregator function `_search_aggregator` (line 618) <!-- VERIFIED: search.py:618 --> uses `ThreadPoolExecutor` with per-future timeouts and overall timeout. Each search module returns a dict with `items`, `total_estimate`, and `has_more` fields.

The result items are constructed via `_make_result_item()` (line 58) <!-- VERIFIED: search.py:58 --> which enforces a standard shape:

```python
def _make_result_item(
    *, type: str, id: str, title: str, snippet: str = "",
    thumbnail_url: Optional[str] = None, url: str = "", meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
```

The `_sanitize_query()` function (line 46) <!-- VERIFIED: search.py:46 --> does basic cleanup:

```python
def _sanitize_query(q: str) -> str:
    q = re.sub(r"[\x00-\x1f\x7f]", "", q)
    q = re.sub(r"\s+", " ", q).strip()
    return q[:200]
```

This strips control characters and collapses whitespace but does NOT perform Unicode normalization (NFC/NFKC), which means composed and decomposed forms of the same character may not match.

The `_search_posts` function (line 113) <!-- VERIFIED: search.py:113 --> uses a full table `Scan` with `FilterExpression` containing `contains(body_plain_lc, :tok)` for each query token. It pages through up to 4 scan pages of 500 items each (2000 items max). This is O(table-size), not O(results), and will degrade as the posts table grows.

The `_search_catalog` function (line 188) <!-- VERIFIED: search.py:188 --> similarly scans the catalog table with 200-item pages. The `_search_files` function (line 237) <!-- VERIFIED: search.py:237 --> delegates to `app.services.filemanager.search_prefix` which uses a prefix-based query (more efficient).

The `_search_users` function (line 86) <!-- VERIFIED: search.py:86 --> delegates to `app.services.discovery.search_users` which uses the discovery index.

### 2.2 Frontend Command Palette (`Header.tsx`)

The command palette is implemented using shadcn's `CommandDialog` component (line 451) <!-- VERIFIED: Header.tsx:451 -->. It combines three data sources:

1. **SEARCH_PAGES** (line 79) <!-- VERIFIED: Header.tsx:79 -->: Static list of 15 navigable pages.
2. **SEARCH_ACTIONS** (line 105) <!-- VERIFIED: Header.tsx:105 -->: 5 action commands (Toggle Dark Mode, New Message, New Post, Keyboard Shortcuts, Log Out).
3. **Content search** (line 153) <!-- CORRECTED: was "line 153", actual React Query at line 153-158 (queryKey at 154, queryFn at 155) -->: A React Query call to `globalSearch(debouncedSearchQuery, undefined, 3)` that fires when the debounced query is >= 2 characters.

Content results are rendered in separate `CommandGroup` sections for Users, Posts, Catalog (lines 528-577) <!-- VERIFIED: Header.tsx:528-577 -->. File results from the backend are not rendered in the palette (the `files` section has no UI group), meaning the backend returns file results but the frontend discards them.

The debounce timer is 300ms (`Header.tsx` line 139-141) <!-- CORRECTED: was "line 139-142", actually lines 139-141 -->:

```tsx
React.useEffect(() => {
  const timer = setTimeout(() => setDebouncedSearchQuery(searchQuery), 300);
  return () => clearTimeout(timer);
}, [searchQuery]);
```

The React Query config uses `staleTime: 60_000` (line 157) <!-- VERIFIED: Header.tsx:157 -->, which caches results for 60 seconds before refetching.

### 2.3 Frontend Search Page (`SearchPage.tsx`)

The dedicated search page uses the same `globalSearch` API endpoint. It renders results in a tabbed layout with `Tabs`/`TabsContent` components. Each tab shows a `SectionCard` with `ResultRow` items. The page reads the `q` parameter from the URL via `useSearchParams`.

The `ResultRow` component renders each result item with an icon, title, snippet, and type badge. The icon is determined by a `resultIcon(type)` function that maps type strings to lucide-react icons (`User`, `FileText`, `ShoppingBag`, `FolderOpen`). New types (message, ticket, contact, video, calendar) will need corresponding icons.

### 2.4 Message Search Infrastructure (`app/routers/messaging.py`)

Message search uses a DynamoDB table `MessageSearch` (line 166) <!-- VERIFIED: messaging.py:166 -->. The `build_message_search_tokens()` function (line 2646) <!-- VERIFIED: messaging.py:2646 --> generates prefix tokens, n-grams, and stemmed tokens for indexing. The `build_message_query_tokens()` function (line 2660) <!-- VERIFIED: messaging.py:2660 --> generates matching query tokens capped at `_MSG_SEARCH_MAX_PREFIX_LEN = 8`.

The search is currently conversation-scoped: you must know the `conversation_id` to search within it. There is no cross-conversation search endpoint. The `_message_search_enabled()` function (line 2677) <!-- VERIFIED: messaging.py:2677 --> gates the feature on both the `DDB_MESSAGE_SEARCH` environment variable and AWS credentials availability.

The MessageSearch table schema (from `scripts/local-ddb-init.py`):

```python
TableDef(
    name="MessageSearch",
    pk="token",
    sk="conversation_id#message_id",
)
```

Each token generated by `build_message_search_tokens` is stored as a separate item with the composite SK. Querying by token returns all `(conversation_id, message_id)` pairs containing that token.

### 2.5 Frontend Search API Client (`frontend/src/api/endpoints/search.ts`)

The `globalSearch` function (line 38) <!-- VERIFIED: search.ts:38 --> makes a `GET /ui/search` call with `q`, `types`, and `limit` parameters. The response type `GlobalSearchResponse` (line 23) <!-- CORRECTED: was "line 21", actually line 23 --> has hardcoded sections for `users`, `posts`, `catalog`, and `files` --- no messages, tickets, contacts, or videos.

```typescript
export interface SearchResultItem {
  type: "user" | "post" | "catalog" | "file";
  id: string;
  title: string;
  snippet: string;
  thumbnail_url?: string;
  url: string;
  meta?: Record<string, unknown>;
}

export interface GlobalSearchResponse {
  query: string;
  results: {
    users: SearchResultSection;
    posts: SearchResultSection;
    catalog: SearchResultSection;
    files: SearchResultSection;
  };
  partial?: boolean;
}
```

### 2.6 Recent Commands (`frontend/src/stores/uiStore.ts`)

The `uiStore` persists `recentCommands` (line 27) <!-- CORRECTED: was "line 28", actually line 27 --> as an array of up to 5 command labels in localStorage under the key `ui-store`. The `trackRecentCommand` function (line 62) <!-- VERIFIED: uiStore.ts:62-65 --> deduplicates and trims to 5 entries. This infrastructure can be extended to also store recent search queries.

The `partialize` function (line 85) <!-- VERIFIED: uiStore.ts:85 --> controls which fields are persisted to localStorage:

```typescript
partialize: (state) => ({
  theme: state.theme,
  sidebarCollapsed: state.sidebarCollapsed,
  recentCommands: state.recentCommands,
}),
```

New search-related fields must be added here for offline persistence.

### 2.7 Alert Stream for Search Suggestions

The alert SSE system (`useAlertStream.ts`, line 21) <!-- VERIFIED: useAlertStream.ts:21 --> demonstrates the SSE pattern used in the app. The search system could potentially use a similar streaming approach for real-time search suggestions, though the initial implementation will use standard REST + debounce.

### 2.8 DynamoDB Tables Involved in Search

| Table | PK | SK | Relevant Fields | Access Pattern |
|-------|----|----|-----------------|----------------|
| `app_single_table` | `POST#{post_id}` | `META` | `body_plain_lc`, `visibility`, `status` | Scan + FilterExpression |
| `discovery` | `user_id` | - | `display_name`, `description` | `search_users()` |
| `catalog` | `category_id` | `item_id` | `name`, `description`, `price_cents` | Scan + in-memory filter |
| `filemanager` | `owner#{user_id}` | `path` | `name`, `content_type` | `search_prefix()` query |
| `MessageSearch` | `token` | `{conv_id}#{msg_id}` | - | Query by token |
| `tickets` | `pk` | `sk` | `subject`, `description`, `status` | Scan + filter (new) |
| `contacts` | `owner_id` | `contact_id` | `display_name`, `email`, `notes` | Scan + filter (new) |
| `vod` | `user_id` | `video_id` | `title`, `description`, `status` | Scan + filter (new) |
| `calendar` | `calendar_id` | `event_id` | `title`, `description`, `start_ts` | Query + filter (new) |

---

## 3. Technical Design

### 3.1 Extended ALLOWED_TYPES

Update `app/routers/search.py` to add new search domains:

```python
ALLOWED_TYPES = {"users", "posts", "catalog", "files", "messages", "tickets", "contacts", "videos", "calendar"}
```

### 3.2 New Search Modules

#### 3.2.1 `_search_messages(q, user_id, limit)` --- Cross-Conversation Message Search

Leverages the existing `MessageSearch` DynamoDB table. The approach:

1. Query the `MessageSearch` table using `build_message_query_tokens(q)` to get matching `(conversation_id, message_id)` pairs.
2. Filter results to only conversations where `user_id` is a participant (authorization check).
3. Return result items with `type="message"`, the message text as snippet, and the conversation URL.

```python
def _search_messages(q: str, user_id: str, limit: int) -> Dict[str, Any]:
    """Cross-conversation message search using the MessageSearch token index."""
    if not _message_search_enabled():
        return _empty_section()

    from app.routers.messaging import build_message_query_tokens, _MSG_SEARCH_MAX_PREFIX_LEN
    from app.services.messaging import list_user_conversations

    tokens = build_message_query_tokens(q)
    if not tokens:
        return _empty_section()

    # Step 1: Get the user's conversation IDs for authorization
    user_convos = list_user_conversations(user_id, limit=500)
    allowed_conv_ids: set[str] = {c["conversation_id"] for c in user_convos}
    if not allowed_conv_ids:
        return _empty_section()

    # Step 2: Query MessageSearch table for each token
    candidate_pairs: Dict[str, set] = {}  # conv_id -> set of msg_ids
    msg_search_table = T.message_search

    for token in tokens[:3]:  # Limit to first 3 tokens to bound cost
        resp = msg_search_table.query(
            KeyConditionExpression=Key("token").eq(token),
            Limit=100,
        )
        for item in resp.get("Items", []):
            sk = item.get("conversation_id#message_id", "")
            parts = sk.split("#", 1)
            if len(parts) != 2:
                continue
            conv_id, msg_id = parts
            if conv_id not in allowed_conv_ids:
                continue
            if conv_id not in candidate_pairs:
                candidate_pairs[conv_id] = set()
            candidate_pairs[conv_id].add(msg_id)

    # Step 3: Fetch actual message records for top results
    results: List[Dict[str, Any]] = []
    for conv_id, msg_ids in list(candidate_pairs.items())[:limit]:
        for msg_id in list(msg_ids)[:1]:  # One message per conversation
            try:
                msg_item = T.messages.get_item(
                    Key={"conversation_id": conv_id, "message_id": msg_id}
                ).get("Item")
                if not msg_item:
                    continue

                text = msg_item.get("text", "")
                is_encrypted = bool(msg_item.get("encryption"))
                is_expired = bool(msg_item.get("expired_at"))

                if is_encrypted:
                    snippet = "[Encrypted message]"
                elif is_expired:
                    snippet = "[Expired message]"
                else:
                    snippet = text[:120] if text else ""

                sender_id = msg_item.get("sender_id", "")
                created_at = int(msg_item.get("created_at", 0))

                results.append(_make_result_item(
                    type="message",
                    id=msg_id,
                    title=f"Message in conversation",
                    snippet=snippet,
                    url=f"/messages/{conv_id}",
                    meta={
                        "conversation_id": conv_id,
                        "sender_id": sender_id,
                        "created_at": created_at,
                        "is_encrypted": is_encrypted,
                    },
                ))
            except Exception:
                logger.exception("Failed to fetch message %s/%s", conv_id, msg_id)
                continue

        if len(results) >= limit:
            break

    return {
        "items": results[:limit],
        "total_estimate": sum(len(ids) for ids in candidate_pairs.values()),
        "has_more": len(results) >= limit,
    }
```

**Authorization**: Each result must be checked against the conversation's participant list in the `Conversations` table. Messages from conversations the user is not part of must be excluded. The implementation above pre-fetches the user's conversation IDs and filters candidates against that set. This avoids per-message authorization checks, bounding authorization cost to a single `list_user_conversations` call.

**Performance note**: The `list_user_conversations` call with `limit=500` retrieves up to 500 conversations. For users with more conversations, we'd need pagination or a dedicated participant index. For the initial implementation, 500 is sufficient.

#### 3.2.2 `_search_tickets(q, user_id, limit)` --- Ticket Title + Body

Scans the `tickets` table for items where `subject` or `description` contains all query tokens. Filters to tickets created by `user_id` or assigned to `user_id`.

```python
def _search_tickets(q: str, user_id: str, limit: int) -> Dict[str, Any]:
    """Search tickets by subject and description text."""
    try:
        tokens = [t for t in re.findall(r"[a-z0-9@._-]+", q.lower()) if t]
        if not tokens:
            return _empty_section()

        matches: List[Dict[str, Any]] = []
        last_key = None
        pages = 0

        while len(matches) < limit and pages < 4:
            kwargs: Dict[str, Any] = {"Limit": 200}
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key

            resp = T.tickets.scan(**kwargs)
            for item in resp.get("Items", []):
                # Authorization: user must be creator or assignee
                creator = item.get("created_by", "")
                assignee = item.get("assigned_to", "")
                if creator != user_id and assignee != user_id:
                    continue

                # Text matching against subject + description
                haystack = " ".join([
                    str(item.get("subject", "")).lower(),
                    str(item.get("description", "") or "").lower(),
                ])
                if not all(tok in haystack for tok in tokens):
                    continue

                ticket_id = item.get("ticket_id", "")
                status = item.get("status", "open")
                space_id = item.get("space_id")

                matches.append(_make_result_item(
                    type="ticket",
                    id=ticket_id,
                    title=str(item.get("subject", "")),
                    snippet=str(item.get("description", "") or "")[:120],
                    url=f"/tickets/{ticket_id}",
                    meta={
                        "status": status,
                        "priority": item.get("priority", "normal"),
                        "space_id": space_id,
                        "created_by": creator,
                        "assigned_to": assignee,
                    },
                ))
                if len(matches) >= limit:
                    break

            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            pages += 1

        has_more = last_key is not None and len(matches) >= limit
        return {"items": matches, "total_estimate": len(matches), "has_more": has_more}
    except Exception:
        logger.exception("Ticket search failed")
        return _empty_section()
```

#### 3.2.3 `_search_contacts(q, user_id, limit)` --- Contact Name + Email

Queries the contacts table filtering on `display_name`, `email`, and `notes` fields. Scoped to the user's own contacts.

```python
def _search_contacts(q: str, user_id: str, limit: int) -> Dict[str, Any]:
    """Search user's contacts by name, email, and notes."""
    try:
        tokens = [t for t in re.findall(r"[a-z0-9@._-]+", q.lower()) if t]
        if not tokens:
            return _empty_section()

        # Query user's contacts partition
        resp = T.contacts.query(
            KeyConditionExpression=Key("owner_id").eq(user_id),
            Limit=500,
        )
        matches: List[Dict[str, Any]] = []
        for item in resp.get("Items", []):
            if item.get("deleted_at"):
                continue
            haystack = " ".join([
                str(item.get("display_name", "")).lower(),
                str(item.get("email", "") or "").lower(),
                str(item.get("notes", "") or "").lower(),
                str(item.get("phone", "") or "").lower(),
            ])
            if not all(tok in haystack for tok in tokens):
                continue

            contact_id = item.get("contact_id", "")
            matches.append(_make_result_item(
                type="contact",
                id=contact_id,
                title=str(item.get("display_name", "")),
                snippet=str(item.get("email", "") or ""),
                url=f"/contacts/{contact_id}",
                meta={
                    "email": item.get("email"),
                    "phone": item.get("phone"),
                },
            ))
            if len(matches) >= limit:
                break

        return {
            "items": matches[:limit],
            "total_estimate": len(matches),
            "has_more": len(matches) > limit,
        }
    except Exception:
        logger.exception("Contact search failed")
        return _empty_section()
```

#### 3.2.4 `_search_videos(q, user_id, limit)` --- VOD Title + Description

Scans the VOD table for items with matching `title` or `description`. Filters to public videos or videos owned by `user_id`.

```python
def _search_videos(q: str, user_id: str, limit: int) -> Dict[str, Any]:
    """Search VOD videos by title and description."""
    try:
        tokens = [t for t in re.findall(r"[a-z0-9@._-]+", q.lower()) if t]
        if not tokens:
            return _empty_section()

        matches: List[Dict[str, Any]] = []
        last_key = None
        pages = 0

        while len(matches) < limit and pages < 4:
            kwargs: Dict[str, Any] = {"Limit": 200}
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key

            resp = T.vod.scan(**kwargs)
            for item in resp.get("Items", []):
                # Authorization: public or owned by user
                visibility = item.get("visibility", "private")
                owner = item.get("user_id", "")
                if visibility != "public" and owner != user_id:
                    continue

                # Skip deleted/processing videos
                status = item.get("status", "")
                if status in ("deleted", "processing"):
                    continue

                haystack = " ".join([
                    str(item.get("title", "")).lower(),
                    str(item.get("description", "") or "").lower(),
                ])
                if not all(tok in haystack for tok in tokens):
                    continue

                video_id = item.get("video_id", "")
                matches.append(_make_result_item(
                    type="video",
                    id=video_id,
                    title=str(item.get("title", "")),
                    snippet=str(item.get("description", "") or "")[:120],
                    thumbnail_url=item.get("thumbnail_url"),
                    url=f"/videos/{video_id}",
                    meta={
                        "duration_seconds": int(item.get("duration_seconds", 0)),
                        "owner_id": owner,
                        "visibility": visibility,
                    },
                ))
                if len(matches) >= limit:
                    break

            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            pages += 1

        has_more = last_key is not None and len(matches) >= limit
        return {"items": matches, "total_estimate": len(matches), "has_more": has_more}
    except Exception:
        logger.exception("Video search failed")
        return _empty_section()
```

#### 3.2.5 `_search_calendar(q, user_id, limit)` --- Calendar Event Title

Queries the calendar table for events with matching `title` or `description`. Scoped to the user's own calendars.

```python
def _search_calendar(q: str, user_id: str, limit: int) -> Dict[str, Any]:
    """Search calendar events by title and description."""
    try:
        tokens = [t for t in re.findall(r"[a-z0-9@._-]+", q.lower()) if t]
        if not tokens:
            return _empty_section()

        # Get user's calendar IDs first
        cal_resp = T.calendar.query(
            KeyConditionExpression=Key("calendar_id").eq(f"USER#{user_id}"),
            Limit=50,
        )
        calendar_ids: List[str] = []
        for item in cal_resp.get("Items", []):
            cid = item.get("calendar_id", "")
            if cid:
                calendar_ids.append(cid)

        if not calendar_ids:
            # Fallback: search the user's default calendar
            calendar_ids = [f"CAL#{user_id}"]

        matches: List[Dict[str, Any]] = []
        for cal_id in calendar_ids[:10]:  # Cap calendars to prevent fan-out
            resp = T.calendar.query(
                KeyConditionExpression=Key("calendar_id").eq(cal_id),
                Limit=200,
            )
            for item in resp.get("Items", []):
                if not item.get("title"):
                    continue
                haystack = " ".join([
                    str(item.get("title", "")).lower(),
                    str(item.get("description", "") or "").lower(),
                    str(item.get("location", "") or "").lower(),
                ])
                if not all(tok in haystack for tok in tokens):
                    continue

                event_id = item.get("event_id", item.get("sk", ""))
                start_ts = int(item.get("start_ts", 0))

                matches.append(_make_result_item(
                    type="calendar",
                    id=event_id,
                    title=str(item.get("title", "")),
                    snippet=str(item.get("description", "") or "")[:120],
                    url=f"/calendar?event={event_id}",
                    meta={
                        "start_ts": start_ts,
                        "end_ts": int(item.get("end_ts", 0)),
                        "location": item.get("location"),
                        "calendar_id": cal_id,
                    },
                ))
                if len(matches) >= limit:
                    break

            if len(matches) >= limit:
                break

        return {
            "items": matches[:limit],
            "total_estimate": len(matches),
            "has_more": len(matches) >= limit,
        }
    except Exception:
        logger.exception("Calendar search failed")
        return _empty_section()
```

### 3.3 Updated Aggregator

The `_search_aggregator` function needs to be updated to include the new search modules and use a larger thread pool:

```python
def _search_aggregator(
    q: str,
    user_id: str,
    types: List[str],
    limit: int,
) -> Dict[str, Any]:
    """Fan out to per-module searches in parallel using ThreadPoolExecutor."""
    results: Dict[str, Any] = {}
    partial = False

    # Build map of search functions
    search_fns: Dict[str, Any] = {}
    if "users" in types:
        search_fns["users"] = lambda: _search_users(q, user_id, limit)
    if "posts" in types:
        search_fns["posts"] = lambda: _search_posts(q, user_id, limit)
    if "catalog" in types:
        search_fns["catalog"] = lambda: _search_catalog(q, limit)
    if "files" in types:
        search_fns["files"] = lambda: _search_files(q, user_id, limit)
    if "messages" in types:
        search_fns["messages"] = lambda: _search_messages(q, user_id, limit)
    if "tickets" in types:
        search_fns["tickets"] = lambda: _search_tickets(q, user_id, limit)
    if "contacts" in types:
        search_fns["contacts"] = lambda: _search_contacts(q, user_id, limit)
    if "videos" in types:
        search_fns["videos"] = lambda: _search_videos(q, user_id, limit)
    if "calendar" in types:
        search_fns["calendar"] = lambda: _search_calendar(q, user_id, limit)

    max_workers = min(len(search_fns), 8)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(fn): name for name, fn in search_fns.items()}
        for future in as_completed(futures, timeout=5):
            name = futures[future]
            try:
                results[name] = future.result(timeout=2)
            except Exception:
                logger.exception("Search module %s timed out or failed", name)
                results[name] = _empty_section()
                partial = True

    # Fill in empty sections for types not searched
    for t in ALLOWED_TYPES:
        if t not in results:
            results[t] = _empty_section()

    return {"results": results, "partial": partial}
```

### 3.4 Recent Searches

#### 3.4.1 Backend Storage

Add a new DDB item pattern in the `app_single_table`:

```
PK: SEARCH_HISTORY#{user_sub}
SK: TS#{timestamp}#{query_hash}
Attributes: query, ts, result_count, ttl
```

TTL set to 90 days. Maximum 50 entries per user.

**DynamoDB item schema**:

```python
{
    "pk":           "SEARCH_HISTORY#alice-user-sub-123",
    "sk":           "TS#1771234567#a1b2c3d4",      # timestamp + MD5(query)[:8]
    "query":        "invoice pdf",
    "ts":           1771234567,
    "result_count": 12,
    "ttl":          1771234567 + (90 * 86400),       # auto-expire after 90 days
}
```

The SK format uses zero-padded timestamp + query hash to ensure uniqueness and chronological ordering. `ScanIndexForward=False` returns most-recent-first.

**Deduplication logic**: Before writing a new history item, query for existing items with the same query text (hash match). If found, update the timestamp instead of creating a duplicate.

```python
import hashlib

def _query_hash(query: str) -> str:
    """Generate a short hash for deduplication."""
    return hashlib.md5(query.lower().strip().encode()).hexdigest()[:8]


def record_search_history(user_sub: str, query: str, result_count: int = 0) -> str:
    """Record a search query in user's search history. Deduplicates."""
    ts = now_ts()
    q_hash = _query_hash(query)
    history_id = f"TS#{ts:010d}#{q_hash}"

    # Check for existing entry with same query hash
    existing = tbl.query(
        KeyConditionExpression=Key("pk").eq(f"SEARCH_HISTORY#{user_sub}"),
        FilterExpression="contains(sk, :hash)",
        ExpressionAttributeValues={":hash": q_hash},
        Limit=1,
    ).get("Items", [])

    if existing:
        # Update timestamp of existing entry
        old_sk = existing[0]["sk"]
        tbl.delete_item(Key={"pk": f"SEARCH_HISTORY#{user_sub}", "sk": old_sk})

    tbl.put_item(Item={
        "pk": f"SEARCH_HISTORY#{user_sub}",
        "sk": history_id,
        "query": query.strip(),
        "ts": ts,
        "result_count": result_count,
        "ttl": ts + (90 * 86400),
    })

    # Enforce cap: delete oldest entries beyond 50
    _trim_search_history(user_sub, max_entries=50)

    return history_id


def list_search_history(user_sub: str, limit: int = 20) -> List[Dict[str, Any]]:
    """List recent search queries, newest first."""
    resp = tbl.query(
        KeyConditionExpression=Key("pk").eq(f"SEARCH_HISTORY#{user_sub}"),
        ScanIndexForward=False,
        Limit=min(limit, 50),
    )
    return [
        {
            "id": item["sk"],
            "query": item["query"],
            "ts": int(item["ts"]),
            "result_count": int(item.get("result_count", 0)),
        }
        for item in resp.get("Items", [])
    ]


def delete_search_history_item(user_sub: str, item_id: str) -> bool:
    """Delete a single search history item."""
    try:
        tbl.delete_item(
            Key={"pk": f"SEARCH_HISTORY#{user_sub}", "sk": item_id},
            ConditionExpression="attribute_exists(pk)",
        )
        return True
    except tbl.meta.client.exceptions.ConditionalCheckFailedException:
        return False


def clear_search_history(user_sub: str) -> int:
    """Delete all search history for a user. Returns count of deleted items."""
    resp = tbl.query(
        KeyConditionExpression=Key("pk").eq(f"SEARCH_HISTORY#{user_sub}"),
        ProjectionExpression="pk, sk",
    )
    items = resp.get("Items", [])
    for item in items:
        tbl.delete_item(Key={"pk": item["pk"], "sk": item["sk"]})
    return len(items)


def _trim_search_history(user_sub: str, max_entries: int = 50) -> None:
    """Evict oldest entries beyond max_entries."""
    resp = tbl.query(
        KeyConditionExpression=Key("pk").eq(f"SEARCH_HISTORY#{user_sub}"),
        ScanIndexForward=False,  # newest first
        ProjectionExpression="pk, sk",
    )
    items = resp.get("Items", [])
    if len(items) <= max_entries:
        return
    for item in items[max_entries:]:
        tbl.delete_item(Key={"pk": item["pk"], "sk": item["sk"]})
```

#### 3.4.2 Backend Endpoints

```
POST /ui/search/history          -- Record a search query
GET  /ui/search/history          -- List recent searches (limit=20)
DELETE /ui/search/history/{id}   -- Delete a single entry
DELETE /ui/search/history        -- Clear all search history
```

#### 3.4.3 Frontend Integration

The `uiStore` gains a new field `recentSearches: string[]` alongside the existing `recentCommands`. When the user submits a search query (presses Enter or clicks "View all results"), the query is recorded both locally and on the server. The command palette shows recent searches when the input is empty, below the "Recently Used" commands section.

### 3.5 Search Suggestions / Autocomplete

Phase 1 (this ticket) implements basic suggestions from:
- Recent search queries (from history)
- Page navigation matches (existing SEARCH_PAGES)
- Top-3 user/post results from the content search (already implemented)

Phase 2 (future ticket) would add server-side autocomplete using prefix indexes.

### 3.6 Enhanced Command Palette UI

The `CommandDialog` in `Header.tsx` gains:

1. **Recent Searches group**: Shown when query is empty, above Pages/Actions.
2. **Domain tabs**: When content results arrive, a row of filter tabs (All, Users, Posts, Files, Messages, ...) appears below the input.
3. **Message results group**: Shows sender name, conversation name, and message snippet.
4. **Ticket results group**: Shows ticket subject and status badge.
5. **"View all in [domain]" links**: Per-group link to the SearchPage filtered to that tab.

Proposed rendering for the enhanced palette:

```tsx
{/* Recent searches (shown when query is empty) */}
{!searchQuery && recentSearches.length > 0 && (
  <CommandGroup heading="Recent Searches">
    {recentSearches.map((query) => (
      <CommandItem key={query} onSelect={() => setSearchQuery(query)}>
        <Clock className="mr-2 h-4 w-4 text-muted-foreground" />
        <span>{query}</span>
        <button
          className="ml-auto text-muted-foreground hover:text-foreground"
          onClick={(e) => { e.stopPropagation(); removeRecentSearch(query); }}
        >
          <X className="h-3 w-3" />
        </button>
      </CommandItem>
    ))}
  </CommandGroup>
)}

{/* Message results */}
{searchResults?.results.messages.items.length > 0 && (
  <CommandGroup heading="Messages">
    {searchResults.results.messages.items.map((item) => (
      <CommandItem key={item.id} onSelect={() => navigate(item.url)}>
        <MessageSquare className="mr-2 h-4 w-4 text-muted-foreground" />
        <div className="flex flex-col">
          <span className="text-sm">{item.title}</span>
          <span className="text-xs text-muted-foreground">{item.snippet}</span>
        </div>
      </CommandItem>
    ))}
    <CommandItem onSelect={() => navigate(`/search?q=${searchQuery}&tab=messages`)}>
      <span className="text-xs text-muted-foreground">View all message results...</span>
    </CommandItem>
  </CommandGroup>
)}

{/* Ticket results */}
{searchResults?.results.tickets.items.length > 0 && (
  <CommandGroup heading="Tickets">
    {searchResults.results.tickets.items.map((item) => (
      <CommandItem key={item.id} onSelect={() => navigate(item.url)}>
        <Ticket className="mr-2 h-4 w-4 text-muted-foreground" />
        <div className="flex flex-col">
          <span className="text-sm">{item.title}</span>
          <span className="text-xs text-muted-foreground">{item.snippet}</span>
        </div>
        <Badge variant="outline" className="ml-auto text-[10px]">
          {item.meta?.status}
        </Badge>
      </CommandItem>
    ))}
  </CommandGroup>
)}
```

### 3.7 Enhanced SearchPage

The `SearchPage.tsx` gains:

1. **Additional tabs**: Messages, Tickets, Contacts, Videos, Calendar alongside existing Users, Posts, Catalog, Files.
2. **Pagination**: "Load more" button per tab (using `has_more` from the response).
3. **Search history sidebar**: Collapsible panel showing recent searches with click-to-rerun.

The tab definition expands to:

```tsx
const SEARCH_TABS = [
  { value: "all",      label: "All",       icon: Search },
  { value: "users",    label: "Users",     icon: User },
  { value: "posts",    label: "Posts",     icon: FileText },
  { value: "catalog",  label: "Catalog",   icon: ShoppingBag },
  { value: "files",    label: "Files",     icon: FolderOpen },
  { value: "messages", label: "Messages",  icon: MessageSquare },
  { value: "tickets",  label: "Tickets",   icon: Ticket },
  { value: "contacts", label: "Contacts",  icon: Users },
  { value: "videos",   label: "Videos",    icon: Play },
  { value: "calendar", label: "Calendar",  icon: CalendarIcon },
] as const;
```

### 3.8 Thread Pool Sizing

With 9 search domains (up from 4), increase `ThreadPoolExecutor(max_workers=8)` (from 4). The overall timeout stays at 5 seconds; individual future timeout stays at 2 seconds. Partial results are returned if some domains time out, with `partial: true` in the response.

### 3.9 Unicode Normalization

Update `_sanitize_query` to include NFC normalization:

```python
import unicodedata

def _sanitize_query(q: str) -> str:
    """Remove control characters, normalize Unicode, and collapse whitespace."""
    q = unicodedata.normalize("NFC", q)
    q = re.sub(r"[\x00-\x1f\x7f]", "", q)
    q = re.sub(r"\s+", " ", q).strip()
    return q[:200]
```

This ensures that "café" (e + combining acute) matches "cafe" (precomposed) consistently.

---

## 4. API Endpoints

### 4.1 Enhanced Global Search

```
GET /ui/search
  Query params:
    q: str (1-200 chars, required)
    types: str (comma-separated, default "users,posts,catalog,files,messages,tickets,contacts,videos,calendar")
    limit: int (1-20 per section, default 5)
  Auth: require_ui_session
  Response 200: {
    query: str,
    results: {
      users:    { items: [SearchResultItem], total_estimate: int, has_more: bool },
      posts:    { items: [SearchResultItem], total_estimate: int, has_more: bool },
      catalog:  { items: [SearchResultItem], total_estimate: int, has_more: bool },
      files:    { items: [SearchResultItem], total_estimate: int, has_more: bool },
      messages: { items: [SearchResultItem], total_estimate: int, has_more: bool },
      tickets:  { items: [SearchResultItem], total_estimate: int, has_more: bool },
      contacts: { items: [SearchResultItem], total_estimate: int, has_more: bool },
      videos:   { items: [SearchResultItem], total_estimate: int, has_more: bool },
      calendar: { items: [SearchResultItem], total_estimate: int, has_more: bool },
    },
    partial: bool
  }
  Response 400: { detail: "Query is empty" } | { detail: "Invalid search types: ..." }
```

**SearchResultItem schema** (per-item in each section):

```json
{
  "type": "message" | "ticket" | "contact" | "video" | "calendar" | "user" | "post" | "catalog" | "file",
  "id": "string (unique ID within type)",
  "title": "string (display title, max 120 chars)",
  "snippet": "string (preview text, max 120 chars)",
  "thumbnail_url": "string | null (URL for avatar/preview image)",
  "url": "string (relative navigation URL, e.g., /messages/conv123)",
  "meta": {
    // type-specific metadata:
    // message: { conversation_id, sender_id, created_at, is_encrypted }
    // ticket: { status, priority, space_id, created_by, assigned_to }
    // contact: { email, phone }
    // video: { duration_seconds, owner_id, visibility }
    // calendar: { start_ts, end_ts, location, calendar_id }
    // user: { follower_count, is_following }
    // post: { author_id, is_locked }
    // catalog: { price_cents, category_id }
    // file: { size }
  }
}
```

### 4.2 Search History

```
POST /ui/search/history
  Body: {
    query: str     (required, 1-200 chars)
    result_count: int  (optional, default 0)
  }
  Auth: require_ui_session (CSRF required for POST)
  Response 200: { ok: true, id: str }
  Response 400: { detail: "Query is empty" }

GET /ui/search/history
  Query params:
    limit: int (1-50, default 20)
  Auth: require_ui_session
  Response 200: {
    items: [
      {
        id: str,             // DDB SK, used for deletion
        query: str,          // the search query text
        ts: int,             // Unix timestamp when recorded
        result_count: int    // number of results at time of search
      }
    ]
  }

DELETE /ui/search/history/{id}
  Auth: require_ui_session (CSRF required for DELETE)
  Response 200: { ok: true }
  Response 404: { detail: "History item not found" }

DELETE /ui/search/history
  Auth: require_ui_session (CSRF required for DELETE)
  Response 200: { ok: true, deleted_count: int }
```

---

## 5. Frontend Components

### 5.1 Enhanced Header Command Palette

**File**: `frontend/src/components/layout/Header.tsx`

Changes to the `CommandDialog` (currently at line 451):

- Add a `RecentSearches` command group above Pages when query is empty.
- Add result groups for Messages, Tickets, Contacts, Videos, Calendar.
- Add domain filter chips below the `CommandInput`.
- Render message results with sender avatar, conversation name, and highlighted snippet.
- Render ticket results with status badge (open/closed/pending).

Icon mapping for new result types:

```tsx
function resultIcon(type: string) {
  switch (type) {
    case "user":     return <User className="h-4 w-4 text-muted-foreground shrink-0" />;
    case "post":     return <FileText className="h-4 w-4 text-muted-foreground shrink-0" />;
    case "catalog":  return <ShoppingBag className="h-4 w-4 text-muted-foreground shrink-0" />;
    case "file":     return <FolderOpen className="h-4 w-4 text-muted-foreground shrink-0" />;
    case "message":  return <MessageSquare className="h-4 w-4 text-muted-foreground shrink-0" />;
    case "ticket":   return <Ticket className="h-4 w-4 text-muted-foreground shrink-0" />;
    case "contact":  return <Users className="h-4 w-4 text-muted-foreground shrink-0" />;
    case "video":    return <Play className="h-4 w-4 text-muted-foreground shrink-0" />;
    case "calendar": return <CalendarIcon className="h-4 w-4 text-muted-foreground shrink-0" />;
    default:         return <Search className="h-4 w-4 text-muted-foreground shrink-0" />;
  }
}
```

### 5.2 Enhanced Search Page

**File**: `frontend/src/pages/search/SearchPage.tsx`

- Add tabs for each new domain.
- Add `useInfiniteQuery` for paginated results per tab.
- Add search history sidebar component.
- Add keyboard navigation (up/down arrows, Enter to navigate to result).

Pagination implementation for per-tab "Load more":

```tsx
function SearchTabContent({ type, query }: { type: string; query: string }) {
  const navigate = useNavigate();
  const [page, setPage] = useState(1);
  const limit = 10;

  const searchQuery = useQuery({
    queryKey: ["search", query, type, page],
    queryFn: () => globalSearch(query, type, limit * page),
    enabled: query.length >= 2,
  });

  const section = searchQuery.data?.results[type as keyof typeof searchQuery.data.results];
  if (!section) return null;

  return (
    <div className="space-y-2">
      {section.items.map((item) => (
        <ResultRow key={item.id} item={item} onClick={() => navigate(item.url)} />
      ))}
      {section.has_more && (
        <Button variant="outline" size="sm" onClick={() => setPage((p) => p + 1)}>
          Load more
        </Button>
      )}
    </div>
  );
}
```

### 5.3 New: SearchHistorySidebar Component

**File**: `frontend/src/components/shared/SearchHistorySidebar.tsx`

- Displays recent search queries.
- Click to re-execute search.
- "Clear history" button.
- Collapsible on mobile.

```tsx
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Clock, X, Trash2, ChevronDown, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { getSearchHistory, deleteSearchHistoryItem, clearSearchHistory } from "@/api/endpoints/search";

interface SearchHistorySidebarProps {
  onSelectQuery: (query: string) => void;
}

export function SearchHistorySidebar({ onSelectQuery }: SearchHistorySidebarProps) {
  const queryClient = useQueryClient();
  const [collapsed, setCollapsed] = useState(false);

  const historyQuery = useQuery({
    queryKey: ["search-history"],
    queryFn: () => getSearchHistory(20),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteSearchHistoryItem(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["search-history"] }),
  });

  const clearMut = useMutation({
    mutationFn: clearSearchHistory,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["search-history"] }),
  });

  const items = historyQuery.data?.items ?? [];

  return (
    <div className="w-64 border-r border-border p-4">
      <div className="flex items-center justify-between mb-3">
        <button onClick={() => setCollapsed(!collapsed)} className="flex items-center gap-1 text-sm font-medium">
          {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          Recent Searches
        </button>
        {items.length > 0 && (
          <Button variant="ghost" size="sm" onClick={() => clearMut.mutate()}>
            <Trash2 className="h-3 w-3" />
          </Button>
        )}
      </div>
      {!collapsed && (
        <div className="space-y-1">
          {items.map((item) => (
            <div key={item.id} className="flex items-center gap-2 group">
              <button
                className="flex-1 flex items-center gap-2 rounded px-2 py-1 text-sm hover:bg-accent text-left"
                onClick={() => onSelectQuery(item.query)}
              >
                <Clock className="h-3 w-3 text-muted-foreground shrink-0" />
                <span className="truncate">{item.query}</span>
              </button>
              <button
                className="opacity-0 group-hover:opacity-100 p-1"
                onClick={() => deleteMut.mutate(item.id)}
              >
                <X className="h-3 w-3 text-muted-foreground" />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
```

### 5.4 Updated Search API Client

**File**: `frontend/src/api/endpoints/search.ts`

- Extend `GlobalSearchResponse` type to include `messages`, `tickets`, `contacts`, `videos`, `calendar` sections.
- Add `recordSearchHistory()`, `getSearchHistory()`, `deleteSearchHistory()`, `clearSearchHistory()` functions.

```typescript
import { api } from "../client";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SearchResultType =
  | "user" | "post" | "catalog" | "file"
  | "message" | "ticket" | "contact" | "video" | "calendar";

export interface SearchResultItem {
  type: SearchResultType;
  id: string;
  title: string;
  snippet: string;
  thumbnail_url?: string;
  url: string;
  meta?: Record<string, unknown>;
}

export interface SearchResultSection {
  items: SearchResultItem[];
  total_estimate: number;
  has_more: boolean;
}

export interface GlobalSearchResponse {
  query: string;
  results: {
    users: SearchResultSection;
    posts: SearchResultSection;
    catalog: SearchResultSection;
    files: SearchResultSection;
    messages: SearchResultSection;
    tickets: SearchResultSection;
    contacts: SearchResultSection;
    videos: SearchResultSection;
    calendar: SearchResultSection;
  };
  partial?: boolean;
}

export interface SearchHistoryItem {
  id: string;
  query: string;
  ts: number;
  result_count: number;
}

// ---------------------------------------------------------------------------
// API calls
// ---------------------------------------------------------------------------

export const globalSearch = (q: string, types?: string, limit = 5) => {
  const params: Record<string, string> = { q, limit: String(limit) };
  if (types) params.types = types;
  return api.get<GlobalSearchResponse>("/ui/search", params);
};

export const recordSearchHistory = (query: string, resultCount?: number) =>
  api.post<{ ok: boolean; id: string }>("/ui/search/history", {
    query,
    result_count: resultCount ?? 0,
  });

export const getSearchHistory = (limit = 20) =>
  api.get<{ items: SearchHistoryItem[] }>("/ui/search/history", {
    limit: String(limit),
  });

export const deleteSearchHistoryItem = (id: string) =>
  api.delete<{ ok: boolean }>(`/ui/search/history/${encodeURIComponent(id)}`);

export const clearSearchHistory = () =>
  api.delete<{ ok: boolean; deleted_count: number }>("/ui/search/history");
```

### 5.5 Updated Types

**File**: `frontend/src/api/types.ts`

- Add `SearchHistoryItem` type.
- Extend `SearchResultItem.type` union to include `"message" | "ticket" | "contact" | "video" | "calendar"`.

### 5.6 Updated uiStore

**File**: `frontend/src/stores/uiStore.ts`

Add `recentSearches` field alongside `recentCommands`:

```typescript
interface UiState {
  // ... existing fields ...
  recentSearches: string[];

  trackRecentSearch: (query: string) => void;
  removeRecentSearch: (query: string) => void;
  clearRecentSearches: () => void;
}

// In the store implementation:
recentSearches: [],

trackRecentSearch: (query) =>
  set((s) => {
    const filtered = s.recentSearches.filter((q) => q !== query);
    return { recentSearches: [query, ...filtered].slice(0, 10) };
  }),

removeRecentSearch: (query) =>
  set((s) => ({
    recentSearches: s.recentSearches.filter((q) => q !== query),
  })),

clearRecentSearches: () => set({ recentSearches: [] }),

// Update partialize:
partialize: (state) => ({
  theme: state.theme,
  sidebarCollapsed: state.sidebarCollapsed,
  recentCommands: state.recentCommands,
  recentSearches: state.recentSearches,
}),
```

---

## 6. E2E Test Plan

### Section 101: Global Search API --- New Domains

```
101.1  Search messages: send a message with unique text, search via /ui/search?types=messages, expect match
101.2  Search tickets: create ticket with unique subject, search via /ui/search?types=tickets, expect match
101.3  Search contacts: create contact with unique name, search via /ui/search?types=contacts, expect match
101.4  Search all domains: search a term that matches across multiple domains, verify all sections populated
101.5  Partial timeout: search with types=users,nonexistent, verify partial=true and users results present
101.6  Empty query returns 400
101.7  Query sanitization: control characters stripped, whitespace collapsed
101.8  Search videos: create VOD with unique title, search via /ui/search?types=videos, expect match
101.9  Search calendar: create event with unique title, search via /ui/search?types=calendar, expect match
101.10 Message search respects authorization: Alice cannot find Bob's private conversation messages
101.11 Ticket search respects authorization: Alice cannot find tickets created by and assigned to Bob
101.12 Encrypted message appears as "[Encrypted message]" in snippet, not plaintext
101.13 Locked post appears as "[Locked]" in snippet, not body text
101.14 Deleted/soft-deleted files excluded from search results
101.15 Limit parameter caps results per section (limit=2 returns at most 2 items per type)
```

### Section 102: Search History API

```
102.1  POST /ui/search/history records a query; GET returns it
102.2  Duplicate queries update timestamp, don't create duplicates
102.3  DELETE /ui/search/history/{id} removes specific entry
102.4  DELETE /ui/search/history clears all entries
102.5  History capped at 50 entries (oldest evicted)
102.6  History respects user isolation (Alice can't see Bob's history)
102.7  POST /ui/search/history with empty query returns 400
102.8  GET /ui/search/history returns items sorted newest-first
102.9  POST /ui/search/history stores result_count when provided
102.10 DELETE /ui/search/history returns deleted_count matching actual deletions
```

### Section 103: Command Palette UI --- Enhanced Search

```
103.1  Ctrl+K opens palette; typing 2+ chars triggers content search with debounce
103.2  Message results appear in "Messages" group with conversation name
103.3  Ticket results appear in "Tickets" group with status badge
103.4  "View all results" navigates to /search?q=<query>
103.5  Recent searches appear when input is empty
103.6  Clicking a recent search re-executes the query
103.7  Escape closes the palette and resets search state
103.8  Contact results appear with email in snippet
103.9  Video results appear with duration in meta
103.10 Calendar results appear with event date
103.11 Clicking a message result navigates to /messages/{conversationId}
103.12 Clicking a ticket result navigates to /tickets/{ticketId}
103.13 "X" button on recent search removes it from list
103.14 Domain filter chips filter results to selected domain only
```

### Section 104: Search Page UI --- Tabs and Pagination

```
104.1  /search?q=test shows tabs for each domain
104.2  Clicking a tab filters results to that domain
104.3  "Load more" button appears when has_more=true
104.4  Clicking "Load more" appends results (not replaces)
104.5  Search history sidebar shows recent queries
104.6  Clicking a history item populates the search input
104.7  Empty tabs are hidden (no tab for domains with 0 results)
104.8  Tab badge shows result count per domain
104.9  URL updates with tab parameter when switching tabs (/search?q=test&tab=messages)
104.10 Back button navigates between tab changes
```

---

## 7. Edge Cases

1. **Message search authorization**: A search token might match messages in conversations the user is no longer part of (they left or were removed). The search module must check participant membership at query time, not index time. The implementation pre-fetches the user's current conversation list and filters candidates against it. This means messages from conversations the user was later removed from are correctly excluded.

2. **Locked/encrypted content**: Locked posts (`unlock_price_cents > 0`) should appear in results with `snippet: "[Locked]"` (existing behavior in `_search_posts`, line 147) <!-- VERIFIED: search.py:147 -->. Encrypted messages should appear as `snippet: "[Encrypted message]"`. Never expose plaintext of locked/encrypted content in search results. View-once messages should appear as `snippet: "[View-once message]"` regardless of whether they've been consumed.

3. **Deleted content**: Soft-deleted files (`deleted_at` set), deleted messages, and closed tickets should be excluded from search results by default. Add an optional `include_deleted=true` parameter for admin search. The ticket search should include closed tickets (they're not deleted), but should show the status clearly in the result metadata.

4. **Rate limiting**: The search endpoint should be rate-limited to prevent abuse. Apply the existing rate limiter with a budget of 30 requests per minute per user. The search history POST endpoint should also be rate-limited (60 requests/minute) to prevent abuse via flooding the history table.

5. **Large result sets**: The `_search_posts` function (line 99) <!-- CORRECTED: was "line 120", actually line 99 --> scans up to 4 pages of 500 items. For messages, the token-based index in the `MessageSearch` table is more efficient (query by token, not scan). Ensure all search modules use query-based access patterns where possible. For tables that require scans (posts, catalog, tickets), monitor DDB read consumption and migrate to a search-specific GSI or OpenSearch in a future ticket.

6. **Empty domains**: If a domain has zero results, it should return `{"items": [], "total_estimate": 0, "has_more": false}` (existing behavior via `_empty_section()`, line 40) <!-- VERIFIED: search.py:40 -->. The frontend should hide empty tabs.

7. **Concurrent search queries**: Rapid typing generates multiple search requests. The frontend debounce (300ms at line 139) <!-- VERIFIED: Header.tsx:139 --> mitigates this, and React Query's stale-while-revalidate pattern handles concurrent requests. The backend should be idempotent.

8. **Unicode and special characters**: The `_sanitize_query` function (line 33) <!-- VERIFIED: search.py:33 --> strips control characters and collapses whitespace. It should also handle Unicode normalization (NFC) for consistent matching across composed/decomposed forms. Emoji in search queries should be preserved (they may appear in message text or post bodies).

9. **Cross-conversation message deduplication**: The same token may appear in multiple messages within the same conversation. The search module should return at most one result per conversation to avoid flooding the results with messages from a single high-volume conversation.

10. **Thread pool starvation**: If one search module (e.g., posts scan) takes the full 2-second timeout, other modules that finish faster are still returned promptly via `as_completed()`. However, if 8+ modules are requested and the thread pool has 8 workers, all workers may be busy. This is handled by the `max_workers=min(len(search_fns), 8)` sizing.

11. **Message search disabled**: When `_message_search_enabled()` returns False (DDB_MESSAGE_SEARCH env var not set), the messages domain returns an empty section. The frontend should handle this gracefully --- show "Message search is not configured" instead of an empty tab.

12. **Search history collision**: The MD5-based query hash is 8 hex chars (32 bits). Hash collisions are possible but extremely unlikely for a per-user history of <= 50 items. If two different queries produce the same hash, the deduplication logic would incorrectly update the older query's timestamp. For a user with 50 history items, the collision probability is approximately 1 in 2 billion.

---

## 8. Security Considerations

1. **Authorization per domain**: Each search module must independently verify that the requesting user has access to the results. Message search must check conversation membership. File search must verify file ownership. Ticket search must verify the user is the ticket creator or an assigned agent. Video search must verify visibility (public) or ownership. Calendar search must verify calendar ownership.

2. **Query injection**: The `_sanitize_query` function (line 33) strips control characters and caps length at 200 characters. DynamoDB `contains()` and `begins_with()` operators are safe against injection. However, if OpenSearch is added in the future, query strings must be escaped for the OpenSearch query DSL. The current regex-based tokenization (`re.findall(r"[a-z0-9@._-]+", q.lower())`) strips all special characters, providing an additional layer of protection.

3. **Information leakage**: Search snippets must not reveal content the user does not have access to. Locked post bodies must show `"[Locked]"`. Encrypted messages must show `"[Encrypted message]"`. Private calendar events must be excluded. Contact notes (which may contain sensitive information) should be searched but NOT included in the snippet --- only the contact name and email should appear in results.

4. **Rate limiting**: Without rate limiting, the search endpoint could be used to enumerate content. Apply a rate limit of 30 requests/minute per user and 5 requests/second burst. The search history endpoints should also be rate-limited to prevent state-flooding attacks.

5. **Search history privacy**: Search history is per-user and must never be exposed to other users, even admins. The history should be deletable by the user. Server-side history storage should use TTL (90 days) to auto-expire old entries. The DDB partition key includes the user's sub, ensuring partition-level isolation.

6. **CSRF**: The search endpoints use `GET` method and are read-only, so CSRF protection is not required (CSRF is only enforced on non-GET methods per `require_ui_session` in `app/auth/deps.py`). The search history `POST`/`DELETE` endpoints must include CSRF validation. The frontend `api.post` and `api.delete` methods automatically attach the `x-csrf-token` header from the `ui_csrf` cookie.

7. **Timing attacks**: Different search domains have different response times (user search via indexed query is fast; post search via scan is slow). The aggregator waits for all futures with `as_completed()`, so the response time is dominated by the slowest domain. An attacker could infer the existence of matching content in a specific domain by timing the response. The 5-second overall timeout and partial result support mitigate this by normalizing response times.

---

## 9. Performance Considerations

1. **Thread pool**: Increasing from 4 to 8 workers. Each worker makes a DynamoDB call with ~10-50ms latency. Total wall-clock time should stay under 500ms for most queries, well within the 5-second timeout. Monitor P99 latency after deployment; if it exceeds 2 seconds, consider breaking the search into fast (users, contacts, files) and slow (posts, messages, tickets) tiers.

2. **Message search efficiency**: The `MessageSearch` table uses a token-based index with exact-match queries (not scans). This is O(matches) not O(table-size), making it suitable for global search. However, the authorization check (`list_user_conversations`) is O(conversations), which could be expensive for users with 500+ conversations. Consider caching the user's conversation ID set in a short-TTL cache (30 seconds).

3. **Caching**: Frontend uses React Query with `staleTime: 60_000` (line 157 in `Header.tsx`). The same query within 60 seconds reuses cached results. Consider adding a backend cache (TTL=30s) for popular queries. An in-memory LRU cache with 1000 entries and 30-second TTL would be effective for reducing DDB reads.

4. **Pagination**: The initial search returns `limit` items per domain (default 5). The "Load more" action should use cursor-based pagination for efficient follow-up queries. Each domain's `has_more` flag indicates whether more results exist. For the initial implementation, "Load more" re-queries with a higher limit (10, 20, etc.) rather than implementing true cursor-based pagination per domain.

5. **DDB read capacity**: The post search uses `Scan` with `FilterExpression` (line 113), which reads all items in the table. For tables with > 10K items, this becomes expensive. Consider adding a search-specific GSI or migrating to OpenSearch for post search in a future ticket. The ticket and catalog scans have the same issue. Monitor consumed read capacity after deployment.

6. **Connection pooling**: The `ThreadPoolExecutor` creates threads that each make DDB calls. boto3's session is thread-safe, and the default connection pool size (10) is sufficient for 8 concurrent workers. No connection pool adjustment is needed.

---

## 10. Migration & Rollback

1. **Database**: No new tables required. Search history uses the existing `app_single_table` with a new PK pattern (`SEARCH_HISTORY#{user_sub}`). The `MessageSearch` table already exists. No GSIs need to be created for this ticket.

2. **Feature flag**: Add `GLOBAL_SEARCH_EXTENDED_DOMAINS=true` environment variable. When false, the `ALLOWED_TYPES` set remains `{"users", "posts", "catalog", "files"}` (backward compatible).

   ```python
   _EXTENDED_SEARCH = os.environ.get("GLOBAL_SEARCH_EXTENDED_DOMAINS", "true").lower() == "true"

   ALLOWED_TYPES = {"users", "posts", "catalog", "files"}
   if _EXTENDED_SEARCH:
       ALLOWED_TYPES |= {"messages", "tickets", "contacts", "videos", "calendar"}
   ```

3. **Rollback**: Set `GLOBAL_SEARCH_EXTENDED_DOMAINS=false` to revert to the original 4-domain search. Search history data persists but is not displayed. No data migration is needed for rollback.

4. **Frontend**: The enhanced command palette is always rendered. New domain result groups are conditionally shown based on whether the backend returns them. If the backend returns the old 4-domain response, the frontend gracefully shows only those domains. The `GlobalSearchResponse` type uses optional sections for backward compatibility:

   ```typescript
   results: {
     users: SearchResultSection;
     posts: SearchResultSection;
     catalog: SearchResultSection;
     files: SearchResultSection;
     messages?: SearchResultSection;   // optional for backward compat
     tickets?: SearchResultSection;
     contacts?: SearchResultSection;
     videos?: SearchResultSection;
     calendar?: SearchResultSection;
   };
   ```

5. **Deployment order**: Backend first (adds new search modules + search history endpoints), then frontend (adds new UI groups + search history sidebar). The frontend can be deployed independently because it handles missing result sections gracefully.


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_global_search.py`

| # | Test Function | Description |
|---|--------------|-------------|
| 1 | `test_platform_011_create` | Create primary entity; 201 |
| 2 | `test_platform_011_read` | Read back entity; correct fields |
| 3 | `test_platform_011_update` | Update entity; 200; changes reflected |
| 4 | `test_platform_011_delete` | Delete entity; 200/204 |
| 5 | `test_platform_011_auth_required` | No auth; 401 |
| 6 | `test_platform_011_validation` | Invalid input; 422 |

All tests use moto-mocked DynamoDB.

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | End-to-end happy path through all layers | router + service + DDB |
| 2 | Error handling propagates correctly | router + service layer |
| 3 | Feature flag disables functionality | settings + router |

### E2E Tests (Playwright)

**File**: `frontend/e2e/global-search.spec.ts` -- 18 tests

**Auth**: `injectAuth(page, identity)` for cookie auth; CSRF header for mutations.

Tests cover API CRUD, UI rendering, negative cases (401/403/404/422), and edge cases.

**Negative/edge tests**: 401 unauthenticated, 403 insufficient role, 404 not found, 422 validation error, 409 conflict

### Test Data Requirements

- DDB seeds: feature-specific tables via setup scripts
- Test users: Alice, Bob, Root, Charlie (admin)
- Sessions via `e2e_admin_session_setup.py`

### CI/Pipeline

- Feature flags: Feature-specific flags (see Rollout Plan section)
- Serial execution (1 worker), 1 retry per playwright.config.ts
- Retry-safe: unique timestamps in test data


---

## Dependencies & Merge Safety

### Depends On

| Ticket | Type | Detail |
|--------|------|--------|
| SOC-003 | Optional | User search discovery provides search infrastructure to extend |

### Depended On By

| Ticket | Type | Detail |
|--------|------|--------|
| (none) | -- | No downstream dependents identified |

### Merge Strategy

**Independent** -- Aggregates existing per-domain search modules.

### Merge Checklist

- [ ] Backend service and router implemented
- [ ] DDB tables created in local-ddb-init.py (if new)
- [ ] Frontend types added to api/types.ts
- [ ] Frontend page/component created
- [ ] Route added to App.tsx
- [ ] E2E pass: `npx playwright test e2e/global-search.spec.ts`
