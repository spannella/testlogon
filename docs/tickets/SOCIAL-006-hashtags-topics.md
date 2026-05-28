# SOCIAL-006: Hashtags / Topics

**Ticket**: SOCIAL-006
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: Medium
**Estimated effort**: 10-14 days

---

## 1. Executive Summary

The platform has no hashtag or topic taxonomy for posts. Newsfeed posts (`FeedPost` in `types.ts:1781-1834`) lack any `tags` or `hashtags` field. While the video system has `tags: List[str]` on `VideoMetadataModel` (`app/models_video.py:126`), those tags are never surfaced as clickable hashtags and exist only as metadata for video gallery filtering. Post bodies may contain `#word` patterns in user-written text, but these are never extracted, indexed, or made interactive.

This means there is no way for users to discover content by topic, no way for creators to categorize their posts, and no cross-content tag-based browsing experience. Hashtags are a fundamental content discovery mechanism on every social platform. Without them, the Discover page (`/discover`, `DiscoverPage.tsx`) is limited to user search and trending creators -- there is no content-level discovery.

This feature adds a `tags` field to posts, automatic hashtag extraction from post body text, a tag input widget in CreatePost, clickable hashtags in rendered post bodies, a `GET /ui/discover/tags/{tag}` endpoint for tag-filtered post discovery, a trending tags API, and a tag discovery page. It also unifies video tags so they appear alongside post tags in the discovery experience.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | I want to add hashtags to my posts so they appear in topic feeds. | CreatePost has a tag input; tags are stored and returned on the post. |
| Creator | I want hashtags I type in my post body (e.g., `#photography`) to be auto-extracted. | Body text `#word` patterns are parsed and added to the post's `tags` list. |
| Viewer | I want to click a hashtag in a post to see all posts with that tag. | Clicking `#photography` navigates to `/discover/tags/photography` showing tagged posts. |
| Viewer | I want to see trending hashtags on the discover page. | Discover page has a "Trending Tags" section showing popular tags. |
| Viewer | I want to browse posts and videos together by topic. | Tag discovery page shows both posts and videos matching the tag. |
| Creator | I want to see which hashtags are popular to improve my reach. | Tag suggestions shown in CreatePost based on trending tags. |

### 2.2 Pain Points

1. **No content-level discovery**: The Discover page (`frontend/src/pages/discover/DiscoverPage.tsx`) only shows user search and trending creators. There is no way to find posts by topic.
2. **No topic categorization**: Posts have no way to be grouped by subject matter. A cooking post and a music post are indistinguishable to the platform.
3. **Creator discoverability**: New creators cannot leverage popular topics to gain visibility. Without hashtags, content must be found through the author, not the subject.
4. **Video tags disconnected**: Videos have `tags` (`app/models_video.py:126`) but these are isolated metadata that do not participate in any cross-content discovery.

---

## 3. Current State Analysis

### 3.1 Post Data Model

The `CreatePostRequest` model (`app/routers/newsfeed.py:1204-1262`) accepts `image_urls`, `video_id`, `visibility`, lock fields, and scheduling fields -- but no `tags` field. The `_post_to_dict` serialization function (`app/routers/newsfeed.py:1792-1899`) maps DDB items to the frontend `FeedPost` shape. The returned dict includes no `tags` key.

The frontend `FeedPost` TypeScript interface (`frontend/src/api/types.ts:1781-1834`) has fields for body content, images, video, reactions, lock/unlock, and scheduling -- no `tags` or `hashtags` field.

### 3.2 Post Storage

Posts are stored in DynamoDB with these key patterns (from `app/routers/newsfeed.py:711-793`):

- `pk_user(user_id)` = `USER#{user_id}`, `sk` = `META`
- `pk_post(post_id)` = `POST#{post_id}`, `sk` = `META`
- `GSI1PK` = `FEED#{user_id}`, `GSI1SK` = `{created_at}#POST#{post_id}`
- `GSI2PK` = `POST_AUTHOR#{user_id}`, `GSI2SK` = `{created_at}#POST#{post_id}`

There is no tag-based GSI or inverted index for discovering posts by tag.

### 3.3 Video Tags

`VideoMetadataModel` (`app/models_video.py:126`) has `tags: List[str] = Field(default_factory=list)`. These tags are stored in the VideoMetadata DynamoDB table but are not exposed as clickable hashtags in any UI, not indexed for cross-content discovery, and not rendered interactively.

### 3.4 Discovery System

The discovery router (`app/routers/discovery.py:16-57`) provides:

- `GET /ui/discover/search` -- user search only (`discovery.py:19-27`)
- `GET /ui/discover/suggested` -- suggested users (`discovery.py:30-36`)
- `GET /ui/discover/trending` -- trending creators (`discovery.py:39-45`)
- `GET /ui/discover/profile/{user_id}` -- user profile (`discovery.py:48-56`)

No tag or topic endpoints exist. The `DiscoverPage.tsx` renders user search results, suggested users, and trending creators with no content discovery.

### 3.5 Post Body Rendering

`CreatePost.tsx` (`frontend/src/pages/feed/CreatePost.tsx:1-60`) uses `MarkdownComposer` for rich text editing. `PostCard.tsx` renders post body as markdown HTML (`body_markdown_html`) or plain text. Neither component parses or linkifies `#hashtag` patterns.

### 3.6 Gaps

1. No `tags` field on `CreatePostRequest` (`newsfeed.py:1204`)
2. No `tags` field in `_post_to_dict` output (`newsfeed.py:1853-1899`)
3. No `tags` field on `FeedPost` TypeScript interface (`types.ts:1781-1834`)
4. No tag input widget in `CreatePost.tsx`
5. No hashtag extraction from post body text
6. No `GET /ui/discover/tags/{tag}` endpoint
7. No trending tags endpoint
8. No tag-based DynamoDB GSI or inverted index
9. No clickable hashtag rendering in PostCard
10. No tag discovery page in frontend

---

## 4. Implementation Plan

### 4.1 Backend: Data Model Changes

**`app/routers/newsfeed.py` -- CreatePostRequest (~line 1204)**

Add `tags` field to the create request:

```python
class CreatePostRequest(ContentFieldsMixin):
    image_urls: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list, max_length=20)
    # ... existing fields ...
```

Validation: max 20 tags per post, each tag 1-50 chars, lowercase alphanumeric + underscores, no leading `#` (stripped on input).

**`app/routers/newsfeed.py` -- Hashtag Auto-Extraction**

Add a function to extract `#hashtag` patterns from post body text:

```python
import re

_HASHTAG_RE = re.compile(r"#([a-zA-Z][a-zA-Z0-9_]{0,49})\b")

def _extract_hashtags(text: str) -> List[str]:
    """Extract unique hashtags from text, lowercased, preserving order."""
    seen = set()
    tags = []
    for match in _HASHTAG_RE.finditer(text):
        tag = match.group(1).lower()
        if tag not in seen:
            seen.add(tag)
            tags.append(tag)
    return tags[:20]
```

Call in `create_post()` (~line 2866): merge explicit tags with auto-extracted tags from `body_plain`, deduplicate:

```python
explicit_tags = [t.lower().lstrip("#").strip() for t in (req.tags or []) if t.strip()]
body_tags = _extract_hashtags(body_plain or "")
all_tags = list(dict.fromkeys(explicit_tags + body_tags))[:20]  # dedupe, preserve order
```

**`app/routers/newsfeed.py` -- Post Item Storage (~line 3076)**

Add `tags` to the DDB item written by `create_post()`:

```python
post_item["tags"] = all_tags
```

**`app/routers/newsfeed.py` -- _post_to_dict (~line 1853)**

Include `tags` in the serialized output:

```python
"tags": list(post.get("tags") or []),
```

### 4.2 Backend: Tag Index (DynamoDB)

Create an inverted index using the existing newsfeed table (single-table design). For each tag on a post, write a `TAG#{tag}` item:

```python
# In create_post(), after writing the post item:
for tag in all_tags:
    _tbl.put_item(Item={
        "pk": f"TAG#{tag}",
        "sk": f"{created_at}#POST#{post_id}",
        "post_id": post_id,
        "author_id": user_id,
        "created_at": created_at,
        "GSI5PK": "TAG_INDEX",
        "GSI5SK": f"{tag}#{created_at}",
    })
```

This allows:
- Query posts by tag: `pk = TAG#{tag}`, `ScanIndexForward=False` (newest first)
- List all known tags: `GSI5PK = TAG_INDEX` (if a GSI5 is available)

**`scripts/local-ddb-init.py`** -- Add GSI5 to the newsfeed table for tag discovery:

```python
GlobalSecondaryIndex(
    index_name="GSI5",
    partition_key="GSI5PK",
    sort_key="GSI5SK",
    projection="KEYS_ONLY",
)
```

### 4.3 Backend: Tag Discovery Endpoints

**`app/routers/discovery.py`** -- Add new endpoints:

```python
@router.get("/tags/{tag}")
async def discover_tag(
    tag: str,
    limit: int = Query(default=20, ge=1, le=50),
    cursor: Optional[str] = Query(default=None),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """Get posts tagged with a specific hashtag."""
    posts, next_cursor = get_posts_by_tag(tag.lower(), viewer_id=user.sub, limit=limit, cursor=cursor)
    return {"tag": tag.lower(), "posts": posts, "next_cursor": next_cursor}

@router.get("/tags")
async def discover_trending_tags(
    limit: int = Query(default=20, ge=1, le=50),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """Get trending tags (most-used in last 7 days)."""
    tags = get_trending_tags(limit=limit)
    return {"tags": tags}
```

**`app/services/discovery.py`** -- Add tag query functions:

```python
def get_posts_by_tag(tag: str, viewer_id: str, limit: int = 20, cursor=None) -> Tuple[List[Dict], Optional[str]]:
    """Query TAG#{tag} partition, fetch post items, apply _post_to_dict."""

def get_trending_tags(limit: int = 20) -> List[Dict]:
    """Scan TAG_INDEX GSI5 for tags with most posts in last 7 days."""
```

### 4.4 Backend: Trending Tags Computation

Store tag usage counts in a dedicated item updated on each post creation:

```python
# In create_post():
for tag in all_tags:
    # Atomic increment of tag usage counter
    _tbl.update_item(
        Key={"pk": "TAG_STATS", "sk": f"TAG#{tag}"},
        UpdateExpression="SET #n = if_not_exists(#n, :z) + :one, last_used_at = :now",
        ExpressionAttributeNames={"#n": "count"},
        ExpressionAttributeValues={":one": 1, ":z": 0, ":now": now_iso()},
    )
```

`get_trending_tags()` queries `pk = TAG_STATS`, filters to `last_used_at` within 7 days, sorts by `count` descending.

### 4.5 Frontend: Types

**`frontend/src/api/types.ts` -- FeedPost interface (~line 1781)**

Add `tags` field:

```typescript
export interface FeedPost {
  // ... existing fields ...
  tags?: string[];
}
```

### 4.6 Frontend: Tag Input in CreatePost

**`frontend/src/pages/feed/CreatePost.tsx`**

Add a tag input section below the body editor:

```tsx
const [tags, setTags] = useState<string[]>([]);
const [tagInput, setTagInput] = useState("");

// In the form JSX:
<div className="flex flex-wrap gap-1 mt-2">
  {tags.map(tag => (
    <Badge key={tag} variant="secondary">
      #{tag}
      <button onClick={() => setTags(t => t.filter(x => x !== tag))}><X className="h-3 w-3" /></button>
    </Badge>
  ))}
  <Input
    placeholder="Add tag..."
    value={tagInput}
    onChange={e => setTagInput(e.target.value.replace(/[^a-zA-Z0-9_]/g, ""))}
    onKeyDown={e => {
      if (e.key === "Enter" && tagInput.trim()) {
        setTags(t => [...new Set([...t, tagInput.trim().toLowerCase()])].slice(0, 20));
        setTagInput("");
        e.preventDefault();
      }
    }}
    className="w-24 h-7 text-sm"
  />
</div>
```

Include `tags` in the mutation payload sent to `createPost()`.

### 4.7 Frontend: Clickable Hashtags in PostCard

**`frontend/src/pages/feed/PostCard.tsx`**

Add a utility function to linkify hashtags in rendered body text:

```tsx
function linkifyHashtags(html: string): string {
  return html.replace(
    /#([a-zA-Z][a-zA-Z0-9_]{0,49})\b/g,
    '<a href="/discover/tags/$1" class="text-primary hover:underline">#$1</a>'
  );
}
```

Apply when rendering `body_markdown_html`:

```tsx
<div dangerouslySetInnerHTML={{ __html: linkifyHashtags(post.body_markdown_html) }} />
```

For plain text bodies, render hashtags as `<Link>` components:

```tsx
function HashtagText({ text }: { text: string }) {
  const parts = text.split(/(#[a-zA-Z][a-zA-Z0-9_]{0,49})/g);
  return <>{parts.map((part, i) =>
    part.startsWith("#")
      ? <Link key={i} to={`/discover/tags/${part.slice(1)}`} className="text-primary hover:underline">{part}</Link>
      : part
  )}</>;
}
```

### 4.8 Frontend: Tag Discovery Page

**New file: `frontend/src/pages/discover/TagPage.tsx`**

A page at `/discover/tags/:tag` that shows all posts matching the tag:

```tsx
export default function TagPage() {
  const { tag } = useParams<{ tag: string }>();
  const q = useQuery({
    queryKey: ["discover", "tags", tag],
    queryFn: () => client.get(`/ui/discover/tags/${tag}`).then(r => r.data),
    enabled: !!tag,
  });

  return (
    <div>
      <h1 className="text-2xl font-bold">#{tag}</h1>
      <p className="text-muted-foreground">{q.data?.posts?.length ?? 0} posts</p>
      {q.data?.posts?.map(post => <PostCard key={post.post_id} post={post} />)}
    </div>
  );
}
```

**`frontend/src/App.tsx`** -- Add route:

```tsx
<Route path="discover/tags/:tag" element={<TagPage />} />
```

### 4.9 Frontend: Trending Tags on Discover Page

**`frontend/src/pages/discover/DiscoverPage.tsx`**

Add a "Trending Tags" section:

```tsx
const tagsQ = useQuery({
  queryKey: ["discover", "trending-tags"],
  queryFn: () => client.get("/ui/discover/tags").then(r => r.data),
});

// In JSX:
<Card>
  <CardHeader><CardTitle>Trending Tags</CardTitle></CardHeader>
  <CardContent>
    <div className="flex flex-wrap gap-2">
      {tagsQ.data?.tags?.map(t => (
        <Link key={t.tag} to={`/discover/tags/${t.tag}`}>
          <Badge variant="outline">#{t.tag} ({t.count})</Badge>
        </Link>
      ))}
    </div>
  </CardContent>
</Card>
```

### 4.10 Frontend: API Endpoint Wrapper

**`frontend/src/api/endpoints/discovery.ts`** -- Add:

```typescript
export async function getPostsByTag(tag: string, limit = 20, cursor?: string) {
  const params: Record<string, any> = { limit };
  if (cursor) params.cursor = cursor;
  const { data } = await client.get(`/ui/discover/tags/${tag}`, { params });
  return data;
}

export async function getTrendingTags(limit = 20) {
  const { data } = await client.get("/ui/discover/tags", { params: { limit } });
  return data;
}
```

### 4.11 Settings

**`app/core/settings.py`** -- Add:

```python
hashtags_max_per_post: int = int(os.environ.get("HASHTAGS_MAX_PER_POST", "20"))
hashtags_max_tag_length: int = int(os.environ.get("HASHTAGS_MAX_TAG_LENGTH", "50"))
hashtags_trending_window_days: int = int(os.environ.get("HASHTAGS_TRENDING_WINDOW_DAYS", "7"))
```

---

## 5. Data Model

### 5.1 Post Item Changes

Existing post items in the newsfeed DDB table gain a new `tags` attribute:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `tags` | L (list of S) | Lowercase hashtags | `["photography", "travel"]` |

### 5.2 Tag Index Items (same table)

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `pk` | S | `TAG#{tag}` | `"TAG#photography"` |
| `sk` | S | `{created_at}#POST#{post_id}` | `"2026-05-27T10:00:00Z#POST#post_abc"` |
| `post_id` | S | Post ID for lookup | `"post_abc"` |
| `author_id` | S | Post author | `"alice@test.local"` |
| `created_at` | S | ISO timestamp | `"2026-05-27T10:00:00Z"` |

### 5.3 Tag Stats Items (same table)

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `pk` | S | `TAG_STATS` | `"TAG_STATS"` |
| `sk` | S | `TAG#{tag}` | `"TAG#photography"` |
| `count` | N | Total posts with this tag | `42` |
| `last_used_at` | S | ISO timestamp of last use | `"2026-05-27T10:00:00Z"` |

### 5.4 Access Patterns

| Access Pattern | Key Condition | Usage |
|---------------|---------------|-------|
| Posts by tag (newest first) | `pk = TAG#{tag}`, `ScanIndexForward=False` | Tag discovery page |
| Trending tags | `pk = TAG_STATS`, scan all `TAG#*` items | Trending tags section |
| Tag count for a specific tag | `pk = TAG_STATS, sk = TAG#{tag}` | Tag metadata display |

---

## 6. API Contract

### 6.1 Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/discover/tags/{tag}` | `get_authenticated_user` | Posts tagged with `{tag}` |
| GET | `/ui/discover/tags` | `get_authenticated_user` | Trending tags list |

### 6.2 GET `/ui/discover/tags/{tag}`

**Response (200):**

```json
{
  "tag": "photography",
  "posts": [
    {
      "post_id": "post_abc",
      "author_id": "alice@test.local",
      "body": "Check out my latest #photography series",
      "tags": ["photography", "travel"],
      "image_urls": ["/uploads/object?s3_key=..."],
      "like_count": 5,
      "comment_count": 2,
      "created_at": "2026-05-27T10:00:00Z"
    }
  ],
  "next_cursor": "eyJpZHgiOiAyMH0="
}
```

### 6.3 GET `/ui/discover/tags`

**Response (200):**

```json
{
  "tags": [
    { "tag": "photography", "count": 42, "last_used_at": "2026-05-27T10:00:00Z" },
    { "tag": "music", "count": 38, "last_used_at": "2026-05-27T09:30:00Z" }
  ]
}
```

### 6.4 Modified: POST `/uploads/post` (CreatePostRequest)

**New field in request body:**

```json
{
  "body_plain": "Beautiful sunset #photography #travel",
  "tags": ["photography", "travel", "nature"]
}
```

The `tags` in the response will be the union of explicit tags and auto-extracted tags from body text.

---

## 7. Security & Privacy

### 7.1 Input Validation

- Tags are lowercase alphanumeric + underscores only. The regex `^[a-z][a-z0-9_]{0,49}$` prevents injection.
- Tags must start with a letter (prevents numeric-only tags, which conflict with post IDs).
- Maximum 20 tags per post enforced server-side regardless of client-side validation.
- Tag length capped at 50 characters; excess silently truncated.
- Leading `#` characters stripped on input (users may paste `#photography` from other platforms).
- Unicode/emoji characters rejected; only ASCII alphanumeric + underscore.

### 7.2 Query Safety

- Tag queries use parameterized DDB key conditions (`pk = :tag_pk`). No string interpolation in key expressions.
- Path parameter `{tag}` is sanitized with the same regex before being used in a DDB key.
- `cursor` parameter is decoded with error handling; malformed cursors return 400 (not 500).

### 7.3 Access Control

- Tag discovery respects post visibility: only `visibility=public` posts appear in tag feeds for non-followers.
- Posts from blocked users are filtered from tag results (requires the user's blocked set loaded per-request).
- Locked posts show in tag feeds but with `body=null` and `is_locked=true` (snippet hidden).

### 7.4 Abuse Prevention

- Rate limiting: tag index writes are bounded by post creation rate limits (existing 10 posts/hour).
- Tag spam detection: If a post contains 15+ tags, flag for moderation review (future: automated moderation queue).
- Trending tags are computed from posts by distinct authors (prevents a single user from dominating trending by posting 50 times with the same tag).

### 7.5 curl Examples

```bash
# Get posts by tag
curl -s -b cookies.txt \
  "http://localhost:8000/ui/discover/tags/photography?limit=10" | jq .

# Get trending tags
curl -s -b cookies.txt \
  "http://localhost:8000/ui/discover/tags?limit=20" | jq .

# Create post with tags
curl -s -b cookies.txt \
  -H "x-csrf-token: $CSRF" \
  -H "Content-Type: application/json" \
  -d '{"body_plain":"Beautiful sunset #photography #travel","tags":["nature"]}' \
  "http://localhost:8000/uploads/post" | jq .tags
```

---

## 8. Performance

### 8.1 DynamoDB Read/Write Estimates

| Operation | WCU | RCU | Latency |
|-----------|-----|-----|---------|
| Create post (no tags) | 1 WCU (existing) | 0 | ~10ms |
| Create post (5 tags) | 1 + 5 (tag index) + 5 (tag stats) = 11 WCU | 0 | ~30ms |
| Create post (20 tags) | 1 + 20 + 20 = 41 WCU | 0 | ~80ms |
| Query posts by tag (page of 20) | 0 | 20 RCU (tag items) + 20 RCU (post items) = 40 RCU | ~50ms |
| Trending tags (100 tag stats) | 0 | ~5 RCU (1 query page) | ~15ms |

### 8.2 Write Optimization

Tag index writes use `BatchWriteItem` to send up to 25 items per batch (all tag items fit in one batch for posts with <=20 tags). This reduces round trips from N to 1:

```python
# Batch write tag index items
with T.newsfeed.batch_writer() as batch:
    for tag in all_tags:
        batch.put_item(Item={
            "pk": f"TAG#{tag}",
            "sk": f"{created_at}#POST#{post_id}",
            "post_id": post_id,
            "author_id": user_id,
            "created_at": created_at,
        })
```

Tag stats updates remain individual `update_item` calls (atomic increment cannot be batched).

### 8.3 Query Optimization

- **Tag query**: Single DDB query on `TAG#{tag}` partition with `ScanIndexForward=False` (newest first). Each page fetches 20 tag-index items, then `BatchGetItem` loads the actual post items.
- **Trending tags**: Query `pk=TAG_STATS` with `ScanIndexForward=False`. With thousands of tags, this is a single DDB page (~1KB per item, 400KB page limit = ~400 items per page).
- **React Query caching**: Tag query results cached for 2 minutes (`staleTime: 120_000`). Trending tags cached for 5 minutes (`staleTime: 300_000`).

### 8.4 Hot Tag Partitions

A viral tag (e.g., `#giveaway`) could accumulate millions of items under `TAG#{tag}`. DynamoDB handles this well since the partition key is the tag and items are small (~200 bytes each). The 10GB partition limit accommodates ~50M tag-index items. For truly viral tags, consider a time-bucketed partition scheme: `TAG#{tag}#2026-05-27`.

---

## 9. Testing Strategy

### 9.1 Unit Tests (pytest)

**File:** `tests/test_hashtags.py`

| # | Test | Assertion |
|---|------|-----------|
| 1 | `_extract_hashtags` extracts tags from body text | `#hello #world` -> `["hello", "world"]` |
| 2 | `_extract_hashtags` deduplicates case-insensitively | `#hello #HELLO #Hello` -> `["hello"]` |
| 3 | `_extract_hashtags` caps at 20 tags | 30 hashtags -> first 20 returned |
| 4 | `_extract_hashtags` ignores invalid patterns | `#1bad #_bad # ##` -> `[]` |
| 5 | `_extract_hashtags` handles unicode gracefully | `#café` -> `["caf"]` (stops at non-ASCII) |
| 6 | `_extract_hashtags` preserves order of first occurrence | `#b #a #c` -> `["b", "a", "c"]` |
| 7 | Create post with explicit tags stores them | Tags appear in DDB item as List(S) |
| 8 | Create post with body hashtags auto-extracts | Tags merged from body + explicit, deduped |
| 9 | Explicit tags strip leading `#` | Input `["#photo", "travel"]` -> stored as `["photo", "travel"]` |
| 10 | `_post_to_dict` includes tags in output | `tags` field present in serialized post |
| 11 | Tag index items written on post creation | `TAG#{tag}` items exist in DDB for each tag |
| 12 | Tag stats incremented on post creation | `TAG_STATS / TAG#{tag}` count == 1 after first post |
| 13 | `get_posts_by_tag` returns matching posts | Query returns posts containing that tag |
| 14 | `get_posts_by_tag` paginates correctly | Second page returns different posts |
| 15 | `get_trending_tags` returns sorted by count | Most-used tags first |
| 16 | `get_trending_tags` excludes stale tags | Tags not used in 7 days excluded |
| 17 | Post with no tags writes no index items | DDB has no `TAG#` items |
| 18 | Tag validation rejects over-length tags | 51-char tag rejected; post still created with valid tags |

```python
class TestExtractHashtags:
    def test_basic_extraction(self):
        assert _extract_hashtags("Hello #world #python") == ["world", "python"]

    def test_deduplication(self):
        assert _extract_hashtags("#Hello #hello #HELLO") == ["hello"]

    def test_max_20(self):
        text = " ".join(f"#tag{i}" for i in range(30))
        result = _extract_hashtags(text)
        assert len(result) == 20

    def test_invalid_patterns(self):
        assert _extract_hashtags("# #1bad #_bad ## #") == []

    def test_preserves_order(self):
        assert _extract_hashtags("#zebra #apple #mango") == ["zebra", "apple", "mango"]


class TestTagIndex:
    def test_tag_items_written(self, client, auth_headers):
        resp = client.post("/uploads/post", json={
            "body_plain": "Test #photography",
            "tags": ["nature"],
        }, headers=auth_headers)
        assert resp.status_code == 200
        post = resp.json()
        assert set(post["tags"]) == {"photography", "nature"}

        # Verify TAG# items exist
        items = T.newsfeed.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": "TAG#photography"},
        )["Items"]
        assert len(items) >= 1
        assert items[0]["post_id"] == post["post_id"]

    def test_tag_stats_incremented(self, client, auth_headers):
        client.post("/uploads/post", json={
            "body_plain": "Test #analytics", "tags": [],
        }, headers=auth_headers)
        stat = T.newsfeed.get_item(Key={"pk": "TAG_STATS", "sk": "TAG#analytics"}).get("Item")
        assert stat is not None
        assert int(stat["count"]) == 1
```

### 9.2 E2E Tests

**File:** `frontend/e2e/hashtags.spec.ts`

**Section 1: Hashtag API -- CRUD (7 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | Create post with explicit tags | 200; post has `tags: ["tagone", "tagtwo"]` |
| 2 | Create post with body hashtags auto-extracted | Post body contains `#hello`; tags includes `"hello"` |
| 3 | Explicit + body tags are merged and deduped | Both sources contribute; no duplicates |
| 4 | Get posts by tag returns matching post | `GET /ui/discover/tags/tagone`; response.posts contains the created post |
| 5 | Get posts by tag paginates | Create 6 tagged posts; `limit=3` returns 3; cursor fetches next page |
| 6 | Get trending tags returns non-empty list | `GET /ui/discover/tags`; response.tags includes `tagone` with count>=1 |
| 7 | Unknown tag returns empty list | `GET /ui/discover/tags/zzz_nonexistent`; `{ posts: [] }` |

**Section 2: Hashtag Validation (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 8 | Tag with leading # is stripped | Input `["#photo"]`; stored as `["photo"]` |
| 9 | Tags are lowercased | Input `["Photography"]`; stored as `["photography"]` |
| 10 | Invalid tag characters rejected | Input `["bad tag!"]`; tag not present in response (silently dropped or 422) |
| 11 | Over 20 tags truncated to 20 | Send 25 explicit tags; response.tags has length 20 |

**Section 3: Hashtag UI -- CreatePost (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 12 | Tag input visible in CreatePost form | Placeholder "Add tag..." visible |
| 13 | Typing tag + Enter adds badge | Type "mynewtag" + Enter; Badge with "#mynewtag" appears |
| 14 | Clicking X on badge removes tag | Badge disappears; tag not in submitted payload |
| 15 | Submit post sends tags to API | POST request body includes `tags: ["mynewtag"]` |

**Section 4: Hashtag UI -- PostCard & Navigation (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 16 | Clickable hashtag link in PostCard | `#tagone` rendered as `<a>` with href `/discover/tags/tagone` |
| 17 | Clicking hashtag navigates to tag page | Click `#tagone`; URL is `/discover/tags/tagone`; page renders |
| 18 | Tag discovery page shows tagged posts | Navigate to `/discover/tags/tagone`; PostCard visible |
| 19 | Trending tags section on Discover page | Navigate to `/discover`; "Trending Tags" heading visible; at least one tag badge rendered |

---

## 10. Acceptance Criteria

1. Posts accept a `tags` field (up to 20 tags) in the create request.
2. Hashtags in post body text (`#word` patterns) are auto-extracted and merged with explicit tags.
3. `GET /ui/discover/tags/{tag}` returns posts tagged with the specified hashtag, newest first.
4. `GET /ui/discover/tags` returns trending tags sorted by usage count.
5. PostCard renders hashtags as clickable links that navigate to the tag discovery page.
6. CreatePost has a tag input widget with badge display and removal.
7. Discover page shows a "Trending Tags" section.
8. `/discover/tags/:tag` route renders a tag discovery page with matching posts.
9. Tags are stored lowercase and deduplicated.
10. Existing video `tags` field is not broken; future integration can unify video + post tags.

---

## 15. Files to Create

| File | Purpose |
|------|---------|
| `frontend/src/pages/discover/TagPage.tsx` | Tag discovery page showing posts for a tag |
| `frontend/e2e/hashtags.spec.ts` | E2E tests |

## 16. Files to Modify

| File | Change |
|------|--------|
| `app/routers/newsfeed.py` | Add `tags` to `CreatePostRequest`, `_post_to_dict`, `create_post`; add `_extract_hashtags` |
| `app/routers/discovery.py` | Add `GET /tags/{tag}` and `GET /tags` endpoints |
| `app/services/discovery.py` | Add `get_posts_by_tag()` and `get_trending_tags()` functions |
| `app/core/settings.py` | Add `hashtags_*` settings |
| `frontend/src/api/types.ts` | Add `tags?: string[]` to `FeedPost` |
| `frontend/src/api/endpoints/discovery.ts` | Add `getPostsByTag()` and `getTrendingTags()` |
| `frontend/src/pages/feed/CreatePost.tsx` | Add tag input widget |
| `frontend/src/pages/feed/PostCard.tsx` | Add hashtag linkification |
| `frontend/src/pages/discover/DiscoverPage.tsx` | Add trending tags section |
| `frontend/src/App.tsx` | Add `/discover/tags/:tag` route |
| `scripts/local-ddb-init.py` | Add GSI5 to newsfeed table (if not already present) |

---

## 11. Pydantic Models

### 11.1 Request Models

```python
class TaggedPostCreateExtension(BaseModel):
    """Mixin fields added to CreatePostRequest."""
    tags: List[str] = Field(default_factory=list, max_length=20, description="Explicit hashtags (max 20)")

    @field_validator("tags", mode="before")
    @classmethod
    def normalize_tags(cls, v: List[str]) -> List[str]:
        out = []
        for raw in (v or []):
            tag = raw.lower().lstrip("#").strip()
            if re.match(r"^[a-z][a-z0-9_]{0,49}$", tag):
                out.append(tag)
        return out[:20]
```

### 11.2 Response Models

```python
class TaggedPostOut(BaseModel):
    """Post summary returned in tag discovery."""
    post_id: str
    author_id: str
    body_snippet: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    image_urls: List[str] = Field(default_factory=list)
    like_count: int = 0
    comment_count: int = 0
    created_at: str

class TagDiscoverOut(BaseModel):
    tag: str
    posts: List[TaggedPostOut]
    next_cursor: Optional[str] = None

class TrendingTagItem(BaseModel):
    tag: str
    count: int
    last_used_at: str

class TrendingTagsOut(BaseModel):
    tags: List[TrendingTagItem]
```

### 11.3 TypeScript Interfaces

```typescript
export interface TaggedPost {
  post_id: string;
  author_id: string;
  body_snippet?: string;
  tags: string[];
  image_urls: string[];
  like_count: number;
  comment_count: number;
  created_at: string;
}

export interface TagDiscoverResponse {
  tag: string;
  posts: TaggedPost[];
  next_cursor?: string;
}

export interface TrendingTag {
  tag: string;
  count: number;
  last_used_at: string;
}

export interface TrendingTagsResponse {
  tags: TrendingTag[];
}
```

---

## 12. Component Tree

### 12.1 TagPage (`/discover/tags/:tag`)

```
TagPage
  |-- Breadcrumb: Discover > Tags > #{tag}
  |-- Header
  |     |-- h1: "#{tag}"
  |     |-- Subtitle: "{count} posts"
  |-- PostList (useInfiniteQuery)
  |     |-- PostCard[] (existing component, renders tags as badges)
  |     |-- LoadMore button (when hasNextPage)
  |-- EmptyState (when posts.length === 0)
        |-- Hash icon
        |-- "No posts tagged #{tag} yet"
```

### 12.2 Enhanced CreatePost

```
CreatePost (existing)
  |-- MarkdownComposer (existing)
  |-- NEW: TagInputSection
  |     |-- Badge[] (each tag, with X remove button)
  |     |-- Input (placeholder "Add tag...", onKeyDown Enter)
  |-- ImageUpload (existing)
  |-- LockToggle (existing)
  |-- SubmitButton (existing)
```

### 12.3 Enhanced DiscoverPage

```
DiscoverPage (existing)
  |-- SearchInput (existing)
  |-- NEW: TrendingTagsCard
  |     |-- CardHeader: "Trending Tags"
  |     |-- CardContent: flex-wrap of Badge links
  |           |-- Link to /discover/tags/{tag}
  |           |-- Badge: "#{tag} (count)"
  |-- SuggestedUsers (existing)
  |-- TrendingCreators (existing)
```

---

## 13. Migration & Rollout

### 13.1 Feature Flag

`HASHTAGS_ENABLED` (default `true`). When `false`:
- `_extract_hashtags()` returns `[]`
- `tags` field accepted in request but not indexed
- Tag endpoints return 404
- Frontend tag input hidden via feature check
- Existing posts unaffected (no `tags` field stored)

### 13.2 Rollout Stages

| Stage | Scope | Duration | Success Criteria |
|-------|-------|----------|-----------------|
| 1 | Backend only: store tags, write index | 2 days | Posts with tags stored; no user-facing change |
| 2 | Discovery endpoints enabled | 1 day | `GET /ui/discover/tags/{tag}` returns results |
| 3 | Frontend: tag input in CreatePost | 2 days | Creators can add tags; clickable in PostCard |
| 4 | Frontend: TagPage + trending section | 2 days | Full discovery experience live |

### 13.3 Backfill (Optional)

Existing posts have no `tags` field. A backfill script can run `_extract_hashtags()` on existing `body_plain` values and write tag-index items retroactively:

```python
# scripts/backfill_hashtags.py (run once, offline)
for post in scan_all_posts():
    tags = _extract_hashtags(post.get("body_plain", ""))
    if tags:
        # Write tag index items + update post item with tags field
        ...
```

Estimated cost: ~0.5 WCU per post * 100K posts = 50K WCU total (spread over minutes with rate limiting).

---

## 14. Dependencies

- None. This feature builds on existing newsfeed and discovery infrastructure.
- Future: DISC-001 (Content Recommendations) can use tags as a content-based signal for recommendations.

---

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| FeedPost has no tags field | `frontend/src/api/types.ts` | 1781-1834 | VERIFIED |
| VideoMetadataModel has tags | `app/models_video.py` | 126 | VERIFIED |
| CreatePostRequest has no tags | `app/routers/newsfeed.py` | 1204-1262 | VERIFIED |
| _post_to_dict output has no tags | `app/routers/newsfeed.py` | 1853-1899 | VERIFIED |
| DDB key builders have no tag key | `app/routers/newsfeed.py` | 711-793 | VERIFIED |
| Discovery router has no tag endpoints | `app/routers/discovery.py` | 16-57 | VERIFIED |
| CreatePost.tsx has no tag input | `frontend/src/pages/feed/CreatePost.tsx` | 1-60 | VERIFIED |
| DiscoverPage has no tag section | `frontend/src/pages/discover/DiscoverPage.tsx` | 1-40 | VERIFIED |
| PostCard uses plain `<img src>` | `frontend/src/pages/feed/PostCard.tsx` | 77-82 | VERIFIED |
