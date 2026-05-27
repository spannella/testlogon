# FEED-002: Stories / Ephemeral Content

**Ticket**: FEED-002
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: High
**Estimated effort**: 12-16 days

---

## 1. Executive Summary

Stories are a 24-hour ephemeral content format that gives creators a lightweight, low-commitment channel for sharing quick updates, behind-the-scenes moments, or time-sensitive promotions. Unlike permanent newsfeed posts, stories auto-expire via DynamoDB TTL, require no manual cleanup, and create a persistent "check back" incentive through the story bar UI that appears above the feed.

This feature introduces a new `Story` entity type in the existing `app_single_table`, a full-screen story viewer overlay, a horizontal story bar component, view tracking with creator analytics, and a highlights system that allows creators to pin their best stories permanently to their profile. The design leverages the existing SOC-001 follow system for the story bar query, the existing presign upload flow for media, and DynamoDB's built-in TTL mechanism for automatic expiry.

Instagram, Snapchat, and YouTube have demonstrated that 24-hour stories drive significantly higher daily engagement than permanent posts alone. Stories appear above the feed in a horizontal bar, creating a persistent "check back" incentive that increases return visits and time-on-platform. The implementation is designed for DynamoDB-native operation with no external processing pipeline.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | I want to post a quick behind-the-scenes photo that disappears after 24 hours. | Story created with image; visible in story bar; gone after 24h. |
| Creator | I want to see who viewed my story. | View count + viewer list available on story detail. |
| Creator | I want to save an expiring story as a highlight on my profile. | POST highlight; story TTL removed; appears in profile highlights section. |
| Viewer | I want to tap a creator's avatar ring to see their stories in a full-screen viewer. | Story viewer opens; slides auto-advance; progress bar shows position. |
| Viewer | I want to see a horizontal bar of active stories above my feed. | Story bar shows avatars with colored rings for creators who have active stories. |
| Creator | I want to add a text overlay and link sticker to my story. | Text and link fields supported during creation; displayed over media. |
| Creator | I want to post a short video story (up to 60 seconds). | Video stories up to 60s accepted; play in full-screen viewer. |
| Creator | I want to organize my highlights into named groups (e.g., "Travel", "BTS"). | Highlight groups with custom titles and optional cover images. |
| Viewer | I want stories from creators I follow to appear, not random creators. | Story bar only shows followed creators with active stories. |

### 2.2 Pain Points

1. **No ephemeral content format**: Creators who want to share quick, disposable updates must post to the permanent feed and manually delete later, which clutters followers' feeds and loses the urgency effect.
2. **No daily engagement loop**: Without stories, there is no visual "new content available" indicator that drives users to open the app daily. The feed only shows content from the last visit onward.
3. **No lightweight creation flow**: Creating a newsfeed post requires title, content, and potentially markdown/rich text. Stories should be image/video + optional text overlay -- nothing more.
4. **No view tracking on individual items**: The newsfeed shows like counts but not per-user view tracking. Creators want to know exactly who saw their content.

### 2.3 Competitive Analysis

| Platform | Story Duration | Video Limit | View Tracking | Highlights | Swipe Navigation |
|----------|---------------|-------------|---------------|------------|-------------------|
| Instagram | 24h | 60s per slide | Yes (viewers list) | Yes (named groups) | Yes (between creators) |
| Snapchat | 24h | 60s | Yes (viewers + screenshots) | Yes (Memories) | Yes |
| YouTube | 24h (Community) / 7d (Shorts) | 60s | Yes (view count only) | No | Limited |
| TikTok | 24h (planned) | 15-60s | Yes | No | Yes |
| **This platform** | **N/A** | **N/A** | **N/A** | **N/A** | **N/A** |

---

## 3. Current State Analysis

### 3.1 Newsfeed Infrastructure

All newsfeed logic lives in `app/routers/newsfeed.py` (~4998 lines). <!-- CORRECTED: was ~5000, actually 4998 lines --> Posts use the `app_single_table` DynamoDB table with `PK=POST#{post_id}`, `SK=META`. The feed index uses `GSI1PK=FEED#{user_id}`. <!-- VERIFIED: app_single_table defined in local-ddb-init.py:217 with GSI1-GSI5 -->

Stories will use the same `app_single_table` but with a distinct entity type (`Story`) and separate GSI partition to avoid mixing ephemeral and permanent content in query results.

### 3.2 Media Upload

The existing presign upload flow handles image uploads to S3 with content-type validation. The upload endpoint is `POST /ui/newsfeed/uploads/image` (see `async def upload_image` at newsfeed.py:2621). <!-- CORRECTED: was POST /ui/newsfeed/presign-upload, actually POST /ui/newsfeed/uploads/image at newsfeed.py:2620-2621 --> Stories will reuse this mechanism for image uploads and extend it for short video clips (up to 60 seconds, capped at 50MB).

### 3.3 Following System

`app/services/social.py` (SOC-001) provides `get_following(user_id, *, limit=20, cursor=None)` which returns a tuple of `(List[Dict], Optional[str])` -- a list of following records and a pagination cursor. <!-- CORRECTED: was app/services/following.py with get_followed_user_ids(user_id), actually app/services/social.py with get_following() (social.py:166-184). The function returns paginated following items, NOT a flat list of user IDs. Callers must extract user IDs from the returned dicts and handle pagination. -->

### 3.4 Gaps

1. No DynamoDB entity type for ephemeral content with TTL-based expiry
2. No story bar or full-screen viewer components in the frontend
3. No view tracking mechanism for individual content items
4. No "highlights" concept for promoting ephemeral content to permanent

---

## 4. Technical Architecture

### 4.1 System Diagram

```
+-------------------+       +-------------------+       +----------------------+
|   Feed Page       |       |   Backend API     |       |   DynamoDB           |
|                   |       |  (stories router) |       |   app_single_table   |
| +---------------+ |       |                   |       |                      |
| | Story Bar     | |       |  GET /stories/bar |------>| GSI1PK:STORIES#{uid} |
| | [O] [O] [O]   | |------>|  (per followed    |       | TTL: ttl_epoch       |
| |  A   B   C    | |       |   creator query)  |       |                      |
| +---------------+ |       |                   |       | pk:STORY#{id}, sk:META|
|                   |       |  POST /stories    |------>| pk:STORYVIEW#{id}    |
| +---------------+ |       |  POST /view       |------>|   sk:VIEWER#{uid}    |
| | Story Viewer  | |       |  POST /highlight  |       |                      |
| | [======----]  | |       +-------------------+       | pk:USER#{uid}        |
| | Full-screen   | |              |                    |   sk:HIGHLIGHT#{gid} |
| | auto-advance  | |              v                    +----------------------+
| +---------------+ |       +-------------------+
|                   |       |   S3 Bucket       |       +----------------------+
| +---------------+ |       |  story-media/     |       |  Following Service   |
| | Story         | |<------| {story_id}.jpg    |       |  (SOC-001)           |
| | Composer      | |       +-------------------+       | get_followed_user_ids|
| | Upload media  | |                                   +----------------------+
| | + text overlay| |
| +---------------+ |
+-------------------+
```

### 4.2 Data Flow -- Story Creation

1. Creator opens StoryComposer, selects image or records short video
2. Frontend calls existing `POST /ui/newsfeed/presign-upload` for S3 presign
3. Frontend PUTs media blob to S3 via presigned URL
4. Frontend calls `POST /ui/stories` with media_url, text_overlay, link sticker
5. Backend writes Story item to `app_single_table` with `ttl_epoch = now + 86400`
6. Backend returns story_id + expires_at

### 4.3 Data Flow -- Story Bar

1. Viewer opens Feed page
2. Frontend calls `GET /ui/stories/bar`
3. Backend calls `get_followed_user_ids(user_id)` from SOC-001
4. For each followed creator (capped at 200), query GSI1 for `STORIES#{creator_id}`, limit 1, filter `expires_at > now`
5. For each active story found, check if viewer has seen it (`STORYVIEW#{story_id}`, `VIEWER#{viewer_id}`)
6. Return bar entries with `has_unseen` flag

### 4.4 Data Flow -- Story Viewing

1. Viewer taps creator avatar in story bar
2. Frontend opens full-screen StoryViewer overlay
3. Frontend calls `GET /ui/stories/user/{user_id}` to get all active stories for that creator
4. For each story slide that becomes visible, frontend calls `POST /ui/stories/{story_id}/view`
5. Backend writes idempotent view record, increments `view_count` on first view

---

## 5. Data Model Deep Dive

### 5.1 Story Item (DynamoDB `app_single_table`)

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `pk` | S | `STORY#{story_id}` | `"STORY#st_a1b2c3d4e5f6"` |
| `sk` | S | `META` | `"META"` |
| `Entity` | S | `Story` | `"Story"` |
| `story_id` | S | `st_<uuid4_hex>` | `"st_a1b2c3d4e5f6a1b2c3d4e5f6a1b2"` |
| `author_id` | S | Creator's user sub | `"alice@test.local"` |
| `media_type` | S | `image` or `video` | `"image"` |
| `media_url` | S | S3 key for the uploaded media | `"story-media/st_abc123.jpg"` |
| `media_thumbnail_url` | S (optional) | Thumbnail for video stories | `"story-media/st_abc123_thumb.jpg"` |
| `text_overlay` | S (optional) | Max 200 chars, displayed over media | `"Check out our new feature!"` |
| `link_url` | S (optional) | Swipe-up / sticker link | `"https://example.com/promo"` |
| `link_label` | S (optional) | Display text for link | `"Learn More"` |
| `duration_seconds` | N (optional) | Video duration | `30` |
| `created_at` | S | ISO 8601 timestamp | `"2026-05-27T10:00:00Z"` |
| `expires_at` | N | Unix epoch = created_at + 86400 | `1748476800` |
| `ttl_epoch` | N | Same as `expires_at`; DynamoDB TTL attribute | `1748476800` |
| `view_count` | N | Denormalized count, incremented on first view | `42` |
| `highlighted` | BOOL | `false` by default; `true` removes TTL | `false` |
| `highlight_group_id` | S (optional) | Groups highlighted stories on profile | `"hg_travel123"` |
| `GSI1PK` | S | `STORIES#{author_id}` | `"STORIES#alice@test.local"` |
| `GSI1SK` | S | `{created_at}#STORY#{story_id}` | `"2026-05-27T10:00:00Z#STORY#st_abc123"` |

**Example item:**

```json
{
  "pk": "STORY#st_a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "sk": "META",
  "Entity": "Story",
  "story_id": "st_a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "author_id": "alice@test.local",
  "media_type": "image",
  "media_url": "story-media/st_a1b2c3d4e5f6.jpg",
  "text_overlay": "Behind the scenes!",
  "created_at": "2026-05-27T10:00:00Z",
  "expires_at": 1748476800,
  "ttl_epoch": 1748476800,
  "view_count": 0,
  "highlighted": false,
  "GSI1PK": "STORIES#alice@test.local",
  "GSI1SK": "2026-05-27T10:00:00Z#STORY#st_a1b2c3d4e5f6"
}
```

### 5.2 Story View Item

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `pk` | S | `STORYVIEW#{story_id}` | `"STORYVIEW#st_abc123"` |
| `sk` | S | `VIEWER#{viewer_user_id}` | `"VIEWER#bob@test.local"` |
| `Entity` | S | `StoryView` | `"StoryView"` |
| `viewed_at` | S | ISO 8601 timestamp | `"2026-05-27T14:30:00Z"` |
| `ttl_epoch` | N | `story.expires_at + 86400` (cleanup 24h after story expires) | `1748563200` |

### 5.3 Story Highlight Group

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `pk` | S | `USER#{author_id}` | `"USER#alice@test.local"` |
| `sk` | S | `HIGHLIGHT#{highlight_group_id}` | `"HIGHLIGHT#hg_travel123"` |
| `Entity` | S | `StoryHighlightGroup` | `"StoryHighlightGroup"` |
| `title` | S | Display name | `"Travel"` |
| `cover_url` | S (optional) | Cover image URL | `"story-media/cover_travel.jpg"` |
| `created_at` | S | ISO 8601 | `"2026-05-27T10:00:00Z"` |

### 5.4 Access Patterns

| Access Pattern | Table/Index | Key Condition | Filter |
|---------------|-------------|---------------|--------|
| Get a story by ID | Table PK/SK | `pk = STORY#{story_id}, sk = META` | None |
| List creator's active stories | GSI1 | `GSI1PK = STORIES#{author_id}` | `expires_at > now OR highlighted = true` |
| Check if viewer has seen a story | Table PK/SK | `pk = STORYVIEW#{story_id}, sk = VIEWER#{viewer_id}` | None |
| List viewers of a story | Table PK | `pk = STORYVIEW#{story_id}` | None |
| List highlight groups for a user | Table PK | `pk = USER#{author_id}`, begins_with `sk = HIGHLIGHT#` | None |
| Get highlighted stories in a group | GSI1 | `GSI1PK = STORIES#{author_id}` | `highlighted = true AND highlight_group_id = X` |

### 5.5 DynamoDB TTL Configuration

The `app_single_table` must have TTL enabled on the `ttl_epoch` attribute. Verify in `scripts/local-ddb-init.py`:

```python
# After table creation, enable TTL:
# ddb_client.update_time_to_live(
#     TableName="app_single_table",
#     TimeToLiveSpecification={"Enabled": True, "AttributeName": "ttl_epoch"}
# )
```

Note: DynamoDB TTL deletion is eventual (items may persist up to 48 hours past TTL in worst case). The `expires_at > now()` filter in queries ensures expired stories are never returned even if not yet physically deleted.

---

## 6. API Contract Design

### 6.1 Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/stories` | `require_ui_session` | Create a new story (image or video) |
| GET | `/ui/stories/bar` | `require_ui_session` | Get story bar data (followed creators with active stories) |
| GET | `/ui/stories/user/{user_id}` | `require_ui_session` | Get all active stories for a specific creator |
| GET | `/ui/stories/{story_id}` | `require_ui_session` | Get single story detail |
| DELETE | `/ui/stories/{story_id}` | `require_ui_session` | Delete own story early |
| POST | `/ui/stories/{story_id}/view` | `require_ui_session` | Record a view (idempotent per viewer) |
| GET | `/ui/stories/{story_id}/viewers` | `require_ui_session` | List viewers (owner only) |
| POST | `/ui/stories/{story_id}/highlight` | `require_ui_session` | Pin story to highlights (removes TTL) |
| DELETE | `/ui/stories/{story_id}/highlight` | `require_ui_session` | Unpin story from highlights (re-applies TTL) |
| GET | `/ui/stories/highlights/{user_id}` | `require_ui_session` | List highlight groups + stories for a user profile |
| POST | `/ui/stories/highlights/groups` | `require_ui_session` | Create a highlight group |
| DELETE | `/ui/stories/highlights/groups/{group_id}` | `require_ui_session` | Delete a highlight group |

### 6.2 POST `/ui/stories` -- Create Story

**Request:**

```json
{
  "media_type": "image",
  "media_url": "story-media/st_abc123.jpg",
  "text_overlay": "Behind the scenes!",
  "link_url": "https://example.com/promo",
  "link_label": "Learn More",
  "duration_seconds": null
}
```

**Response (201):**

```json
{
  "story_id": "st_a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "expires_at": 1748476800,
  "media_url": "/mock/s3/uploads/story-media/st_abc123.jpg",
  "created_at": "2026-05-27T10:00:00Z"
}
```

**Error responses:**
- `400`: Video story over 60 seconds
- `422`: Invalid media_type, text_overlay exceeds 200 chars
- `429`: Max 30 stories per day exceeded

### 6.3 GET `/ui/stories/bar`

**Response (200):**

```json
{
  "bar": [
    {
      "user_id": "alice@test.local",
      "display_name": "Alice",
      "avatar_url": "/mock/s3/avatars/alice.jpg",
      "latest_story_id": "st_abc123",
      "latest_media_url": "/mock/s3/story-media/st_abc123.jpg",
      "story_count": 3,
      "has_unseen": true
    },
    {
      "user_id": "bob@test.local",
      "display_name": "Bob",
      "avatar_url": "/mock/s3/avatars/bob.jpg",
      "latest_story_id": "st_def456",
      "latest_media_url": "/mock/s3/story-media/st_def456.jpg",
      "story_count": 1,
      "has_unseen": false
    }
  ]
}
```

### 6.4 POST `/ui/stories/{story_id}/view`

**Response (200):**

```json
{
  "ok": true,
  "already_viewed": false
}
```

Second call for the same viewer:

```json
{
  "ok": true,
  "already_viewed": true
}
```

### 6.5 GET `/ui/stories/{story_id}/viewers` (Owner Only)

**Response (200):**

```json
{
  "viewers": [
    {"user_id": "bob@test.local", "display_name": "Bob", "viewed_at": "2026-05-27T14:30:00Z"},
    {"user_id": "charlie@test.local", "display_name": "Charlie", "viewed_at": "2026-05-27T15:00:00Z"}
  ],
  "total_count": 2
}
```

### 6.6 Rate Limits

| Endpoint | Per-user | Per-IP | Notes |
|----------|----------|--------|-------|
| POST /stories | 30/day | 60/day | Max stories per day |
| POST /view | 300/hour | 600/hour | High volume expected |
| GET /bar | 60/min | 120/min | Called on every feed page load |
| All others | 60/min | 120/min | Standard newsfeed group |

---

## 7. Backend Implementation

### 7.1 Story Creation

```python
@router.post("/stories", status_code=201)
def create_story(
    req: CreateStoryRequest,
    ctx=Depends(require_ui_session),
):
    user_id = ctx["user_sub"]
    story_id = f"st_{uuid.uuid4().hex}"
    created_at = now_iso()
    expires_at = int(time.time()) + 86400  # 24 hours

    if req.media_type == "video" and req.duration_seconds and req.duration_seconds > 60:
        raise HTTPException(status_code=400, detail="video stories must be 60 seconds or less")

    # Rate limit: max 30 stories per day
    _check_daily_story_limit(user_id)

    item = {
        "pk": f"STORY#{story_id}",
        "sk": "META",
        "Entity": "Story",
        "story_id": story_id,
        "author_id": user_id,
        "media_type": req.media_type,
        "media_url": req.media_url,
        "text_overlay": req.text_overlay,
        "link_url": req.link_url,
        "created_at": created_at,
        "expires_at": expires_at,
        "ttl_epoch": expires_at,
        "view_count": 0,
        "highlighted": False,
        "GSI1PK": f"STORIES#{user_id}",
        "GSI1SK": f"{created_at}#STORY#{story_id}",
    }
    ddb_put_item(item)
    return {"story_id": story_id, "expires_at": expires_at}
```

### 7.2 Story Bar Query

```python
@router.get("/stories/bar")
def get_story_bar(ctx=Depends(require_ui_session)):
    user_id = ctx["user_sub"]
    # <!-- CORRECTED: get_followed_user_ids does not exist. Use get_following() from app/services/social.py:166 -->
    # get_following returns (items: List[Dict], cursor: Optional[str]); must paginate and extract user IDs
    followed_items, _ = get_following(user_id, limit=200)
    followed_ids = [it.get("following_user_id") or it.get("sk", "").replace("FOLLOWING#", "") for it in followed_items]
    now = int(time.time())
    bar = []
    for creator_id in followed_ids[:200]:
        resp = tbl.query(
            KeyConditionExpression="GSI1PK = :pk",
            ExpressionAttributeValues={":pk": f"STORIES#{creator_id}"},
            IndexName="GSI1",
            ScanIndexForward=False,
            Limit=1,
        )
        items = resp.get("Items", [])
        if items and items[0].get("expires_at", 0) > now:
            bar.append({
                "user_id": creator_id,
                "latest_story_id": items[0]["story_id"],
                "latest_media_url": items[0]["media_url"],
                "story_count": resp.get("Count", 1),
                "has_unseen": not _has_viewed_latest(user_id, items[0]["story_id"]),
            })
    return {"bar": bar}
```

### 7.3 View Recording

```python
@router.post("/stories/{story_id}/view")
def record_story_view(story_id: str, ctx=Depends(require_ui_session)):
    viewer_id = ctx["user_sub"]
    story = ddb_get_item({"pk": f"STORY#{story_id}", "sk": "META"})
    if not story:
        raise HTTPException(status_code=404, detail="story not found")

    view_key = {"pk": f"STORYVIEW#{story_id}", "sk": f"VIEWER#{viewer_id}"}
    existing = ddb_get_item(view_key)
    if existing:
        return {"ok": True, "already_viewed": True}

    ddb_put_item({
        **view_key,
        "Entity": "StoryView",
        "viewed_at": now_iso(),
        "ttl_epoch": story.get("expires_at", 0) + 86400,
    })
    tbl.update_item(
        Key={"pk": f"STORY#{story_id}", "sk": "META"},
        UpdateExpression="ADD view_count :one",
        ExpressionAttributeValues={":one": 1},
    )
    return {"ok": True, "already_viewed": False}
```

### 7.4 Highlight Pinning

```python
@router.post("/stories/{story_id}/highlight")
def highlight_story(story_id: str, body: HighlightRequest, ctx=Depends(require_ui_session)):
    user_id = ctx["user_sub"]
    story = ddb_get_item({"pk": f"STORY#{story_id}", "sk": "META"})
    if not story or story["author_id"] != user_id:
        raise HTTPException(status_code=403, detail="forbidden")

    tbl.update_item(
        Key={"pk": f"STORY#{story_id}", "sk": "META"},
        UpdateExpression="SET highlighted = :t, highlight_group_id = :g REMOVE ttl_epoch",
        ExpressionAttributeValues={":t": True, ":g": body.group_id},
    )
    return {"ok": True}
```

---

## 8. Frontend Component Design

### 8.1 Component Tree

```
FeedPage
  |-- StoryBar (new)
  |     |-- "Your Story" button (+ icon overlay if no active story)
  |     |-- CreatorStoryAvatar[] (horizontal scroll)
  |           |-- Avatar image with ring (gradient=unseen, gray=seen)
  |           |-- Display name below
  |           |-- onClick -> openStoryViewer(userId)
  |-- PostList (existing)

StoryViewer (new, overlay, z-50)
  |-- ProgressBarSegments (one per slide)
  |-- StorySlide
  |     |-- MediaDisplay (img or video)
  |     |-- TextOverlay (positioned over media)
  |     |-- LinkSticker (swipe-up / tap)
  |     |-- CreatorInfo (avatar + name + timestamp, top-left)
  |     |-- CloseButton (X, top-right)
  |-- TapZones (left=prev, center=pause, right=next)
  |-- SwipeGesture (left=next creator, right=prev creator)
  |-- ViewersList (pull up from bottom, creator only)

StoryComposer (new, dialog)
  |-- MediaPicker (file input for image/video)
  |-- TextOverlayInput (max 200 chars)
  |-- LinkStickerInput (URL + label)
  |-- PostStoryButton

StoryHighlights (new, profile section)
  |-- HighlightGroup[]
        |-- Cover thumbnail
        |-- Group title
        |-- onClick -> open highlight stories in StoryViewer
```

### 8.2 New Files

| File | Purpose |
|------|---------|
| `frontend/src/pages/feed/StoryBar.tsx` | Horizontal scrollable bar of creator avatars with story rings |
| `frontend/src/pages/feed/StoryViewer.tsx` | Full-screen overlay: swipeable slides, progress bars, auto-advance |
| `frontend/src/pages/feed/StoryComposer.tsx` | Story creation dialog: image/video upload, text overlay, link sticker |
| `frontend/src/pages/feed/StoryHighlights.tsx` | Profile section showing highlight groups with story thumbnails |
| `frontend/src/api/endpoints/stories.ts` | API client functions for all story endpoints |

### 8.3 React Query Hooks

```typescript
// frontend/src/api/endpoints/stories.ts
export const useStoryBar = () => useQuery({
  queryKey: ["stories", "bar"],
  queryFn: () => client.get("/ui/stories/bar").then(r => r.data),
  refetchInterval: 60_000,  // Refresh every minute
});

export const useCreatorStories = (userId: string) => useQuery({
  queryKey: ["stories", "user", userId],
  queryFn: () => client.get(`/ui/stories/user/${userId}`).then(r => r.data),
  enabled: !!userId,
});

export const useRecordView = () => useMutation({
  mutationFn: (storyId: string) => client.post(`/ui/stories/${storyId}/view`),
});

export const useStoryViewers = (storyId: string) => useQuery({
  queryKey: ["stories", storyId, "viewers"],
  queryFn: () => client.get(`/ui/stories/${storyId}/viewers`).then(r => r.data),
});
```

### 8.4 StoryViewer Interaction Model

- **Progress bars**: Array of thin bars at the top, one per story slide. Active bar fills over 5 seconds (image) or video duration. Paused when user holds down.
- **Tap left**: Go to previous slide (or previous creator if at first slide).
- **Tap right**: Go to next slide (or next creator if at last slide).
- **Tap center**: Pause/resume auto-advance.
- **Swipe left**: Jump to next creator's stories.
- **Swipe right**: Jump to previous creator's stories.
- **Close (X)**: Return to feed page.
- **View recorded**: `POST /stories/{id}/view` called when slide becomes visible (fires once per session per story via a local `viewedSet`).

---

## 9. Security & Privacy Considerations

### 9.1 Authentication & Authorization

- All endpoints use `require_ui_session` (cookie auth with CSRF enforcement).
- Delete story: only the author can delete their own story (`story.author_id == ctx["user_sub"]`).
- Viewer list: only the author can see who viewed their story.
- Highlight actions: only the author can pin/unpin their own stories.

### 9.2 Input Validation

- `text_overlay`: Max 200 characters. Sanitized for XSS (HTML escaped before rendering).
- `link_url`: Must be a valid URL (validated via Pydantic `HttpUrl`). Displayed as a clickable sticker, not rendered as raw HTML.
- `media_type`: Enum `"image" | "video"`. No arbitrary strings.
- `duration_seconds`: Max 60 for videos. Enforced server-side.

### 9.3 Privacy

- Story views are tracked per user. Viewers are aware their view is recorded (UI shows "Seen by N" to the creator).
- Stories from private accounts are only visible to approved followers (if follower approval is implemented via SOC-001).
- DynamoDB TTL ensures expired story view records are cleaned up automatically.

### 9.4 Abuse Prevention

- Rate limit: max 30 stories per day per creator.
- Media size capped at 50MB per story.
- Link stickers are not rendered as raw HTML to prevent XSS.
- Content moderation: Stories are subject to the same content reporting system as posts (via existing `content_reports` infrastructure).

---

## 10. Performance & Scalability

### 10.1 Story Bar Query Cost

The story bar queries GSI1 for each followed creator (up to 200). Each query reads 1 item (Limit=1). Plus 1 `get_item` per active story to check view status.

**Worst case**: 200 followed creators, all with active stories = 200 GSI1 queries + 200 get_items = 400 DDB reads.

**Optimization**: Batch the view-check queries using `BatchGetItem` (up to 100 keys per batch). This reduces 200 individual get_items to 2 batch requests.

**Caching**: The story bar response can be cached in React Query for 60 seconds (`refetchInterval: 60_000`). The bar data changes slowly (new stories appear every few hours, not seconds).

### 10.2 DynamoDB Capacity

| Operation | RCU per Request | WCU per Request | Frequency |
|-----------|----------------|-----------------|-----------|
| Create story | 0 | 1 | ~30/day/creator |
| Story bar query | ~400 (200 queries) | 0 | 1/min/viewer |
| Record view | 2 (get + put) | 2 (put + update) | 1/story/viewer |
| Highlight | 1 (get) | 1 (update) | Rare |

**Recommendation**: Use on-demand billing for `app_single_table` (already configured). The story bar query is the heaviest operation and is bounded by the 200-follower cap.

### 10.3 Known Bottlenecks

- **Story bar N+1 query**: Querying GSI1 per followed creator is inherently N+1. For users following 200+ creators, this adds ~500ms latency. Mitigation: cap at 200, cache results aggressively, consider a denormalized "active story creators" list updated on story creation/expiry.
- **DynamoDB TTL lag**: Items may persist up to 48 hours past TTL. The `expires_at > now` filter in queries handles this correctly.

---

## 11. Migration & Rollback Plan

### 11.1 Feature Flags

| Variable | Default | Description |
|----------|---------|-------------|
| `STORIES_ENABLED` | `true` | Master feature flag |
| `STORY_MAX_DURATION_SECONDS` | `60` | Maximum video story length |
| `STORY_MAX_MEDIA_SIZE_BYTES` | `52428800` (50MB) | Maximum upload size |
| `STORY_EXPIRY_SECONDS` | `86400` (24h) | Story lifetime |
| `STORY_BAR_MAX_FOLLOWED` | `200` | Max followed creators to query for story bar |
| `STORY_MAX_PER_DAY` | `30` | Max stories a creator can post per day |

Add to `app/core/settings.py`:

```python
stories_enabled: bool = os.environ.get("STORIES_ENABLED", "1") not in ("0", "false", "False")
story_max_duration_seconds: int = int(os.environ.get("STORY_MAX_DURATION_SECONDS", "60"))
story_max_media_size_bytes: int = int(os.environ.get("STORY_MAX_MEDIA_SIZE_BYTES", "52428800"))
story_expiry_seconds: int = int(os.environ.get("STORY_EXPIRY_SECONDS", "86400"))
story_bar_max_followed: int = int(os.environ.get("STORY_BAR_MAX_FOLLOWED", "200"))
story_max_per_day: int = int(os.environ.get("STORY_MAX_PER_DAY", "30"))
```

### 11.2 Incremental Deployment

1. **Phase 1 (backend)**: Deploy story CRUD endpoints + DDB TTL config behind `STORIES_ENABLED` flag.
2. **Phase 2 (frontend)**: Deploy StoryBar and StoryViewer. Bar only visible when `stories_enabled` is true (returned via a `/ui/features` config endpoint or feature flag check).
3. **Phase 3 (highlights)**: Deploy highlight pinning + profile section.
4. **Phase 4 (GA)**: Enable flag, monitor TTL behavior and bar query latency.

### 11.3 Rollback

- Set `STORIES_ENABLED=false`. StoryBar hidden. Endpoints return 404.
- Existing stories will auto-expire via TTL within 24 hours (48h worst case).
- Highlighted stories persist (no TTL) but are hidden from the UI.
- No database migration needed -- Story items use the existing `app_single_table`.

---

## 12. Testing Strategy

### 12.1 Unit Tests (pytest)

| # | Test | File |
|---|------|------|
| 1 | `CreateStoryRequest` validates media_type enum | `tests/test_models.py` |
| 2 | Reject video story over 60 seconds | `tests/test_stories.py` |
| 3 | Story item has correct TTL epoch (created_at + 86400) | `tests/test_stories.py` |
| 4 | View recording is idempotent | `tests/test_stories.py` |
| 5 | Highlight removes ttl_epoch from item | `tests/test_stories.py` |
| 6 | Unhighlight re-applies ttl_epoch | `tests/test_stories.py` |
| 7 | Story bar only includes followed creators | `tests/test_stories.py` |
| 8 | Story bar filters expired stories | `tests/test_stories.py` |
| 9 | Daily story limit enforced | `tests/test_stories.py` |
| 10 | Only author can view viewer list | `tests/test_stories.py` |

### 12.2 E2E Tests

**Test File:** `frontend/e2e/stories.spec.ts`

**Section 1: Story CRUD API (6 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | Create image story | 201; response has `story_id`, `expires_at` ~24h from now |
| 2 | Create video story with text overlay | 201; `text_overlay` stored |
| 3 | Reject video story over 60 seconds | 400; "60 seconds or less" |
| 4 | Get own stories list | 200; contains created story with correct `media_type` |
| 5 | Delete own story | 200; subsequent GET returns 404 |
| 6 | Cannot delete another user's story | 403 |

**Section 2: Story Bar API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 7 | Story bar includes followed creator with active story | Bar contains entry for creator with `has_unseen: true` |
| 8 | Story bar excludes expired stories | Create story, wait for TTL or mock expiry; bar empty |
| 9 | Story bar shows `has_unseen: false` after viewing | Record view; re-fetch bar; `has_unseen` is false |
| 10 | Story bar excludes unfollowed creators | Unfollow; re-fetch bar; creator absent |

**Section 3: View Tracking API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 11 | Record view returns `already_viewed: false` on first view | POST view; 200 |
| 12 | Record view is idempotent (second call returns `already_viewed: true`) | POST view twice; second returns `already_viewed: true` |
| 13 | View count increments on first view only | Check `view_count` after two view calls; equals 1 |
| 14 | Creator can list viewers of their story | GET viewers; contains viewer's user ID |

**Section 4: Highlights API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 15 | Highlight a story removes TTL | POST highlight; GET story; `highlighted: true` |
| 16 | Unhighlight re-applies TTL | DELETE highlight; GET story; `highlighted: false`, `ttl_epoch` set |
| 17 | Create highlight group | POST group; 201; has `highlight_group_id` |
| 18 | List highlights for user profile | GET highlights; contains highlighted story in correct group |

**Section 5: Story Viewer UI (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 19 | Story bar visible on feed page | Navigate to `/feed`; story bar container visible |
| 20 | Clicking story ring opens viewer overlay | Click avatar; full-screen viewer visible with progress bar |
| 21 | Closing viewer returns to feed | Click X; viewer dismissed; feed page visible |

---

## 13. Monitoring & Alerting

### 13.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `story_created_total` | Counter | `media_type` | Stories created |
| `story_view_total` | Counter | - | Story views recorded |
| `story_view_duplicate_total` | Counter | - | Duplicate view attempts (already_viewed) |
| `story_bar_query_latency_ms` | Histogram | - | Story bar endpoint latency |
| `story_bar_creators_returned` | Histogram | - | Number of creators in bar response |
| `story_highlighted_total` | Counter | - | Stories pinned to highlights |
| `story_expired_total` | Counter | - | Stories expired via TTL (from DDB Streams if configured) |

### 13.2 Dashboard Queries

- **Creation rate**: `rate(story_created_total[1h])` -- stories per hour
- **Bar latency**: `histogram_quantile(0.99, story_bar_query_latency_ms)` -- p99 bar query time
- **View rate**: `rate(story_view_total[1h])` -- views per hour

### 13.3 Alert Thresholds

| Alert | Condition | Severity |
|-------|-----------|----------|
| Story bar query slow | p99 latency > 2s for 5 minutes | Warning |
| Story creation errors | 5xx rate > 5% on POST /stories for 5 minutes | Critical |
| High story volume from single user | > 30 stories/day from one user (bypassing limit) | Warning |
| TTL not working | Stories older than 48h still returned by queries | Critical |

---

## 14. Open Questions & Risks

### 14.1 Unresolved Decisions

1. **Story reactions**: Should viewers be able to react to stories (emoji, quick reply)? This would require additional DDB items and a reply mechanism. Recommendation: defer to a future ticket.
2. **Story sharing**: Should users be able to share someone's story to their own DMs? This adds a new message kind (`story_share`). Recommendation: defer.
3. **Analytics dashboard**: Should creators have a dedicated analytics page showing view trends over time? The current design only shows view count + viewer list. A full analytics dashboard is a separate feature.
4. **Music/audio overlay**: Should stories support background music? This would require audio upload + mixing. Recommendation: out of scope for MVP.

### 14.2 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Story bar query too slow for users following 200+ creators | Medium | High | Cap at 200, aggressive caching, consider denormalized index |
| DynamoDB TTL lag causes expired stories to appear | Low | Low | `expires_at > now` filter in all queries |
| Video story playback on mobile Safari | Medium | Medium | Test thoroughly; ensure `<video>` element uses `playsinline` attribute |
| S3 lifecycle rule conflicts with highlighted stories | Low | Medium | Highlighted stories have no TTL; exclude from lifecycle rule by prefix |

### 14.3 Dependency Risks

- **SOC-001 (Follow System)**: Required. The story bar cannot function without `get_following()` from `app/services/social.py`. If SOC-001 is not deployed, the story bar returns empty. <!-- CORRECTED: was get_followed_user_ids, actually get_following -->
- **DynamoDB TTL**: Must be enabled on `app_single_table`. If not enabled, stories never expire.

---

## 15. Implementation Timeline

### Phase 1: Backend Story CRUD (Days 1-3)

| Day | Task |
|-----|------|
| 1 | Add `STORIES_*` settings to `app/core/settings.py`. Create `app/services/stories.py` with story CRUD functions. Create Pydantic models. |
| 2 | Create `app/routers/stories.py` with story creation, deletion, get, and list endpoints. Register in `app/main.py`. |
| 3 | Implement view tracking (idempotent view recording, view count increment, viewer list). Write unit tests. |

### Phase 2: Backend Bar + Highlights (Days 4-5)

| Day | Task |
|-----|------|
| 4 | Implement story bar endpoint with follow system integration. Optimize with BatchGetItem for view checks. |
| 5 | Implement highlight pinning/unpinning, highlight groups CRUD, and highlights list endpoint. |

### Phase 3: Frontend StoryBar + Viewer (Days 6-9)

| Day | Task |
|-----|------|
| 6 | Create `StoryBar.tsx` with horizontal scroll, avatar rings, unseen indicators. Integrate into FeedPage. |
| 7 | Create `StoryViewer.tsx` with full-screen overlay, progress bars, tap/swipe navigation. |
| 8 | Create `StoryComposer.tsx` with media picker, text overlay, link sticker. Wire presign upload. |
| 9 | Create `StoryHighlights.tsx` for profile section. Add API client functions to `stories.ts`. |

### Phase 4: Frontend Types + Polish (Days 10-11)

| Day | Task |
|-----|------|
| 10 | Add TypeScript types to `api/types.ts`. Add React Query hooks. Handle loading/error states. |
| 11 | Cross-browser testing (mobile Safari video playback), accessibility (keyboard navigation in viewer), responsive design. |

### Phase 5: E2E Tests + QA (Days 12-14)

| Day | Task |
|-----|------|
| 12 | Write `frontend/e2e/stories.spec.ts` sections 1-3 (CRUD, bar, view tracking). |
| 13 | Write sections 4-5 (highlights, UI tests). |
| 14 | Full suite run, fix flaky tests, manual QA, code review. |

---

## 16. Files to Create

| File | Purpose |
|------|---------|
| `app/services/stories.py` | Story CRUD, view tracking, highlights, bar query |
| `app/routers/stories.py` | API endpoints (or integrate into newsfeed.py) |
| `frontend/src/pages/feed/StoryBar.tsx` | Horizontal story bar component |
| `frontend/src/pages/feed/StoryViewer.tsx` | Full-screen story viewer overlay |
| `frontend/src/pages/feed/StoryComposer.tsx` | Story creation dialog |
| `frontend/src/pages/feed/StoryHighlights.tsx` | Profile highlights section |
| `frontend/src/api/endpoints/stories.ts` | API client for story endpoints |
| `frontend/e2e/stories.spec.ts` | E2E tests |

## 17. Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register stories router |
| `app/core/settings.py` | Add `STORIES_*` settings | <!-- VERIFIED: settings.py is a frozen dataclass (1197 lines); no STORIES_* settings exist yet -->
| `scripts/local-ddb-init.py` | Ensure `ttl_epoch` TTL attribute is enabled on `app_single_table` | <!-- VERIFIED: app_single_table defined at local-ddb-init.py:217 -->
| `frontend/src/api/types.ts` | Add `Story`, `StoryBarEntry`, `StoryHighlightGroup` interfaces |
| `frontend/src/pages/feed/FeedPage.tsx` | Add `StoryBar` above posts list |
| `frontend/src/App.tsx` | No new route needed (overlay pattern) |

---

## 18. Dependencies

- **SOC-001 (Follow System)**: Required for `get_following()` (app/services/social.py:166) to populate the story bar. <!-- CORRECTED: was get_followed_user_ids, actually get_following -->
- **Newsfeed upload**: Reused for story media upload (POST /ui/newsfeed/uploads/image, newsfeed.py:2620). <!-- CORRECTED: was presign-upload, actually uploads/image -->
- **DynamoDB TTL**: Must be enabled on the `app_single_table` for the `ttl_epoch` attribute. <!-- VERIFIED: app_single_table at local-ddb-init.py:217 -->

---

## 19. Acceptance Criteria

1. Creator can post an image story that appears in the story bar for followers.
2. Creator can post a video story (up to 60 seconds) with a text overlay.
3. Stories expire and disappear from the bar after 24 hours.
4. Viewer can tap a creator's ring to open the full-screen story viewer.
5. Story viewer auto-advances slides and supports tap/swipe navigation.
6. Each view is recorded once per user per story (idempotent).
7. Creator can see view count and viewer list on their own stories.
8. Creator can highlight a story to make it permanent on their profile.
9. Removing a highlight re-applies the 24-hour TTL from the original creation time.
10. Story bar shows unseen indicator (colored ring) vs. seen (gray ring).

---

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| Newsfeed router file | `app/routers/newsfeed.py` | 4998 lines | VERIFIED (ticket said ~5000) |
| `app_single_table` DDB table | `scripts/local-ddb-init.py` | 217 | VERIFIED: PK=pk, SK=sk, GSI1-GSI5 + GSI_SCHEDULE_DUE |
| Feed index uses `GSI1PK=FEED#{user_id}` | `app/routers/newsfeed.py` | passim | VERIFIED |
| Image upload endpoint | `app/routers/newsfeed.py` | 2620-2621 | VERIFIED: `@router.post("/uploads/image")` / `async def upload_image(...)` (ticket said `/ui/newsfeed/presign-upload` -- CORRECTED) |
| Following service | `app/services/social.py` | 166-184 | VERIFIED: `get_following(user_id, *, limit=20, cursor=None) -> Tuple[List[Dict], Optional[str]]` (ticket said `app/services/following.py` with `get_followed_user_ids` -- CORRECTED) |
| `app/services/following.py` existence | N/A | N/A | DOES NOT EXIST (CORRECTED to `app/services/social.py`) |
| `app/core/settings.py` | `app/core/settings.py` | 1-1197 | VERIFIED: frozen dataclass; no `STORIES_*` settings exist yet |
| `require_ui_session` auth dependency | `app/auth/deps.py` | 184+ | VERIFIED: `async def get_authenticated_user(request: Request) -> AuthenticatedUser` |

### Key Corrections Summary

1. **`app/services/following.py` does not exist** -- following logic is in `app/services/social.py`.
2. **`get_followed_user_ids(user_id)` does not exist** -- the actual function is `get_following(user_id, *, limit=20, cursor=None)` at social.py:166, which returns `(List[Dict], Optional[str])` (paginated following items + cursor, NOT a flat list of user IDs).
3. **`POST /ui/newsfeed/presign-upload` does not exist** -- the actual upload endpoint is `POST /ui/newsfeed/uploads/image` at newsfeed.py:2620.
