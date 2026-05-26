# FEED-001: Video Posts in Newsfeed

**Ticket**: FEED-001
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-25

---

## 1. Overview & Motivation

### 1.1 Purpose

FEED-001 adds first-class video support to the newsfeed, allowing creators to publish posts with an embedded video player. Videos that have been uploaded, transcoded, and published through the existing VOD pipeline (VOD-001 through VOD-012) can be attached to newsfeed posts. The video plays inline using the shared `MediaPlayer` HLS component (MEDIA-001), bringing the same adaptive-bitrate playback experience from the Video Player Page into the social feed.

### 1.2 User Stories

| Actor | Story | Acceptance |
|-------|-------|------------|
| Creator | As a creator, I want to attach one of my published videos to a newsfeed post, so my followers can watch it directly in their feed. | Video picker shows only `published` videos; post appears with inline player. |
| Creator | As a creator, I want to add caption text alongside a video post, so I can provide context or commentary. | Both `video_id` and text content fields are stored and rendered together. |
| Creator | As a creator, I want to lock a video post behind a paywall, so viewers must pay to watch the video. | Locked video posts show blurred thumbnail + lock overlay; unlocking reveals player. |
| Viewer | As a viewer, I want to watch a video post inline in my feed without navigating to a separate page. | `MediaPlayer` renders HLS manifest; playback entitlement is auto-issued on load. |
| Viewer | As a viewer, I want to tip, react to, and comment on video posts the same way I do text posts. | All existing post interactions work identically on video posts. |

### 1.3 Why This Is Needed Now

The VOD pipeline is complete (VOD-001 through VOD-012) and creators can upload, transcode, and publish videos. However, the only way to share a video is via direct link to the Video Player Page. Embedding videos in the social feed is the primary discovery mechanism for creator content and the most natural engagement surface for viewers. Without this feature, the video infrastructure is underutilized and creators must direct viewers to a separate page.

---

## 2. Current State Analysis

### 2.1 Newsfeed Post Model

> **Implementation note**: There is no separate `app/services/newsfeed.py` — all newsfeed logic (models, helpers, endpoints) lives in `app/routers/newsfeed.py` (~4500 lines).

Posts are stored in the `app_single_table` DynamoDB table with:
- **PK**: `POST#{post_id}`, **SK**: `META`
- **Content fields** (via `ContentFieldsMixin`): `body`, `body_plain`, `body_markdown`, `body_rich`, `body_format`, `body_version`
- **Media fields**: `image_urls: List[str]` (CDN URLs for attached images)
- **Lock fields**: `locked`, `lock_type`, `unlock_price_cents`, `unlock_limit`, etc.
- **Feed index** (GSI1): `FEED#{user_id}` / `{created_at}#POST#{post_id}`

The `CreatePostRequest` model (`app/routers/newsfeed.py`, line 1204) currently accepts `image_urls`, `visibility`, lock fields, scheduling fields, and content envelope fields. There is no `video_id` field.

### 2.2 Video Metadata Model

Videos are stored in the `VideoMetadata` DynamoDB table (VOD-001) with primary key `video_id` (format: `v_<uuid4_hex>`). Key fields relevant to newsfeed embedding:

| Field | Type | Purpose |
|-------|------|---------|
| `video_id` | String | Unique identifier |
| `owner_user_id` | String | Creator who uploaded |
| `title` | String | Display title |
| `status` | String | Lifecycle state (`created`, `encoding`, `published`, `deleted`, etc.) |
| `thumbnail_url` | String (optional) | Poster image URL |
| `hls_manifest_url` | String (optional) | HLS playback manifest |
| `duration_seconds` | Number (optional) | Video length |
| `visibility` | String | `private`, `public`, `unlisted` |

### 2.3 Playback Entitlements

`app/services/playback_entitlements.py` provides `issue_playback_entitlement()` which generates a signed JWT token for time-limited HLS playback access. The Video Player Page (`VideoPlayerPage`) and the video listing endpoint (`/ui/videos/{video_id}`) already call this function. The newsfeed must use the same mechanism.

### 2.4 Existing Video Listing Endpoints

`GET /ui/videos` returns the caller's own videos with optional `status` filter. This endpoint already supports `status=published` filtering, which the video picker dialog will use to list eligible videos.

### 2.5 MediaPlayer Component

`frontend/src/components/shared/MediaPlayer.tsx` is a fully featured HLS player with:
- HLS.js initialization with quality selection
- Loading/error/buffering overlays
- Poster image support via `poster` prop
- VOD mode with seek bar and duration display
- `data-testid="media-player"` for E2E targeting

Props relevant to newsfeed embedding: `src` (HLS manifest URL), `poster` (thumbnail), `title`, `mode="vod"`, `controls={true}`.

### 2.6 Gaps

1. **No `video_id` field** on post model or DDB item
2. **No video validation** on post creation (ownership, status checks)
3. **No video metadata in post response** (title, thumbnail, duration, manifest URL needed for rendering)
4. **No playback entitlement issuance** when loading a video post in the feed
5. **No frontend video picker** in the CreatePost composer
6. **No video rendering** in PostCard component

---

## 3. Technical Design

### 3.1 Data Model Changes

#### 3.1.1 DynamoDB Post Item

Add a single new attribute to the post item:

| Field | Type | Description |
|-------|------|-------------|
| `video_id` | String (optional) | References a `VideoMetadata` record. Null for non-video posts. |

**Mutual exclusivity rule**: A post may have `image_urls` OR `video_id`, not both. If `video_id` is set, `image_urls` must be empty. This is enforced at the API level, not at the DDB level.

#### 3.1.2 Post Response Enrichment

When `video_id` is present, `_post_to_dict` enriches the response with a `video` sub-object:

```python
class PostVideoEmbed(BaseModel):
    video_id: str
    title: str
    thumbnail_url: Optional[str] = None
    duration_seconds: Optional[float] = None
    hls_manifest_url: Optional[str] = None
    playback_token: Optional[str] = None
    playback_expires_at: Optional[int] = None
```

The `video` field is `None` for non-video posts and populated by fetching the video metadata record at read time.

**Locked posts**: When `locked_body=True`, the `video` sub-object is still returned but with `hls_manifest_url=None` and `playback_token=None`. The `thumbnail_url` is included (for the blurred preview) but no playback is possible until unlocked.

### 3.2 Backend Changes

#### 3.2.1 Request Model

File: `app/routers/newsfeed.py` (in `CreatePostRequest`)

```python
class CreatePostRequest(ContentFieldsMixin):
    image_urls: List[str] = Field(default_factory=list)
    video_id: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=r"^v_[a-f0-9]{32}$",
        description="ID of a published video owned by the poster. Mutually exclusive with image_urls.",
    )
    # ... existing fields unchanged ...
```

Add corresponding field to `EditPostRequest`:

```python
class EditPostRequest(ContentFieldsMixin):
    video_id: Optional[str] = Field(default=None, min_length=1, max_length=64, pattern=r"^v_[a-f0-9]{32}$")
    # ... existing fields unchanged ...
```

#### 3.2.2 Create Post Validation

In the `create_post` endpoint (line 2841), add validation after the existing lock logic and before building `post_item`:

```python
# --- Video validation ---
video_id = req.video_id
if video_id:
    # Mutual exclusivity: video_id and image_urls cannot coexist
    if req.image_urls:
        raise HTTPException(
            status_code=400,
            detail="video_id and image_urls are mutually exclusive; provide one or the other",
        )
    # Validate video exists, is owned by poster, and is published
    from app.services.video_metadata_store import get_video
    try:
        video = get_video(video_id)
    except HTTPException:
        raise HTTPException(status_code=400, detail="video not found")
    if video.owner_user_id != user_id:  # Note: video metadata field is `video.id`, not `video.video_id`
        raise HTTPException(status_code=403, detail="video is not owned by this user")
    if video.status != "published":
        raise HTTPException(
            status_code=400,
            detail="video must be in published status to attach to a post",
        )
```

Store `video_id` in the post item:

```python
post_item = {
    # ... existing fields ...
    "video_id": video_id,  # None if no video attached
}
```

> **Implementation note**: `create_post` builds `post_item` as an explicit dict (lines 3023–3054) and returns `PostResponse(...)` with explicit field assignments (lines 3076–3110), not `**kwargs`. Add `video_id` to both the dict literal and the `PostResponse(...)` call.

#### 3.2.3 Post Serialization (`_post_to_dict`)

Enrich the response with video metadata when `video_id` is present. This fetch is performed at read time to ensure the response always reflects the current video state:

```python
def _post_to_dict(post: Dict[str, Any], locked_body: bool = False, ...) -> Dict[str, Any]:
    # ... existing logic ...

    # Video embed metadata
    video_embed = None
    raw_video_id = post.get("video_id")
    if raw_video_id and isinstance(raw_video_id, str):
        try:
            from app.services.video_metadata_store import get_video
            video_record = get_video(raw_video_id)
            video_embed = {
                "video_id": raw_video_id,
                "title": video_record.title,
                "thumbnail_url": video_record.thumbnail_url,
                "duration_seconds": video_record.duration_seconds,
                "hls_manifest_url": None if locked_body else video_record.hls_manifest_url,
                "playback_token": None,  # Issued separately per-viewer
                "playback_expires_at": None,
            }
        except Exception:
            video_embed = None

    return {
        # ... existing fields ...
        "video": video_embed,
    }
```

When `locked_body=True`, the video embed omits `hls_manifest_url` and `playback_token` (video is behind paywall).

#### 3.2.4 Playback Entitlement for Video Posts

Add a new endpoint that issues a playback token for a video embedded in a post. This is needed because the feed response does not include per-viewer playback tokens (they are short-lived and viewer-specific):

```python
@router.post("/posts/{post_id}/video/entitlement")
def issue_video_post_entitlement(post_id: str, user_id: UserIdDep):
    """Issue a playback entitlement token for a video post's embedded video."""
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="post not found")

    video_id = post.get("video_id")
    if not video_id:
        raise HTTPException(status_code=400, detail="post has no video")

    # Check lock status (viewer must have unlocked if locked)
    # Use the existing `has_unlocked(user_id, post_id)` helper (line 2104)
    # which checks the unlock record in DDB — same pattern used by
    # tip/comment/reaction endpoints throughout newsfeed.py
    is_locked = bool(post.get("locked"))
    if is_locked:
        is_owner = post.get("user_id") == user_id
        if not is_owner and not has_unlocked(user_id, post_id):
            raise HTTPException(status_code=403, detail="post is locked")

    from app.services.playback_entitlements import issue_playback_entitlement
    from app.services.video_metadata_store import get_video

    video = get_video(video_id)
    if video.status != "published" or not video.hls_manifest_url:
        raise HTTPException(status_code=400, detail="video is not available for playback")

    ttl = getattr(S, "video_playback_token_ttl_seconds", 300) or 300
    result = issue_playback_entitlement(
        tenant_id=video.owner_user_id,
        asset_id=video.id,
        session_id=f"feed_{user_id}_{post_id}",
        device_id="browser",
        profile="auto",
        audience="playback",
        ttl_seconds=ttl,
    )
    return {
        "video_id": video_id,
        "hls_manifest_url": video.hls_manifest_url,
        "playback_token": result.get("token"),
        "playback_expires_at": result.get("expires_at_epoch"),
    }
```

#### 3.2.5 Response Model Updates

Add `video` field to `PostResponse`:

```python
class PostVideoEmbed(BaseModel):
    video_id: str
    title: str
    thumbnail_url: Optional[str] = None
    duration_seconds: Optional[float] = None
    hls_manifest_url: Optional[str] = None
    playback_token: Optional[str] = None
    playback_expires_at: Optional[int] = None


class PostResponse(BaseModel):
    # ... existing fields ...
    video: Optional[PostVideoEmbed] = None
```

### 3.3 Frontend Changes

#### 3.3.1 TypeScript Types

File: `frontend/src/api/types.ts`

```typescript
export interface PostVideoEmbed {
  video_id: string;
  title: string;
  thumbnail_url?: string | null;
  duration_seconds?: number | null;
  hls_manifest_url?: string | null;
  playback_token?: string | null;
  playback_expires_at?: number | null;
}

export interface FeedPost {
  // ... existing fields ...
  video?: PostVideoEmbed | null;
}
```

#### 3.3.2 API Endpoints

File: `frontend/src/api/endpoints/newsfeed.ts`

```typescript
export const issueVideoPostEntitlement = (postId: string) =>
  api.post<{
    video_id: string;
    hls_manifest_url: string;
    playback_token: string;
    playback_expires_at: number;
  }>(`/ui/posts/${postId}/video/entitlement`);
```

#### 3.3.3 CreatePost Component

File: `frontend/src/pages/feed/CreatePost.tsx`

**New state**:
```typescript
const [pendingVideo, setPendingVideo] = useState<VideoListItem | null>(null);
const [videoPickerOpen, setVideoPickerOpen] = useState(false);
```

**Video button in toolbar** (alongside existing Image and File buttons):
```tsx
<Button
  variant="ghost"
  size="sm"
  onClick={() => setVideoPickerOpen(true)}
  disabled={uploading || imageUrls.length > 0}
  title={imageUrls.length > 0 ? "Remove images first to attach a video" : "Attach video"}
>
  <Video className="h-4 w-4" />
</Button>
```

**Mutual exclusivity logic**:
- Selecting a video clears `imageUrls` (sets to `[]`) and disables the image upload button.
- Selecting an image clears `pendingVideo` (sets to `null`) and disables the video button.
- The "X" button on the video preview card removes `pendingVideo` and re-enables the image button.

**Video preview card** (shown below toolbar when video is selected):
```tsx
{pendingVideo && (
  <div className="flex items-center gap-3 p-2 border rounded-md bg-muted/50">
    {pendingVideo.thumbnail_url && (
      <img src={pendingVideo.thumbnail_url} alt="" className="h-12 w-20 object-cover rounded" />
    )}
    <div className="flex-1 min-w-0">
      <p className="text-sm font-medium truncate">{pendingVideo.title}</p>
      {pendingVideo.duration_seconds && (
        <p className="text-xs text-muted-foreground">
          {formatDuration(pendingVideo.duration_seconds)}
        </p>
      )}
    </div>
    <Button variant="ghost" size="icon" onClick={() => setPendingVideo(null)}>
      <X className="h-4 w-4" />
    </Button>
  </div>
)}
```

**Submit payload**: Include `video_id` in the create post request body when `pendingVideo` is set:
```typescript
const payload = {
  ...buildContentPayload(body, editorMode, richDoc),
  image_urls: imageUrls,
  video_id: pendingVideo?.video_id ?? undefined,
  // ... existing fields ...
};
```

#### 3.3.4 VideoPickerDialog Component

File: `frontend/src/pages/feed/VideoPickerDialog.tsx` (new file)

A dialog that lists the user's published videos and allows selection:

```tsx
interface VideoPickerDialogProps {
  open: boolean;
  onClose: () => void;
  onSelect: (video: VideoListItem) => void;
}
```

Implementation:
- Uses `useQuery` with `listMyVideos({ status: "published" })` from `@/api/endpoints/videos`
- Renders a scrollable list of video cards (thumbnail + title + duration)
- Click selects and calls `onSelect`
- Empty state: "No published videos. Upload and publish a video first."
- Loading state: spinner

#### 3.3.5 PostCard Component

File: `frontend/src/pages/feed/PostCard.tsx`

**Video player rendering** (above text content, below author header):

```tsx
{post.video && !isLocked && (
  <VideoPostPlayer
    postId={post.post_id}
    video={post.video}
    className="mt-3"
  />
)}

{post.video && isLocked && (
  <div className="mt-3 relative aspect-video rounded-lg overflow-hidden">
    {post.video.thumbnail_url ? (
      <img
        src={post.video.thumbnail_url}
        alt=""
        className="w-full h-full object-cover blur-lg"
      />
    ) : (
      <div className="w-full h-full bg-muted" />
    )}
    <div className="absolute inset-0 flex flex-col items-center justify-center bg-black/50">
      <Lock className="h-8 w-8 text-white mb-2" />
      <p className="text-white text-sm font-medium">
        Unlock for ${((post.unlock_price_cents ?? 0) / 100).toFixed(2)}
      </p>
    </div>
  </div>
)}
```

#### 3.3.6 VideoPostPlayer Component

File: `frontend/src/pages/feed/VideoPostPlayer.tsx` (new file)

A wrapper around `MediaPlayer` that handles entitlement fetching:

```tsx
interface VideoPostPlayerProps {
  postId: string;
  video: PostVideoEmbed;
  className?: string;
}

export function VideoPostPlayer({ postId, video, className }: VideoPostPlayerProps) {
  const { data: entitlement, isLoading } = useQuery({
    queryKey: ["video-post-entitlement", postId],
    queryFn: () => issueVideoPostEntitlement(postId),
    staleTime: 4 * 60 * 1000,  // Refresh 1 min before typical 5-min expiry
    enabled: !!video.hls_manifest_url,
  });

  if (!video.hls_manifest_url) {
    return <VideoThumbnailFallback video={video} className={className} />;
  }

  if (isLoading) {
    return (
      <div className={cn("aspect-video bg-muted rounded-lg flex items-center justify-center", className)}>
        <Loader2 className="h-6 w-6 animate-spin" />
      </div>
    );
  }

  const manifestUrl = entitlement?.hls_manifest_url ?? video.hls_manifest_url;

  return (
    <div className={className}>
      <MediaPlayer
        src={manifestUrl}
        mode="vod"
        poster={video.thumbnail_url ?? undefined}
        title={video.title}
        controls
      />
      {video.title && (
        <p className="mt-1 text-sm font-medium text-muted-foreground truncate">
          {video.title}
        </p>
      )}
      {video.duration_seconds && (
        <p className="text-xs text-muted-foreground">
          {formatDuration(video.duration_seconds)}
        </p>
      )}
    </div>
  );
}
```

**Click-to-play pattern**: The `MediaPlayer` component already supports `poster` prop (thumbnail shown before play). On first interaction, HLS loading begins. No additional click-to-play wrapper is needed beyond the native poster behavior.

**Duration badge on thumbnail**: The `MediaPlayer` already handles poster display. For the pre-play state, a duration overlay badge is rendered on top of the poster:

```tsx
{!isPlaying && video.duration_seconds && (
  <Badge className="absolute bottom-2 right-2 bg-black/70 text-white text-xs">
    {formatDuration(video.duration_seconds)}
  </Badge>
)}
```

---

## 4. Implementation Plan

### 4.1 Phase 1: Backend (Data + API)

| Step | File | Change |
|------|------|--------|
| 1 | `app/routers/newsfeed.py` | Add `video_id` to `CreatePostRequest` and `EditPostRequest` |
| 2 | `app/routers/newsfeed.py` | Add video validation logic in `create_post` |
| 3 | `app/routers/newsfeed.py` | Add `video_id` to `post_item` DDB write |
| 4 | `app/routers/newsfeed.py` | Enrich `_post_to_dict` with video embed metadata |
| 5 | `app/routers/newsfeed.py` | Add `PostVideoEmbed` model and include in `PostResponse` |
| 6 | `app/routers/newsfeed.py` | Add `POST /posts/{post_id}/video/entitlement` endpoint |
| 7 | `app/routers/newsfeed.py` | Handle `video_id` in `edit_post` (with same validation) |
| 8 | `app/routers/newsfeed.py` | Add `video_id` to `CreateDraftPostRequest`, `UpdateDraftPostRequest`, and `DraftPostResponse` |

### 4.2 Phase 2: Frontend (UI)

| Step | File | Change |
|------|------|--------|
| 1 | `frontend/src/api/types.ts` | Add `PostVideoEmbed` interface and `video` field to `FeedPost` |
| 2 | `frontend/src/api/endpoints/newsfeed.ts` | Add `issueVideoPostEntitlement` function |
| 3 | `frontend/src/pages/feed/VideoPickerDialog.tsx` | New component: video picker dialog |
| 4 | `frontend/src/pages/feed/VideoPostPlayer.tsx` | New component: entitlement-aware video player |
| 5 | `frontend/src/pages/feed/CreatePost.tsx` | Add video button, picker integration, mutual exclusivity |
| 6 | `frontend/src/pages/feed/PostCard.tsx` | Render `VideoPostPlayer` for video posts, locked overlay |

### 4.3 Phase 3: E2E Tests

File: `frontend/e2e/feed-video-posts.spec.ts`

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/feed-video-posts.spec.ts` — approximately 18 tests across 4 sections.

### 5.2 Test Setup

```typescript
// beforeAll:
// 1. Create a published video via video API (presign + complete + transition to published)
// 2. Create an unpublished video (status=created) for negative tests
// 3. Seed payment methods for unlock tests
```

Test users: Alice (creator), Bob (viewer). Alice owns the videos.

### 5.3 Section 1: Video Post CRUD API (6 tests)

| # | Test | Assertion |
|---|------|-----------|
| 1 | Create video post with valid published video_id | 200; response has `video.video_id`, `video.title`, `video.thumbnail_url` |
| 2 | Create video post with caption text + video | 200; response has both `body` and `video` populated |
| 3 | Reject create with non-existent video_id | 400; detail contains "video not found" |
| 4 | Reject create with video not owned by poster | 403; detail contains "not owned" |
| 5 | Reject create with unpublished video | 400; detail contains "published status" |
| 6 | Reject create with both image_urls and video_id | 400; detail contains "mutually exclusive" |

### 5.4 Section 2: Video Post in Feed (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 7 | Video post appears in creator's feed with video metadata | GET /feed; find post; `video.video_id` matches |
| 8 | Video embed includes title, thumbnail_url, duration_seconds | Fields are non-null and match the source video |
| 9 | Video post entitlement endpoint returns playback token | POST /posts/{id}/video/entitlement; 200; has `playback_token` |
| 10 | Entitlement denied for locked video post (non-owner, not unlocked) | POST entitlement; 403 |

### 5.5 Section 3: Locked Video Posts (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 11 | Locked video post hides hls_manifest_url in feed response | GET feed as Bob; `video.hls_manifest_url` is null |
| 12 | Locked video post still returns thumbnail_url (for blurred preview) | `video.thumbnail_url` is present |
| 13 | After unlock, video post shows hls_manifest_url | Unlock; re-fetch; `video.hls_manifest_url` is non-null |
| 14 | After unlock, entitlement endpoint succeeds | POST entitlement; 200 |

### 5.6 Section 4: Interactions on Video Posts (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 15 | Comment on video post | POST comment; 200; comment_count increments |
| 16 | Tip on video post | POST tip; 200; tip_total_cents increments |
| 17 | React to video post | POST reaction; 200; reactions_counts updated |
| 18 | Like video post | POST like; 200; like_count increments, liked_by_me=true |

### 5.7 Section 5 (Optional/UI): CreatePost + PostCard UI (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 19 | Video picker dialog lists only published videos | Open picker; see published video; do NOT see unpublished |
| 20 | Selecting video shows preview card in composer | Preview card visible with title and thumbnail |
| 21 | Published video post renders MediaPlayer in feed | Navigate to feed; `[data-testid="media-player"]` visible on post |

---

## 6. Error Handling

### 6.1 Backend Errors

| Scenario | Status | Error Code/Detail |
|----------|--------|-------------------|
| `video_id` not found in VideoMetadata table | 400 | `"video not found"` |
| Video `owner_user_id` does not match poster | 403 | `"video is not owned by this user"` |
| Video `status` is not `published` | 400 | `"video must be in published status to attach to a post"` |
| Both `image_urls` and `video_id` provided | 400 | `"video_id and image_urls are mutually exclusive; provide one or the other"` |
| Entitlement request on locked post (non-owner, not unlocked) | 403 | `"post is locked"` |
| Entitlement request on post with no video | 400 | `"post has no video"` |
| Video deleted after post creation (entitlement request) | 400 | `"video is not available for playback"` |

### 6.2 Frontend Error States

| Scenario | Behavior |
|----------|----------|
| Video fetch fails in `_post_to_dict` | `video` field is `null`; PostCard renders as text-only post |
| Entitlement endpoint returns error | VideoPostPlayer shows thumbnail fallback with "Playback unavailable" |
| HLS manifest load fails | MediaPlayer shows error overlay with "Retry" button |
| Video picker has no published videos | Empty state message in dialog |

---

## 7. Performance Considerations

### 7.1 N+1 Query on Feed Load

`_post_to_dict` fetches video metadata per-post via `get_video(video_id)`. For a feed page of 20 posts where 5 are video posts, this adds 5 additional DDB `GetItem` calls.

**Mitigation**:
1. `GetItem` on a DDB primary key is single-digit millisecond latency
2. Video posts are expected to be a minority of feed items
3. If profiling shows an issue, batch fetch video metadata with `BatchGetItem` in a post-processing step

### 7.2 Playback Entitlement on Scroll

The `VideoPostPlayer` uses React Query with `staleTime: 4 * 60 * 1000` (4 minutes). Entitlements are issued lazily (only when the component mounts in viewport) and cached. Scrolling past a video post and back does not re-issue.

### 7.3 Video Embed Caching

Video metadata (title, thumbnail, duration) changes infrequently after publication. A future optimization could cache the embed sub-object on the post item itself (denormalized) and refresh on video update. This is out of scope for FEED-001.

---

## 8. Security Considerations

### 8.1 Ownership Validation

The `create_post` endpoint verifies `video.owner_user_id == user_id` before allowing attachment. This prevents users from embedding someone else's published video in their own posts (which would bypass the video owner's monetization controls).

### 8.2 Playback Access Control

The entitlement endpoint checks:
1. Post exists
2. Post has a video
3. If post is locked, viewer has unlocked it (or is the owner)
4. Video is still in `published` status with a valid manifest

This ensures paywalled video content cannot be accessed by forging a direct entitlement request.

### 8.3 Video ID Format Validation

The `video_id` field uses a regex pattern (`^v_[a-f0-9]{32}$`) to prevent injection of arbitrary strings into DDB queries.

---

## 9. Migration & Rollout

### 9.1 Backward Compatibility

- Existing posts have no `video_id` attribute. `_post_to_dict` gracefully handles `post.get("video_id")` returning `None`.
- The `video` field in `PostResponse` is `Optional[PostVideoEmbed] = None`, so existing clients that do not expect it will ignore it.
- Frontend `PostCard` conditionally renders the video player only when `post.video` is truthy.

### 9.2 Feature Flag (Optional)

If a phased rollout is desired, gate the video button in `CreatePost` behind a feature flag:

```python
# Backend: app/core/settings.py — uses os.environ.get() pattern (frozen dataclass)
newsfeed_video_posts_enabled: bool = os.environ.get("NEWSFEED_VIDEO_POSTS_ENABLED", "true").lower() in ("1", "true", "yes", "on")
```

```typescript
// Frontend: featureFlags.ts
export const newsfeedVideoPostsEnabled = true;
```

The flag controls only the creation path. Reading/rendering video posts is always enabled (posts already created should always display correctly).

### 9.3 No DynamoDB Schema Changes Required

The `video_id` field is stored as a top-level string attribute on the existing post item. No new tables, GSIs, or `attr_types` declarations are needed.

---

## 10. Open Questions

| # | Question | Proposed Answer |
|---|----------|-----------------|
| 1 | Should video posts support multiple videos? | No. One video per post (matches image_urls mutual exclusivity). Creators can make multiple posts. |
| 2 | Should the video embed be denormalized onto the post item? | Not for v1. Fetch at read time. Revisit if performance is an issue. |
| 3 | Should video posts appear in scheduled posts? | Yes. Scheduling works identically -- `video_id` is just another field on the post item. |
| 4 | Can a draft contain a video_id? | Yes. Add `video_id` to `CreateDraftPostRequest` and `UpdateDraftPostRequest` for consistency. No validation is needed until publish time. |
| 5 | Should the video picker support searching/filtering? | v1: simple list of published videos sorted by newest. Future: add search. |
