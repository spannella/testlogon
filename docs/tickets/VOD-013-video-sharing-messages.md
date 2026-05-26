# VOD-013: Video Sharing in Messages

**Ticket**: VOD-013
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-25

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The platform has a fully functional VOD pipeline (upload, transcode, HLS playback) and a rich messaging system supporting text, images, files, audio, galleries, file shares, calendar events, and meeting polls. However, there is no first-class integration that allows users to share a transcoded video from the VOD library directly into a conversation with inline playback.

Currently, users can share a video file via `file_share` messages, but this simply links to the raw file in the file manager -- it does not leverage the VOD pipeline's HLS adaptive bitrate streaming, thumbnails, or playback entitlements. Recipients must navigate away from the conversation to the video player page to watch the content.

### 1.2 Proposed Solution

Introduce a new `video_share` message kind that references a video by `video_id`. When rendered in the conversation, the message displays:
- A thumbnail preview (click-to-play)
- Video title and duration metadata
- An inline HLS player (using the existing `MediaPlayer` component) that starts on user interaction
- Automatic playback entitlement issuance when the recipient views the message

This creates a seamless in-conversation video viewing experience without leaving the messaging UI.

### 1.3 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | As a creator, I want to share one of my published videos in a DM so my subscriber can watch it inline. | Creator opens Video picker in ComposeBar, selects video, sends; recipient sees thumbnail + title in conversation. |
| Recipient | As a recipient, I want to watch a shared video inline without navigating to another page. | Clicking play on the thumbnail loads the HLS player within the message bubble; adaptive quality works. |
| Creator | As a creator, I want to share my unlisted video in a group chat for early access previews. | Unlisted videos are shareable; group members can play inline; the video does not appear in the public video listing. |
| User | As a user, I want to share a public video from another creator into my group chat. | Any user can share any published+public video by video_id; playback entitlement auto-issued to all recipients. |
| User | As a user, I expect that private videos cannot be shared by non-owners. | Attempting to share a private video that you do not own returns 403. |
| Admin | As an admin, I want to see video share messages in conversation archives. | `video_share` messages appear in messaging archive exports with video metadata. |

### 1.4 Scope Boundaries

**In scope:**
- New `video_share` message kind
- Backend endpoint for creating video share messages
- Frontend VideoPickerDialog component
- ComposeBar integration
- MessageBubble inline playback rendering
- Automatic playback entitlement issuance
- E2E and unit tests

**Out of scope:**
- Video upload from within the messaging flow (use existing upload page)
- PPV/locked video shares (future ticket)
- Live stream sharing (separate BCAST ticket)
- Video editing/trimming before share

---

## 2. Current State Analysis

### 2.1 Message Kind Architecture

The `MessageOut` model (`app/routers/messaging.py`, line 2285) defines supported kinds:

```python
kind: Literal["text", "image", "file", "audio", "video", "gallery", "file_share", "calendar_share", "calendar_event", "meeting_poll"]
```

Each kind has:
1. A `Create*MessageIn` Pydantic model for the request body
2. A dedicated POST endpoint (e.g., `create_file_share_message`)
3. A projection block in `_message_out_from_item` that enriches the stored DDB item for the response
4. A frontend `MessageBubble` rendering branch

The existing `"video"` kind is for raw video file attachments (uploaded inline, stored in S3 as a single file), NOT for VOD pipeline videos. The new `"video_share"` kind is semantically different: it references a video record by ID and leverages the full VOD playback infrastructure.

### 2.2 File Share Pattern (Reference Implementation)

The `file_share` message kind (`app/routers/messaging.py`, line 8148) provides the closest analogy:

1. **Request model**: `CreateFileShareMessageIn` with `file_path`, `permission`, optional `text`, optional `send_at`
2. **Validation**: Verifies the file exists and is owned by the sender
3. **Side effect**: Shares the file with all participants (best-effort)
4. **Storage**: DDB item includes `kind: "file_share"` and a `file_share` dict with metadata
5. **Rendering**: `_message_out_from_item` projects the `file_share` dict into the response
6. **Frontend**: `FileMessageCard` component renders file metadata with download/preview links

### 2.3 Video Metadata Model

`app/models_video.py` defines `VideoMetadataModel` with:
- `id`, `owner_user_id`, `title`, `description`
- `status`: `created | probing | probe_failed | pending_encoding | encoding | encoding_failed | pending_review | approved | rejected | published | archived | deleted`
- `visibility`: `private | unlisted | public`
- `thumbnail_url`, `hls_manifest_url`
- `duration_seconds`, `width`, `height`
- `drm_enabled`, `drm_key_id`

Key observation: Only videos with `status="published"` and `visibility in ("public", "unlisted")` should be shareable by non-owners. Owners can share their own videos regardless of visibility (but must be `status="published"` or `"approved"` for playback to work).

### 2.4 Playback Entitlement System

`app/services/playback_entitlements.py` provides `issue_playback_entitlement(...)` which generates a signed HS256 JWT with:
- `tenant_id` (video owner)
- `asset_id` (video_id)
- `session_id`, `device_id`, `profile`
- `audience` (e.g., "playback")
- TTL (default 300 seconds)

The video listing endpoint (`app/routers/video_listing.py`, line 195) already calls `_try_issue_playback_token` when returning video details. For video share messages, entitlements will be issued similarly when the message is fetched by a recipient.

### 2.5 MediaPlayer Component

`frontend/src/components/shared/MediaPlayer.tsx` is a shared HLS.js player supporting:
- `src` (HLS manifest URL)
- `mode` ("live" | "vod")
- `poster` (thumbnail image)
- `title` (overlay title)
- `drmKeyUrl` (AES-128 key server)
- Quality selection, fullscreen, PiP, volume control

This component is already used by `VideoPlayerPage.tsx` and can be embedded directly in `MessageBubble`.

### 2.6 Existing Video Listing Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /ui/videos` | List caller's own videos (all statuses/visibilities) |
| `GET /ui/videos/public` | List all published+public videos |
| `GET /ui/videos/creator/{id}` | List a creator's published+public videos |
| `GET /ui/videos/{id}` | Get video detail (owner sees all; non-owner requires published+public/unlisted) |

The VideoPickerDialog will use `GET /ui/videos` for the owner's library and the detail endpoint for validation.

---

## 3. Technical Design

### 3.1 New Message Kind: `video_share`

Add `"video_share"` to the `MessageOut.kind` literal union and create a dedicated field for the video metadata payload.

### 3.2 Data Model Changes

**File: `app/routers/messaging.py`** -- New request model:

```python
class CreateVideoShareMessageIn(BaseModel):
    video_id: str = Field(min_length=1, max_length=128)
    text: Optional[str] = Field(default=None, max_length=2000)
    send_at: Optional[int] = None
```

**File: `app/routers/messaging.py`** -- Update `MessageOut`:

```python
kind: Literal["text", "image", "file", "audio", "video", "gallery", "file_share",
              "calendar_share", "calendar_event", "meeting_poll", "video_share"]
# ...
video_share: Optional[Dict[str, Any]] = None
```

**DynamoDB message item** (stored in Messages table):

```python
{
    "conversation_id": "...",
    "message_id": "m_<uuid>",
    "sender_id": "...",
    "created_at": <unix_ts>,
    "kind": "video_share",
    "text": "Check out my new video!",  # optional caption
    "video_share": {
        "video_id": "v_abc123",
        "owner_user_id": "user_xyz",
        "title": "My Cool Video",
        "thumbnail_url": "https://...",
        "duration_seconds": 342.5,
        "width": 1920,
        "height": 1080,
        "visibility": "public",
        "drm_enabled": false,
    },
    "reactions": {}
}
```

The `video_share` dict is a snapshot of key metadata at send time. This ensures the message remains displayable even if the video is later deleted or made private. The `video_id` is stored for live-fetching updated metadata (e.g., playback URL) at read time.

### 3.3 Backend Endpoint

**Path**: `POST /ui/messaging/conversations/{conversation_id}/messages/video-share`

**Auth**: `get_messaging_user_id` (supports cookie+CSRF, Bearer token, and API key auth — same as all other message creation endpoints)

**Request body**: `CreateVideoShareMessageIn`

**Logic**:

```python
@router.post(
    "/conversations/{conversation_id}/messages/video-share",
    response_model=MessageOut,
)
def create_video_share_message(
    conversation_id: str,
    inp: CreateVideoShareMessageIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    require_participant_active(user_id, conversation_id)
    convo = _get_conversation_or_404(conversation_id)

    # 1. Validate video exists
    video = get_video(inp.video_id)  # raises 404 if not found

    # 2. Authorization: who can share this video?
    is_owner = video.owner_user_id == user_id
    if not is_owner:
        # Non-owners can only share published+public or published+unlisted videos
        if video.status != "published":
            raise HTTPException(403, "video is not published")
        if video.visibility == "private":
            raise HTTPException(403, "cannot share a private video you do not own")

    # 3. Owner sharing: video must be at least approved/published for playback
    if is_owner and video.status not in ("approved", "published"):
        raise HTTPException(400, "video must be approved or published to share")

    # 4. Build video_share metadata snapshot
    video_share_data = {
        "video_id": video.id,
        "owner_user_id": video.owner_user_id,
        "title": video.title,
        "thumbnail_url": video.thumbnail_url,
        "duration_seconds": float(video.duration_seconds) if video.duration_seconds else None,
        "width": video.width,
        "height": video.height,
        "visibility": video.visibility,
        "drm_enabled": video.drm_enabled,
    }

    # 5. Handle scheduled send
    ts = now_ts()
    deliver_at: Optional[int] = None
    is_scheduled = False
    if inp.send_at is not None:
        if inp.send_at <= ts + 5:
            raise HTTPException(400, "send_at must be at least 5 seconds in the future")
        deliver_at = inp.send_at
        is_scheduled = True

    # 6. Create message item
    mid = "m_" + new_id()
    item = {
        "conversation_id": conversation_id,
        "message_id": mid,
        "sender_id": user_id,
        "created_at": ts,
        "kind": "video_share",
        "video_share": video_share_data,
        "reactions": {},
    }
    if inp.text:
        item["text"] = inp.text
    if is_scheduled:
        item["status"] = "scheduled"
        item["deliver_at"] = deliver_at

    ttl = _message_retention_ttl(convo, ts)
    if ttl:
        item["ttl"] = ttl

    tbl_msgs.put_item(Item=item)

    # 7. Post-send side effects (if not scheduled)
    if not is_scheduled:
        participants = tbl_parts.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(conversation_id))["Items"]
        _bump_unread_counts(conversation_id, user_id, participants)
        _record_delivery_receipts(conversation_id, mid, user_id, participants)

        preview_text = inp.text or f"[Shared video: {video_share_data['title']}]"
        tbl_convos.update_item(
            Key={"conversation_id": conversation_id},
            UpdateExpression="SET last_message_at = :ts, last_message_preview = :p, last_message_id = :mid",
            ExpressionAttributeValues={":ts": ts, ":p": preview_text, ":mid": mid},
        )

        _fanout_new_message_event(
            conversation_id=conversation_id,
            sender_id=user_id,
            message_item=item,
            payload={"message_id": mid, "created_at": ts, "message": _serialize_message_event_payload(item, user_id)},
            respect_mute=False,
        )

    # 8. Audit + archive
    audit_event("messaging_message_sent", user_id, req, outcome="success",
                conversation_id=conversation_id, message_id=mid, kind="video_share", scheduled=is_scheduled)
    _emit_message_lifecycle_archive_event_or_503(...)
    _meter_message_send(user_id=user_id, conversation_id=conversation_id, message_id=mid)

    return _message_out_from_item(item, user_id)
```

### 3.4 Message Rendering (Backend)

In `_message_out_from_item`, add a projection block for `video_share` (following the pattern of `calendar_share`):

```python
video_share_out: Optional[Dict[str, Any]] = None
if merged_item.get("kind") == "video_share":
    raw = merged_item.get("video_share") or {}
    video_id = raw.get("video_id")

    # Try to issue a live playback entitlement for the viewer
    playback_token = None
    playback_expires_at = None
    hls_manifest_url = raw.get("hls_manifest_url")

    if video_id and viewer_user_id:
        try:
            video = get_video(video_id)
            # Refresh manifest URL from live record (may have changed)
            hls_manifest_url = video.hls_manifest_url
            # Issue entitlement for the viewer
            token, expires = _try_issue_playback_token(video, viewer_user_id)
            playback_token = token
            playback_expires_at = expires
        except Exception:
            pass  # Video may have been deleted; use snapshot data

    video_share_out = {
        "video_id": raw.get("video_id"),
        "owner_user_id": raw.get("owner_user_id"),
        "title": raw.get("title"),
        "thumbnail_url": raw.get("thumbnail_url"),
        "duration_seconds": float(raw["duration_seconds"]) if raw.get("duration_seconds") else None,
        "width": int(raw["width"]) if raw.get("width") else None,
        "height": int(raw["height"]) if raw.get("height") else None,
        "visibility": raw.get("visibility"),
        "drm_enabled": bool(raw.get("drm_enabled", False)),
        "hls_manifest_url": hls_manifest_url,
        "playback_token": playback_token,
        "playback_expires_at": playback_expires_at,
    }
```

This means every time a conversation is fetched, the viewer receives a fresh playback token valid for 300 seconds. The frontend refreshes the token by re-fetching messages (React Query refetch).

### 3.5 Gallery Index Integration

The video share messages should appear in the conversation gallery under the "video" tab. Update `_gallery_item_from_message` to handle `kind == "video_share"`:

```python
if gallery_type == "video" and kind == "video_share":
    vs = message.get("video_share") or {}
    url = vs.get("hls_manifest_url") or vs.get("thumbnail_url") or ""
    if url:
        return GalleryItemOut(
            message_id=message["message_id"],
            conversation_id=message["conversation_id"],
            sender_id=message["sender_id"],
            created_at=int(message["created_at"]),
            type="video",
            url=url,
            thumbnail_url=vs.get("thumbnail_url"),
            title=vs.get("title"),
        )
```

### 3.6 Searchability

Video share messages with a text caption should be indexed for message search (same as text messages). Update `_is_searchable_kind` to include `"video_share"`:

```python
def _is_searchable_kind(kind: str) -> bool:
    return kind in {"text", "file", "audio", "video", "video_share"}
```

### 3.7 Settings

**File: `app/core/settings.py`** -- New settings:

```python
# VOD Sharing (VOD-013)
video_sharing_enabled: bool = os.environ.get("VIDEO_SHARING_ENABLED", "1") not in ("0", "false", "False")
video_share_playback_token_ttl_seconds: int = int(os.environ.get("VIDEO_SHARE_PLAYBACK_TOKEN_TTL_SECONDS", "300"))
```

**File: `.env.local.example`**:

```bash
VIDEO_SHARING_ENABLED=true
VIDEO_SHARE_PLAYBACK_TOKEN_TTL_SECONDS=300
```

---

## 4. Frontend Design

### 4.1 VideoPickerDialog Component

**File**: `frontend/src/pages/messages/VideoPickerDialog.tsx`

A dialog that lists the user's published/approved videos for selection. Modeled after `FilePickerDialog.tsx`.

```tsx
interface VideoPickerDialogProps {
  open: boolean;
  onClose: () => void;
  onSelect: (video: VideoListItem) => void;
}

export function VideoPickerDialog({ open, onClose, onSelect }: VideoPickerDialogProps) {
  const [search, setSearch] = React.useState("");
  const [debouncedSearch, setDebouncedSearch] = React.useState("");
  const [selected, setSelected] = React.useState<VideoListItem | null>(null);

  // Fetch user's videos (published + approved only)
  const { data, isLoading } = useQuery({
    queryKey: ["my-videos", "shareable"],
    queryFn: () => listMyVideos({ status: "published" }),
    enabled: open,
  });

  // Filter by search term (client-side for simplicity)
  const filtered = React.useMemo(() => {
    const items = data?.items ?? [];
    if (!debouncedSearch) return items;
    const q = debouncedSearch.toLowerCase();
    return items.filter((v) => v.title.toLowerCase().includes(q));
  }, [data, debouncedSearch]);

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-lg max-h-[80vh] flex flex-col">
        <DialogHeader>
          <DialogTitle>Share a Video</DialogTitle>
        </DialogHeader>

        {/* Search input */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input placeholder="Search videos..." value={search} onChange={...} className="pl-9" />
        </div>

        {/* Video list */}
        <ScrollArea className="flex-1 min-h-0">
          {filtered.map((video) => (
            <VideoListRow
              key={video.video_id}
              video={video}
              selected={selected?.video_id === video.video_id}
              onClick={() => setSelected(video)}
            />
          ))}
          {filtered.length === 0 && !isLoading && (
            <p className="text-center text-muted-foreground py-8">No shareable videos found</p>
          )}
        </ScrollArea>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button disabled={!selected} onClick={() => { onSelect(selected!); onClose(); }}>
            Share Video
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
```

Each `VideoListRow` displays:
- Thumbnail (small, 64x36px aspect-ratio container)
- Title (truncated)
- Duration badge (formatted as `mm:ss` or `h:mm:ss`)
- Visibility badge (public/unlisted)

### 4.2 ComposeBar Integration

**File**: `frontend/src/pages/messages/ComposeBar.tsx`

Add a new callback prop and toolbar button:

```tsx
// New prop on ComposeBarProps:
onSendVideoShare?: (params: SendVideoShareReq) => void;

// New state:
const [videoPickerOpen, setVideoPickerOpen] = React.useState(false);

// New toolbar button (alongside existing FolderOpen and CalendarDays):
<TooltipTrigger asChild>
  <Button
    type="button"
    variant="ghost"
    size="icon"
    className="h-8 w-8"
    onClick={() => setVideoPickerOpen(true)}
  >
    <Video className="h-4 w-4" />
  </Button>
</TooltipTrigger>
<TooltipContent>Share Video</TooltipContent>

// VideoPickerDialog at the bottom of ComposeBar:
<VideoPickerDialog
  open={videoPickerOpen}
  onClose={() => setVideoPickerOpen(false)}
  onSelect={(video) => {
    onSendVideoShare?.({ video_id: video.video_id, text: text.trim() || undefined });
    setText("");
  }}
/>
```

### 4.3 ConversationView Integration

**File**: `frontend/src/pages/messages/ConversationView.tsx`

Add a mutation for sending video share messages and wire it to ComposeBar:

```tsx
import { sendVideoShareMessage } from "@/api/endpoints/messaging";

// In ConversationView:
const videoShareMut = useMutation({
  mutationFn: (params: SendVideoShareReq) =>
    sendVideoShareMessage(convoId, params),
  onSuccess: (newMsg) => {
    // Prepend to messages cache (same optimistic pattern as other sends)
    queryClient.setQueryData(["messages", convoId], (old) => { ... });
    queryClient.invalidateQueries({ queryKey: ["conversations"] });
  },
  onError: (err) => toast.error(err instanceof ApiError ? err.message : "Failed to share video"),
});

// Pass to ComposeBar:
<ComposeBar
  ...
  onSendVideoShare={(params) => videoShareMut.mutate(params)}
/>
```

### 4.4 MessageBubble Rendering

**File**: `frontend/src/pages/messages/MessageBubble.tsx`

Add a rendering branch for `kind === "video_share"`:

```tsx
// Inside MessageBubble, after other kind-specific rendering blocks:

{message.kind === "video_share" && message.video_share && (
  <VideoShareCard
    videoShare={message.video_share}
    conversationId={conversationId}
    messageId={message.message_id}
  />
)}
```

**New component** `VideoShareCard` (inline in MessageBubble.tsx or separate file):

```tsx
interface VideoShareCardProps {
  videoShare: {
    video_id: string;
    title: string;
    thumbnail_url?: string;
    duration_seconds?: number;
    width?: number;
    height?: number;
    hls_manifest_url?: string;
    playback_token?: string;
    playback_expires_at?: number;
    drm_enabled?: boolean;
  };
  conversationId: string;
  messageId: string;
}

function VideoShareCard({ videoShare, conversationId, messageId }: VideoShareCardProps) {
  const [playing, setPlaying] = useState(false);
  const navigate = useNavigate();

  const aspectRatio = videoShare.width && videoShare.height
    ? videoShare.width / videoShare.height
    : 16 / 9;

  // Construct authenticated manifest URL (append token as query param)
  const manifestUrl = videoShare.hls_manifest_url
    ? `${videoShare.hls_manifest_url}${videoShare.hls_manifest_url.includes("?") ? "&" : "?"}token=${videoShare.playback_token || ""}`
    : null;

  if (playing && manifestUrl) {
    return (
      <div className="rounded-lg overflow-hidden max-w-md" style={{ aspectRatio }}>
        <MediaPlayer
          src={manifestUrl}
          mode="vod"
          poster={videoShare.thumbnail_url}
          title={videoShare.title}
          drmKeyUrl={videoShare.drm_enabled ? `/ui/videos/${videoShare.video_id}/drm-key` : undefined}
        />
      </div>
    );
  }

  return (
    <div
      className="relative rounded-lg overflow-hidden max-w-md cursor-pointer group"
      style={{ aspectRatio }}
      onClick={() => manifestUrl ? setPlaying(true) : navigate(`/videos/${videoShare.video_id}`)}
      data-testid="video-share-card"
    >
      {/* Thumbnail */}
      {videoShare.thumbnail_url ? (
        <img
          src={videoShare.thumbnail_url}
          alt={videoShare.title}
          className="w-full h-full object-cover"
        />
      ) : (
        <div className="w-full h-full bg-muted flex items-center justify-center">
          <Video className="h-12 w-12 text-muted-foreground" />
        </div>
      )}

      {/* Play overlay */}
      <div className="absolute inset-0 flex items-center justify-center bg-black/30 group-hover:bg-black/40 transition-colors">
        <div className="rounded-full bg-white/90 p-3">
          <Play className="h-6 w-6 text-black fill-black" />
        </div>
      </div>

      {/* Duration badge */}
      {videoShare.duration_seconds && (
        <Badge className="absolute bottom-2 right-2 bg-black/70 text-white text-xs">
          {formatDuration(videoShare.duration_seconds)}
        </Badge>
      )}

      {/* Title bar */}
      <div className="absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black/60 to-transparent p-2 pt-6">
        <p className="text-white text-sm font-medium truncate">{videoShare.title}</p>
      </div>
    </div>
  );
}
```

### 4.5 API Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface VideoShareAttachment {
  video_id: string;
  owner_user_id: string;
  title: string;
  thumbnail_url?: string;
  duration_seconds?: number;
  width?: number;
  height?: number;
  visibility: string;
  drm_enabled: boolean;
  hls_manifest_url?: string;
  playback_token?: string;
  playback_expires_at?: number;
}

// Add to Message interface:
video_share?: VideoShareAttachment;
```

**File**: `frontend/src/api/endpoints/messaging.ts`

```typescript
export interface SendVideoShareReq {
  video_id: string;
  text?: string;
  send_at?: number;
}

export async function sendVideoShareMessage(
  conversationId: string,
  body: SendVideoShareReq,
): Promise<Message> {
  const resp = await api.post<Message>(
    `/ui/messaging/conversations/${conversationId}/messages/video-share`,
    body,
  );
  return resp.data;
}
```

### 4.6 Playback Token Refresh

The playback token embedded in the message has a 300-second TTL. When a user starts playback:

1. The token may still be valid (fetched < 5 minutes ago via React Query).
2. If expired, HLS.js will receive a 403 from the manifest/segment request.
3. On 403, the `VideoShareCard` triggers a message refetch to obtain a fresh token:

```tsx
const queryClient = useQueryClient();

const handlePlayerError = useCallback((error: MediaError) => {
  if (error.code === "MANIFEST_LOAD_ERROR" || error.code === "FRAG_LOAD_ERROR") {
    // Token likely expired; refetch messages to get fresh token
    queryClient.invalidateQueries({ queryKey: ["messages", conversationId] });
    setPlaying(false);
    toast.info("Refreshing playback access...");
  }
}, [conversationId, queryClient]);
```

---

## 5. Privacy & Authorization

### 5.1 Sharing Rules Matrix

| Video Status | Visibility | Sender is Owner | Can Share? |
|-------------|-----------|-----------------|------------|
| published | public | Yes | Yes |
| published | public | No | Yes |
| published | unlisted | Yes | Yes |
| published | unlisted | No | Yes |
| published | private | Yes | Yes |
| published | private | No | **No** (403) |
| approved | any | Yes | Yes |
| approved | any | No | **No** (403) |
| encoding/created/failed | any | Yes | **No** (400) |
| encoding/created/failed | any | No | **No** (403) |
| (deleted) | any | any | **No** (404) |

### 5.2 Playback Entitlement Rules

When `_message_out_from_item` renders a `video_share` message, it issues a playback entitlement if:

1. The video still exists (not deleted)
2. The video is in `"published"` or `"approved"` status
3. The video has an `hls_manifest_url` (transcoding complete)
4. The viewer is either:
   - The video owner (always entitled), OR
   - A participant in the conversation (any participant who can read the message)

The entitlement is issued with `audience="playback"` and the standard TTL (300s). The `tenant_id` is the video owner's user ID, and `asset_id` is the `video_id`.

### 5.3 Video Deletion After Share

If a video is deleted (soft-deleted) after being shared:
- The message remains in the conversation with the snapshot metadata (title, thumbnail)
- The `_message_out_from_item` projection catches the exception when trying to fetch the live video record
- `hls_manifest_url` and `playback_token` will be `null` in the response
- The frontend shows the thumbnail and title but displays "Video unavailable" instead of the play button

### 5.4 Visibility Change After Share

If a video's visibility changes from public to private after being shared:
- The message snapshot retains the original metadata
- Playback entitlements are still issued because the message itself grants implicit access (the sender authorized sharing at send time)
- This is intentional: recipients who received the share retain access

---

## 6. Implementation Plan

### 6.1 Files to Create

| File | Purpose |
|------|---------|
| `frontend/src/pages/messages/VideoPickerDialog.tsx` | Video selection dialog for ComposeBar |
| `frontend/src/pages/messages/VideoShareCard.tsx` | Inline video player card for MessageBubble |
| `tests/test_video_share_message.py` | Unit tests for the video share endpoint |
| `frontend/e2e/messaging-video-share.spec.ts` | E2E tests for video sharing in messages |

### 6.2 Files to Modify

| File | Change |
|------|--------|
| `app/routers/messaging.py` | Add `CreateVideoShareMessageIn` model; add `create_video_share_message` endpoint; add `video_share` projection in `_message_out_from_item`; update `MessageOut.kind` literal; add `video_share` field to `MessageOut`; update `_is_searchable_kind`; update gallery index handler |
| `app/main.py` | No change needed (messaging router already registered) |
| `app/core/settings.py` | Add `video_sharing_enabled`, `video_share_playback_token_ttl_seconds` |
| `.env.local.example` | Add `VIDEO_SHARING_ENABLED`, `VIDEO_SHARE_PLAYBACK_TOKEN_TTL_SECONDS` |
| `frontend/src/api/types.ts` | Add `VideoShareAttachment` interface; add `video_share` to `Message` |
| `frontend/src/api/endpoints/messaging.ts` | Add `SendVideoShareReq` interface; add `sendVideoShareMessage` function |
| `frontend/src/pages/messages/ComposeBar.tsx` | Add `onSendVideoShare` prop; add Video button to toolbar; integrate `VideoPickerDialog` |
| `frontend/src/pages/messages/ConversationView.tsx` | Add `videoShareMut` mutation; pass `onSendVideoShare` to `ComposeBar` |
| `frontend/src/pages/messages/MessageBubble.tsx` | Add rendering branch for `kind === "video_share"`; import `VideoShareCard` |

### 6.3 Step-by-Step Implementation Order

**Step 1: Backend data model + endpoint (no frontend change)**
1. Add `"video_share"` to `MessageOut.kind` literal in `app/routers/messaging.py`.
2. Add `video_share: Optional[Dict[str, Any]] = None` field to `MessageOut`.
3. Add `CreateVideoShareMessageIn` model.
4. Implement `create_video_share_message` endpoint.
5. Add `video_share` projection block in `_message_out_from_item`.
6. Add settings to `app/core/settings.py`.
7. Update `.env.local.example`.

**Step 2: Backend search + gallery integration**
1. Update `_is_searchable_kind` to include `"video_share"`.
2. Update gallery index extraction to handle `video_share` messages under the "video" tab.
3. Ensure `_serialize_message_event_payload` correctly serializes `video_share` messages.

**Step 3: Frontend API layer**
1. Add `VideoShareAttachment` to `types.ts`.
2. Add `video_share` field to `Message` interface.
3. Add `SendVideoShareReq` and `sendVideoShareMessage` to `messaging.ts`.

**Step 4: Frontend VideoPickerDialog**
1. Create `VideoPickerDialog.tsx`.
2. Uses `listMyVideos` from `api/endpoints/videos.ts` (already exists).

**Step 5: Frontend ComposeBar integration**
1. Add `onSendVideoShare` prop to `ComposeBar`.
2. Add Video button to toolbar (lucide `Video` icon).
3. Wire `VideoPickerDialog` open/close/select.

**Step 6: Frontend ConversationView wiring**
1. Add `videoShareMut` useMutation.
2. Pass `onSendVideoShare` to ComposeBar.

**Step 7: Frontend MessageBubble rendering**
1. Create `VideoShareCard.tsx` component.
2. Add `kind === "video_share"` branch in MessageBubble.
3. Integrate `MediaPlayer` for inline playback.

**Step 8: Tests**
1. Write unit tests (`tests/test_video_share_message.py`).
2. Write E2E tests (`frontend/e2e/messaging-video-share.spec.ts`).

### 6.4 Dependency Graph

```
VOD-001 (metadata model) ─────────────┐
VOD-006 (video listing API) ──────────┤
VOD-008 (video player page) ──────────┤
MEDIA-001 (shared player component) ──┤
Messaging (existing infrastructure) ──┤
                                       v
                            VOD-013 (this ticket)
```

---

## 7. Testing Strategy

### 7.1 Unit Tests: `tests/test_video_share_message.py`

| Test | What It Validates |
|------|-------------------|
| `test_share_own_published_public_video` | Owner shares published+public video; 200; response has `kind="video_share"`, `video_share.video_id` set. |
| `test_share_own_published_private_video` | Owner shares own private published video; 200 (owner can share own videos regardless of visibility). |
| `test_share_own_approved_video` | Owner shares approved (not yet published) video; 200. |
| `test_share_own_encoding_video_400` | Owner tries to share video still encoding; 400. |
| `test_share_nonowner_public_video` | Non-owner shares published+public video; 200. |
| `test_share_nonowner_unlisted_video` | Non-owner shares published+unlisted video; 200. |
| `test_share_nonowner_private_video_403` | Non-owner tries to share private video; 403. |
| `test_share_nonowner_unpublished_video_403` | Non-owner tries to share approved (not published) video; 403. |
| `test_share_nonexistent_video_404` | Share with invalid video_id; 404. |
| `test_share_deleted_video_404` | Share a soft-deleted video; 404. |
| `test_video_share_with_caption` | Send with `text="Check this out"`; response has `text` field populated. |
| `test_video_share_scheduled` | Send with `send_at` in future; response has `scheduled=true`, `deliver_at` set. |
| `test_video_share_scheduled_past_400` | Send with `send_at` in past; 400. |
| `test_video_share_non_participant_403` | Non-participant of conversation tries to share; 403. |
| `test_video_share_message_out_has_playback_token` | Fetch messages; `video_share` dict includes `playback_token` and `playback_expires_at`. |
| `test_video_share_feature_disabled_403` | Set `VIDEO_SHARING_ENABLED=false`; share returns 403. |
| `test_video_share_preview_text_in_conversation` | After send, conversation `last_message_preview` contains `[Shared video: <title>]`. |

### 7.2 E2E Tests: `frontend/e2e/messaging-video-share.spec.ts`

Following existing patterns (`injectAuth`, `page.request`, section numbering):

**Section 130: Video Share API (DM)**

```typescript
test("130.1 Alice shares a published video in DM with Bob", async ({ page }) => {
  // POST /ui/messaging/conversations/{dm}/messages/video-share
  // with video_id of a published+public video owned by Alice
  // Verify 200, response.kind === "video_share"
  // Verify response.video_share.title matches
});

test("130.2 Shared video appears in conversation messages", async ({ page }) => {
  // GET messages for the DM
  // Verify the video_share message is present with correct metadata
});

test("130.3 Video share includes playback token for recipient", async ({ page }) => {
  // Bob fetches messages
  // Verify video_share.playback_token is non-null
  // Verify video_share.hls_manifest_url is non-null
});

test("130.4 Alice cannot share a video still encoding", async ({ page }) => {
  // Create video in "created" status; try to share; expect 400
});

test("130.5 Bob cannot share Alice's private video", async ({ page }) => {
  // Create private video; Bob tries to share; expect 403
});

test("130.6 Video share with caption stores text", async ({ page }) => {
  // Share with text="Great content!"; verify text in response
});

test("130.7 Scheduled video share", async ({ page }) => {
  // Share with send_at in future; verify scheduled=true
});
```

**Section 131: Video Share in Group Chat**

```typescript
test("131.1 Alice shares video in group chat", async ({ page }) => {
  // Create group with Alice+Bob; share video; verify success
});

test("131.2 All group participants get playback token", async ({ page }) => {
  // Bob fetches group messages; verify playback_token is present
});

test("131.3 Non-owner can share public video in group", async ({ page }) => {
  // Bob shares Alice's public video in the group; verify 200
});
```

**Section 132: Playback & Permissions**

```typescript
test("132.1 Playback token allows HLS manifest fetch", async ({ page }) => {
  // Extract playback_token from video_share message
  // Fetch the HLS manifest URL with token appended
  // Verify 200 response (in dev mode, mock S3 serves the manifest)
});

test("132.2 Deleted video shows null manifest in message", async ({ page }) => {
  // Share video, then delete the video
  // Fetch messages again; verify hls_manifest_url is null
});

test("132.3 Conversation preview shows video title", async ({ page }) => {
  // Fetch conversations list; verify last_message_preview contains video title
});
```

**Section 133: VideoPickerDialog UI**

```typescript
test("133.1 Video picker shows user's published videos", async ({ page }) => {
  // Open messages, click Video button in ComposeBar
  // Verify dialog opens with video list
  // Verify at least one video appears with title and thumbnail
});

test("133.2 Video picker search filters results", async ({ page }) => {
  // Type in search box; verify list filters
});

test("133.3 Selecting video and clicking Share sends message", async ({ page }) => {
  // Click a video in the list; click Share button
  // Verify message appears in conversation
});

test("133.4 Empty state shows message when no videos", async ({ page }) => {
  // User with no published videos sees "No shareable videos found"
});
```

**Section 134: Inline Playback UI**

```typescript
test("134.1 Video share message shows thumbnail with play button", async ({ page }) => {
  // Navigate to conversation with video share message
  // Verify thumbnail image is visible
  // Verify play button overlay is visible
  // Verify duration badge is visible
});

test("134.2 Clicking play starts inline HLS player", async ({ page }) => {
  // Click the video share card
  // Verify MediaPlayer component appears (video element with HLS source)
});

test("134.3 Video title shown on the card", async ({ page }) => {
  // Verify the video title text is visible in the message bubble
});
```

### 7.3 Edge Cases

| Edge Case | Expected Behavior |
|-----------|-------------------|
| Video deleted between share and message fetch | Message renders with snapshot title/thumbnail; play button shows "Video unavailable". |
| Token expired mid-playback | HLS.js gets 403; frontend refetches messages for fresh token; user clicks play again. |
| Very long video title (256 chars) | Truncated in MessageBubble with ellipsis; full title in tooltip. |
| Video with no thumbnail (transcode in progress when shared) | Fallback placeholder with Video icon shown. |
| DRM-enabled video shared | `drmKeyUrl` passed to MediaPlayer; key fetched for AES-128 decryption during playback. |
| Sender shares video then changes visibility to private | Recipients retain playback access (entitlement still issued). |
| Concurrent shares of same video in same conversation | Each creates a separate message; no conflict. |
| Share video in conversation with 100+ participants | Entitlement issued per-viewer on message fetch; no blast issuance at send time. |

### 7.4 Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Playback token issuance on every message fetch | Token generation is a local HMAC computation (~microseconds); no external call. Issued lazily only for `video_share` messages. |
| Large conversation with many video shares | Entitlement issuance is O(n) per video_share message in the page. With typical page size of 50 messages, this is negligible. |
| `get_video` call per video_share message on fetch | Single DDB `get_item` per video; consistent reads; fast. Could be batched in future if many video shares in one page. |
| Video metadata snapshot staleness | Snapshot captures title/thumbnail at send time. Live refresh of `hls_manifest_url` happens at read time (needed for playback). Stale title/thumbnail is acceptable. |
| MediaPlayer bundle size in MessageBubble | `hls.js` is already loaded by the app (used on VideoPlayerPage); no additional bundle impact. `VideoShareCard` uses lazy rendering (only loads MediaPlayer on play click). |

---

## Appendix A: Configuration Reference

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `VIDEO_SHARING_ENABLED` | `true` | Master toggle for video share message creation |
| `VIDEO_SHARE_PLAYBACK_TOKEN_TTL_SECONDS` | `300` | TTL for playback tokens issued in video share messages |

---

## Appendix B: File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/routers/messaging.py` | Modify | Add `CreateVideoShareMessageIn`; add `create_video_share_message` endpoint; add `video_share` projection in `_message_out_from_item`; update `MessageOut.kind` and add `video_share` field; update searchability and gallery handlers |
| `app/core/settings.py` | Modify | Add `video_sharing_enabled`, `video_share_playback_token_ttl_seconds` |
| `.env.local.example` | Modify | Add `VIDEO_SHARING_ENABLED`, `VIDEO_SHARE_PLAYBACK_TOKEN_TTL_SECONDS` |
| `frontend/src/api/types.ts` | Modify | Add `VideoShareAttachment` interface; extend `Message` |
| `frontend/src/api/endpoints/messaging.ts` | Modify | Add `SendVideoShareReq` + `sendVideoShareMessage` |
| `frontend/src/pages/messages/ComposeBar.tsx` | Modify | Add `onSendVideoShare` prop; add Video toolbar button; integrate VideoPickerDialog |
| `frontend/src/pages/messages/ConversationView.tsx` | Modify | Add `videoShareMut`; pass to ComposeBar |
| `frontend/src/pages/messages/MessageBubble.tsx` | Modify | Add `video_share` rendering branch |
| `frontend/src/pages/messages/VideoPickerDialog.tsx` | **New** | Video selection dialog |
| `frontend/src/pages/messages/VideoShareCard.tsx` | **New** | Inline HLS player card for message bubbles |
| `tests/test_video_share_message.py` | **New** | 17 unit tests for video share endpoint |
| `frontend/e2e/messaging-video-share.spec.ts` | **New** | ~18 E2E tests across 5 sections (130-134) |

---

## Appendix C: API Endpoint Summary

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/messaging/conversations/{id}/messages/video-share` | `get_messaging_user_id` | Create a video share message |
| GET | `/ui/messaging/conversations/{id}/messages` | `get_messaging_user_id` | (Existing) Extended: returns `video_share` field with playback token for `video_share` messages |
| GET | `/ui/videos` | `require_ui_session` | (Existing) Used by VideoPickerDialog to list shareable videos |
| GET | `/ui/videos/{id}` | `require_ui_session` | (Existing) Used for live metadata refresh during message rendering |

---

## Appendix D: Message Flow Sequence

```
┌─────────┐                    ┌─────────┐                    ┌─────────┐
│  Alice   │                    │ Backend  │                    │   Bob    │
└────┬────┘                    └────┬────┘                    └────┬────┘
     │                              │                              │
     │  POST .../messages/video-share                              │
     │  { video_id: "v_abc" }       │                              │
     │─────────────────────────────>│                              │
     │                              │                              │
     │                   ┌──────────┴──────────┐                   │
     │                   │ 1. Validate video    │                   │
     │                   │ 2. Check auth        │                   │
     │                   │ 3. Snapshot metadata  │                   │
     │                   │ 4. Store in DDB       │                   │
     │                   │ 5. Fanout SSE event   │                   │
     │                   └──────────┬──────────┘                   │
     │                              │                              │
     │  200 { kind: "video_share",  │                              │
     │    video_share: { ... } }    │     SSE: new_message         │
     │<─────────────────────────────│─────────────────────────────>│
     │                              │                              │
     │                              │  GET .../messages             │
     │                              │<─────────────────────────────│
     │                              │                              │
     │                   ┌──────────┴──────────┐                   │
     │                   │ Render message:       │                   │
     │                   │ - Fetch live video    │                   │
     │                   │ - Issue playback token│                   │
     │                   │ - Return enriched msg │                   │
     │                   └──────────┬──────────┘                   │
     │                              │                              │
     │                              │  200 [{ kind: "video_share", │
     │                              │    video_share: {             │
     │                              │      hls_manifest_url,        │
     │                              │      playback_token,          │
     │                              │      ... } }]                 │
     │                              │─────────────────────────────>│
     │                              │                              │
     │                              │                    ┌─────────┴─────────┐
     │                              │                    │ Click play:        │
     │                              │                    │ Load HLS manifest  │
     │                              │                    │ with playback_token│
     │                              │                    │ → Inline playback  │
     │                              │                    └─────────┬─────────┘
     │                              │                              │
```
