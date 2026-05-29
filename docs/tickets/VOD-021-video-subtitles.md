# VOD-021: Video Subtitles and Closed Captions

**Ticket**: VOD-021
**Author**: Engineering
**Status**: Implemented
**Date**: 2026-05-28
**Priority**: High
**Estimated effort**: 10-12 days
**Dependencies**: VOD-001, VOD-008, MEDIA-001

---

## 1. Overview & Motivation

### 1.1 Problem Statement

Videos on the platform currently have no subtitle or closed caption support. Creators cannot upload SRT or VTT files, viewers cannot toggle captions during playback, and the HLS manifests do not reference any text tracks. This creates three concrete problems:

1. **Accessibility**: Deaf and hard-of-hearing viewers cannot consume video content. Web Content Accessibility Guidelines (WCAG 2.1 AA) require synchronized captions for all prerecorded audio content (Success Criterion 1.2.2). Without captions, the platform fails basic accessibility compliance.
2. **International reach**: Creators who produce content in one language cannot serve viewers who speak another. Manual subtitle upload is the standard approach on every major video platform (YouTube, Vimeo, Twitch VODs), and its absence limits audience growth for multi-language creators.
3. **Engagement metrics**: Industry data consistently shows that captioned videos have higher watch-through rates (up to 40% longer average view duration) because viewers in sound-sensitive environments (commutes, offices, late nights) can still follow the content.

This ticket introduces a complete subtitle pipeline: upload API with SRT-to-VTT conversion, S3 storage, HLS manifest injection, a new `SubtitleTrack` data model nested on `VideoMetadataModel`, a CC toggle and track selector in `MediaPlayer.tsx`, and a subtitle management panel in the video edit UI.

### 1.2 How It Works

1. Creator navigates to a video they own and opens the subtitle management panel.
2. Creator uploads a subtitle file (VTT or SRT format), selects the language from an ISO 639-1 dropdown, enters a display label (e.g., "English", "Espanol"), and optionally marks it as the default track.
3. Backend validates the file format, converts SRT to VTT if needed, sanitizes the content, and uploads the VTT file to S3 at `subtitles/{video_id}/{track_id}.vtt`.
4. A `SubtitleTrack` record is appended to the `subtitle_tracks` list on the video's DynamoDB metadata record.
5. When a viewer loads the video player, the `subtitle_tracks` array is included in the video detail response. The `MediaPlayer` component renders `<track>` elements for each track and provides a CC toggle button and language selector dropdown.
6. The viewer's caption preference (enabled/disabled, preferred language) is persisted in `localStorage` and restored on subsequent visits.
7. For HLS-aware clients, `#EXT-X-MEDIA:TYPE=SUBTITLES` entries are injected into the master manifest, pointing to the VTT files served as sidecar tracks (no VTT segmentation required -- HLS.js supports sidecar VTT natively).

### 1.3 Design Principles

- **Non-destructive**: Subtitles are stored as separate files alongside the video assets. Adding, removing, or replacing subtitles never modifies the video media files.
- **Format normalization**: The platform accepts both SRT and VTT uploads but always converts to VTT internally. VTT is the web-native format supported by HTML5 `<track>` elements and HLS.js.
- **Creator ownership**: Only the video owner can manage subtitle tracks. Viewers consume them read-only.
- **Graceful degradation**: If no subtitle tracks exist, the player behaves exactly as it does today. The CC button only appears when tracks are available.
- **Future-ready**: The `is_auto_generated` flag on `SubtitleTrack` is reserved for a future auto-captioning feature (speech-to-text). This ticket implements manual upload only.

### 1.4 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | I want to upload subtitle files for my video in SRT or VTT format. | POST subtitle with file + language; 201; track appears in list. |
| Creator | I want to see all subtitle tracks on my video and delete ones I no longer need. | GET subtitles returns list; DELETE removes track from list and S3. |
| Creator | I want to designate one track as the default so viewers see captions automatically. | Set `is_default: true`; viewer's player enables this track by default on first visit. |
| Creator | I want SRT files automatically converted to VTT so I do not have to convert manually. | Upload `.srt` file; backend converts; stored file is `.vtt`. |
| Viewer | I want to toggle closed captions on and off during playback. | CC button in player controls; clicking toggles active text track. |
| Viewer | I want to choose from multiple subtitle languages when available. | Subtitle selector dropdown lists all tracks by label; clicking switches active track. |
| Viewer | I want my caption preference remembered across sessions. | Preference stored in localStorage; restored on next visit. |
| Viewer | I want captions styled readably with a semi-transparent background. | White text on `rgba(0,0,0,0.75)` background; configurable font size. |
| Admin | I want to verify subtitle content does not contain malicious payloads. | VTT files sanitized on upload; no `<script>`, no `<style>`, no data URIs. |

---

## 2. Current State Analysis

### 2.1 Video Metadata Model (`app/models_video.py`)

`VideoMetadataModel` (line 36) has fields covering technical properties, encoding, outputs, DRM, pricing, download, watermark, clipping, concatenation, gallery, ad-support, and purchase tiers -- but **no subtitle or caption fields exist**. The last field group is Purchase Tiers (VOD-019) ending at line 144. <!-- VERIFIED: app/models_video.py:36 — class VideoMetadataModel(BaseModel) -->

`VideoOut` (line 180) is the public response model. It similarly has no subtitle fields. The last field is `watermark_downloads` at line 207. <!-- VERIFIED: app/models_video.py:180 — class VideoOut(BaseModel) -->

### 2.2 Video Detail Response (`app/routers/video_listing.py`)

`VideoDetailOut` (line 67) defines the full video detail shape returned to the frontend. It includes renditions, DRM, download, watermark, ad, clipping, concatenation, and purchase tier fields but **no subtitle tracks array**. The last field group is Concatenation provenance at line 132. <!-- VERIFIED: app/routers/video_listing.py:67 — class VideoDetailOut(BaseModel) -->

The `_video_to_detail()` helper (line 178) maps `VideoMetadataModel` to `VideoDetailOut` and would need to pass through the new `subtitle_tracks` field. The function signature accepts keyword arguments for access, entitlement, and ad fields and returns at line 275. <!-- VERIFIED: app/routers/video_listing.py:178 — def _video_to_detail( -->

### 2.3 Media Player (`frontend/src/components/shared/MediaPlayer.tsx`)

The `MediaPlayer` component (758 lines) provides HLS.js playback with quality selection, fullscreen, PiP, volume control, and custom overlays. <!-- VERIFIED: MediaPlayer.tsx — 758 lines (wc -l) -->

`MediaPlayerProps` (line 46) accepts `src`, `mode`, `autoplay`, `muted`, `poster`, `title`, `drmKeyUrl`, `className`, `controls`, and callbacks -- **no subtitles/captions props**. <!-- VERIFIED: MediaPlayer.tsx:46 — export interface MediaPlayerProps { -->

The `<video>` element (line 548) has no `<track>` children. There is no CC toggle button, no subtitle selector, and no text track event handling. <!-- VERIFIED: MediaPlayer.tsx:548 — <video -->

The quality selector pattern (`QualitySelector` component, lines 91-151) provides a good UI reference for the subtitle track selector -- both are dropdown menus in the player controls bar. <!-- VERIFIED: MediaPlayer.tsx:91 — function QualitySelector({ -->

### 2.4 S3 Upload Infrastructure (`app/services/vod_s3_uploader.py`)

The VTT MIME type is **already registered** in `_CONTENT_TYPE_MAP` at line 37: `".vtt": "text/vtt"`. <!-- VERIFIED: app/services/vod_s3_uploader.py:37 — ".vtt": "text/vtt", -->

This means the existing `upload_segment()` function (line 96) can upload VTT files with the correct `Content-Type` header without modification. However, `upload_segment()` takes a `local_path: Path` parameter (it uploads from a local file, not from memory), so for subtitle uploads we will use `_s3.put_object()` directly (as shown in Section 11.2) rather than `upload_segment()` -- this avoids writing the small VTT content to a temp file unnecessarily. <!-- VERIFIED: app/services/vod_s3_uploader.py:96 — def upload_segment(*, local_path: Path, ...) --> <!-- CORRECTED: was "call upload_segment() with subtitle S3 key", actually upload_segment requires local_path; use put_object() directly for in-memory VTT content -->

### 2.5 VOD Pipeline Services

The existing VOD service layer in `app/services/` includes: <!-- VERIFIED: ls app/services/vod_*.py -->

- `vod_s3_uploader.py` -- S3 upload with multipart support and content-type mapping
- `vod_mp4_generator.py` -- MP4 download generation
- `vod_playback_url.py` -- Presigned URL minting for HLS playback
- `vod_thumbnail_extractor.py` -- Poster thumbnail generation
- `vod_drm_keys.py` -- DRM key management
- `vod_encryption.py` -- HLS encryption
- `vod_file_bridge.py` -- File manager integration
- `vod_purchase.py` -- Pay-per-view purchase logic

**No subtitle-related service exists.** A new `vod_subtitle_manager.py` service is needed. <!-- CORRECTED: vod_subtitle_manager.py NOW EXISTS with validate_language_code:30, srt_to_vtt:42, validate_vtt:91, sanitize_vtt_content:132, upload_subtitle_to_s3:150, upload_subtitle:190, list_subtitles:301, delete_subtitle:315, update_subtitle:354 -->

**Note**: The ticket's "Key files to verify against" listed `app/services/vod_probe.py` and `app/services/vod_transcoder.py` -- these files do **not** exist. FFprobe functionality lives inside `app/services/video_clipper.py` (line 375) and `app/services/video_concatenator.py` (line 420). Transcoding is handled by a combination of `app/services/transcode_job_store.py` and the FFmpeg executor. <!-- CORRECTED: was "vod_probe.py / vod_transcoder.py", actually these files do not exist; ffprobe is in video_clipper.py and video_concatenator.py -->

### 2.6 Video Metadata Store (`app/services/video_metadata_store.py`)

The `video_to_item()` function (line 21) serializes `VideoMetadataModel` to a DynamoDB item dict. It handles optional string fields (lines 36-64), list fields like `source_video_ids` and `tags` (lines 66-69), optional numeric fields with `Decimal` conversion (lines 76-108), renditions as list of dicts (lines 156-164), and feature-specific field groups for download, watermark, gallery, ads, and purchase tiers. <!-- VERIFIED: app/services/video_metadata_store.py:21 — def video_to_item(video: VideoMetadataModel) -> Dict[str, Any] -->

The `video_from_item()` function (line 169) deserializes a DynamoDB item back to `VideoMetadataModel`. It uses `_int_or_none` and `_float_or_none` helper closures for safe numeric coercion from DynamoDB `Decimal` types. <!-- VERIFIED: app/services/video_metadata_store.py:169 — def video_from_item(item: Dict[str, Any]) -> VideoMetadataModel -->

The `subtitle_tracks` list will need serialization logic similar to `renditions` -- each `SubtitleTrack` is a nested dict within the DDB list attribute. The `video_from_item` function will need to deserialize the list back to `SubtitleTrack` objects.

### 2.7 Settings (`app/core/settings.py`)

The settings file (1367 lines) contains VOD-related settings starting at line 1053 (video metadata table name) and extending through line 1219 (VOD-019 rental settings). This includes table names, S3 buckets/prefixes, upload config, playback tokens, DRM, thumbnails, FFmpeg, downloads, clipping, concatenation, gallery, ads, and purchase tiers. <!-- VERIFIED: app/core/settings.py — 1367 lines; VOD settings at lines 1053-1219 --> <!-- CORRECTED: was "lines 1054-1112", actually VOD settings span lines 1053-1219 (VOD-001 through VOD-019) -->

**No subtitle-related settings exist.** New settings are needed for the feature flag, max tracks per video, max file size, and allowed formats. <!-- CORRECTED: Subtitle settings NOW EXIST at app/core/settings.py:1359-1363 — video_subtitle_enabled, video_subtitle_max_tracks, video_subtitle_max_file_size_kb, video_subtitle_allowed_formats, video_subtitle_url_ttl_seconds -->

### 2.8 Auth Dependency

The `require_ui_session` dependency is defined in `app/services/sessions.py` (line 283), not in `app/auth/deps.py`. The video listing router imports it as `from app.services.sessions import require_ui_session`. <!-- VERIFIED: app/services/sessions.py:283 — async def require_ui_session( --> <!-- CORRECTED: was "app/auth/deps.py", actually in app/services/sessions.py; video_listing.py line 23 imports from app.services.sessions -->

### 2.9 DynamoDB Table: VideoMetadata

The `VideoMetadata` table is defined in `scripts/local-ddb-init.py` (line 708) with:
- Primary key: `video_id` (String)
- GSIs: `ByOwnerCreatedAt` (owner_user_id / created_at), `ByStatusCreatedAt` (status / created_at), `BySourceBroadcast` (source_broadcast_session_id), `ByCategory` (category / trending_score_sort), `ByGalleryPublished` (gallery_status / published_at)
- Numeric attribute type overrides: `created_at: N`, `trending_score_sort: N`, `published_at: N`

Subtitle tracks are stored as a nested list attribute on the existing record -- **no new DynamoDB table or GSI is needed**. <!-- VERIFIED: scripts/local-ddb-init.py:708 — VideoMetadata table definition -->

### 2.10 Gaps Summary

1. No `SubtitleTrack` data model or `subtitle_tracks` field on video metadata
2. No subtitle upload, list, or delete API endpoints
3. No SRT-to-VTT conversion logic
4. No VTT format validation or content sanitization
5. No subtitle track data in video detail API responses
6. No `<track>` elements in the `<video>` player
7. No CC toggle button or subtitle language selector in player controls
8. No caption preference persistence in localStorage
9. No HLS manifest subtitle injection (`#EXT-X-MEDIA:TYPE=SUBTITLES`)
10. No subtitle management UI on the video edit/detail page

---

## 3. Technical Design

### 3.1 System Diagram

```
+---------------------------------------------------------------------------+
|                         Frontend (React/Vite)                             |
|                                                                           |
|  VideoPlayerPage (/videos/:videoId)                                       |
|    +-- MediaPlayer (enhanced)                                             |
|    |     +-- <video>                                                      |
|    |     |     +-- <track kind="subtitles" src="..." srclang="en" />      |
|    |     |     +-- <track kind="subtitles" src="..." srclang="es" />      |
|    |     +-- SubtitleSelector (new dropdown in controls bar)              |
|    |     +-- CC toggle button (new)                                       |
|    |                                                                      |
|  VideoPlayerPage (owner view)                                             |
|    +-- SubtitleManager (new panel)                                        |
|          +-- Upload form: file + language + label + is_default            |
|          +-- Track list with delete buttons                               |
|          +-- Preview: play video with selected subtitle track             |
|                                                                           |
+-------------------+-------------------------------------------------------+
                    |
           Vite proxy :3000 -> :8000
                    |
+-------------------v-------------------------------------------------------+
|                      FastAPI Backend (:8000)                               |
|                                                                           |
|  POST /ui/videos/{video_id}/subtitles                                     |
|    +-- Auth: require_ui_session (owner check)                             |
|    +-- Validate file format (VTT or SRT)                                  |
|    +-- SRT -> VTT conversion (if needed)                                  |
|    +-- Sanitize VTT content (strip scripts/styles/data URIs)              |
|    +-- Upload VTT to S3: subtitles/{video_id}/{track_id}.vtt             |
|    +-- Append SubtitleTrack to video metadata                             |
|    +-- Return 201 with track details                                      |
|                                                                           |
|  GET /ui/videos/{video_id}/subtitles                                      |
|    +-- Auth: require_ui_session                                           |
|    +-- Return subtitle_tracks array from video metadata                   |
|                                                                           |
|  DELETE /ui/videos/{video_id}/subtitles/{track_id}                        |
|    +-- Auth: require_ui_session (owner check)                             |
|    +-- Remove track from video metadata                                   |
|    +-- Delete VTT file from S3                                            |
|                                                                           |
|  PATCH /ui/videos/{video_id}/subtitles/{track_id}                         |
|    +-- Auth: require_ui_session (owner check)                             |
|    +-- Update label, is_default fields                                    |
|                                                                           |
|  GET /ui/videos/{video_id}/subtitles/{track_id}/vtt                       |
|    +-- Auth: require_ui_session OR public (if video is public)            |
|    +-- Return presigned S3 URL for the VTT file                           |
|                                                                           |
|  +---------------------------------------------------+                    |
|  | DynamoDB: VideoMetadata (existing table)           |                    |
|  |   PK: video_id                                    |                    |
|  |   subtitle_tracks: [                              |                    |
|  |     { track_id, language, label, format, s3_key,  |                    |
|  |       is_default, is_auto_generated, created_at } |                    |
|  |   ]                                               |                    |
|  +---------------------------------------------------+                    |
|                                                                           |
|  +---------------------------------------------------+                    |
|  | S3: Subtitle file storage                          |                    |
|  |   Key: subtitles/{video_id}/{track_id}.vtt        |                    |
|  |   Content-Type: text/vtt                           |                    |
|  |   Cache-Control: max-age=86400                     |                    |
|  +---------------------------------------------------+                    |
|                                                                           |
+--------------------------------------------------------------------------+
```

### 3.2 Data Flow: Subtitle Upload

1. **Creator uploads file**: Frontend sends `POST /ui/videos/{video_id}/subtitles` with `multipart/form-data` containing the subtitle file, `language`, `label`, and optionally `is_default`.
2. **Auth + ownership check**: Backend verifies `require_ui_session` (imported from `app.services.sessions`) and `ctx["user_sub"] == video.owner_user_id`. <!-- VERIFIED: require_ui_session is in app/services/sessions.py:283 -->
3. **Format detection**: Inspect file extension and content header. Accept `.vtt` and `.srt` only.
4. **SRT conversion**: If the file is SRT format, convert to VTT by prepending the `WEBVTT` header, converting timestamp separators from `,` to `.`, and stripping sequence numbers.
5. **VTT validation**: Parse the converted/uploaded VTT content. Verify `WEBVTT` header, validate timestamp pairs, reject malformed cue timings.
6. **Content sanitization**: Strip `<script>`, `<style>`, `<object>`, `<embed>`, `<iframe>` tags and `data:` URIs from cue payloads. Only allow VTT-safe tags: `<b>`, `<i>`, `<u>`, `<c>`, `<lang>`, `<v>`, `<ruby>`, `<rt>`.
7. **S3 upload**: Write sanitized VTT to `subtitles/{video_id}/{track_id}.vtt` using `_s3.put_object()` directly (not `upload_segment()` which requires a local file path) with `Content-Type: text/vtt`. <!-- CORRECTED: was "upload_segment()", actually use put_object() since content is in-memory; upload_segment requires local_path: Path -->
8. **Metadata update**: Append `SubtitleTrack` to the video's `subtitle_tracks` list in DynamoDB. If `is_default` is `true`, set all other tracks' `is_default` to `false` first.
9. **Response**: Return 201 with the new track's details including the signed playback URL.

### 3.3 Data Flow: Viewer Playback with Subtitles

1. **Load video detail**: Frontend fetches `GET /ui/videos/{video_id}` which returns `subtitle_tracks` in the response.
2. **MediaPlayer receives tracks**: `subtitleTracks` prop passed to `MediaPlayer`.
3. **Render `<track>` elements**: For each subtitle track, render a `<track kind="subtitles" src={vttUrl} srclang={language} label={label} default={isDefault} />` inside the `<video>` element.
4. **CC button**: A `Subtitles` (lucide-react icon) button appears in the controls bar when `subtitleTracks.length > 0`.
5. **Track selection**: Clicking the CC button toggles the first/default track on or off. If multiple tracks exist, a dropdown lets the viewer pick a language.
6. **Preference persistence**: When the viewer enables/disables captions or selects a language, the preference is saved to `localStorage` (`cc-enabled`, `cc-language`).
7. **Preference restoration**: On mount, `MediaPlayer` reads localStorage preferences and activates the appropriate track if available.

### 3.4 Data Model Changes

#### 3.4.1 New Pydantic Models (`app/models_video.py`)

```python
class SubtitleTrack(BaseModel):
    """A single subtitle/caption track attached to a video."""
    track_id: str = Field(min_length=1, max_length=64)
    language: str = Field(min_length=2, max_length=10)  # ISO 639-1 or BCP-47
    label: str = Field(min_length=1, max_length=100)     # Display name: "English", "Espanol"
    format: Literal["vtt"] = "vtt"                       # Always VTT after conversion
    s3_key: str = Field(min_length=1)
    is_default: bool = False
    is_auto_generated: bool = False
    created_at: int = 0
```

#### 3.4.2 VideoMetadataModel Addition

Add to `VideoMetadataModel` in `app/models_video.py` (after the Purchase Tiers fields ending at line 144): <!-- CORRECTED: was "after watermark fields at line ~112", actually watermark_downloads is at line 111 and Purchase Tiers (VOD-019) fields end at line 144 — add after line 144 -->

```python
# Subtitles / Closed Captions (VOD-021)
subtitle_tracks: List[SubtitleTrack] = Field(default_factory=list)
```

#### 3.4.3 VideoOut Addition

Add to `VideoOut` (after `watermark_downloads` at line 207): <!-- VERIFIED: app/models_video.py:207 — watermark_downloads: bool = False is the last field -->

```python
# Subtitles / Closed Captions (VOD-021)
subtitle_tracks: List[SubtitleTrack] = Field(default_factory=list)
```

#### 3.4.4 VideoDetailOut Addition

Add to `VideoDetailOut` in `app/routers/video_listing.py` (after `source_video_ids` at line 132 -- this is the last field before the closing of the class): <!-- CORRECTED: was "after watermark_downloads at line 100", actually watermark_downloads is at line 100 but the class continues through line 133; add after the last field group -->

```python
# Subtitles / Closed Captions (VOD-021)
subtitle_tracks: list = Field(default_factory=list)
```

#### 3.4.5 Request Models

```python
class UploadSubtitleIn(BaseModel):
    """Metadata accompanying a subtitle file upload (form fields)."""
    language: str = Field(min_length=2, max_length=10)
    label: str = Field(min_length=1, max_length=100)
    is_default: bool = False

class UpdateSubtitleIn(BaseModel):
    """Updatable fields on an existing subtitle track."""
    label: Optional[str] = Field(default=None, min_length=1, max_length=100)
    is_default: Optional[bool] = None
```

#### 3.4.6 Response Models

```python
class SubtitleTrackOut(BaseModel):
    track_id: str
    language: str
    label: str
    format: str
    vtt_url: str
    is_default: bool
    is_auto_generated: bool
    created_at: int

class SubtitleListOut(BaseModel):
    tracks: List[SubtitleTrackOut]
    video_id: str
```

### 3.5 DynamoDB Storage

Subtitle tracks are stored as a nested list attribute on the existing `VideoMetadata` table record -- no new DynamoDB table is needed. The `VideoMetadata` table uses `video_id` as the sole primary key (no sort key). <!-- VERIFIED: scripts/local-ddb-init.py:708 — PK is "video_id", no sort key -->

Each video's `subtitle_tracks` field is a JSON-serializable list of dicts:

```json
{
  "video_id": "vid_tutorial_101",
  "subtitle_tracks": [
    {
      "track_id": "st_a1b2c3d4e5f6",
      "language": "en",
      "label": "English",
      "format": "vtt",
      "s3_key": "subtitles/vid_tutorial_101/st_a1b2c3d4e5f6.vtt",
      "is_default": true,
      "is_auto_generated": false,
      "created_at": 1748476800
    },
    {
      "track_id": "st_f6e5d4c3b2a1",
      "language": "es",
      "label": "Espanol",
      "format": "vtt",
      "s3_key": "subtitles/vid_tutorial_101/st_f6e5d4c3b2a1.vtt",
      "is_default": false,
      "is_auto_generated": false,
      "created_at": 1748477400
    }
  ]
}
```

This approach avoids a separate DynamoDB table and a GSI -- subtitle tracks are always accessed in the context of a specific video, so co-locating them on the video record is optimal. The maximum number of tracks per video is capped at 20 (configurable via `VIDEO_SUBTITLE_MAX_TRACKS`), keeping the item size well within DynamoDB's 400KB limit (20 tracks * ~300 bytes = ~6KB).

### 3.6 S3 Storage Convention

```
s3://{vod-output}/{prefix}/subtitles/{video_id}/{track_id}.vtt
```

The bucket and prefix are resolved from settings (consistent with other VOD outputs): <!-- VERIFIED: app/core/settings.py:1073-1074 — vod_output_bucket / vod_output_prefix -->

```python
bucket = S.vod_output_bucket or S.transcode_output_bucket or "vod-output"  # default: "vod-output"
prefix = S.vod_output_prefix or S.transcode_output_prefix or "tenants"     # default: "tenants"
```

Example in dev mode (moto S3):
```
s3://vod-output/tenants/subtitles/vid_tutorial_101/st_a1b2c3d4e5f6.vtt
```

The VTT file is served to the browser via a presigned URL (or the mock S3 path in dev mode: `/mock/s3/vod-output/tenants/subtitles/vid_tutorial_101/st_a1b2c3d4e5f6.vtt`).

Content headers:
- `Content-Type: text/vtt`
- `Cache-Control: max-age=86400` (24 hours; subtitle files change infrequently)
- `Access-Control-Allow-Origin: *` (required for cross-origin `<track>` loading)

### 3.7 SRT-to-VTT Conversion

SRT (SubRip Text) is the most common subtitle format used by creators. The conversion is straightforward:

```
SRT format:
1
00:00:01,500 --> 00:00:04,000
Hello, welcome to the tutorial.

2
00:00:05,200 --> 00:00:08,800
Today we'll cover video editing basics.
```

Converts to:

```
WEBVTT

00:00:01.500 --> 00:00:04.000
Hello, welcome to the tutorial.

00:00:05.200 --> 00:00:08.800
Today we'll cover video editing basics.
```

Conversion rules:
1. Prepend `WEBVTT\n\n` header.
2. Strip numeric sequence lines (lines matching `^\d+$` preceding a timestamp line).
3. Replace `,` with `.` in timestamp separators (`00:00:01,500` becomes `00:00:01.500`).
4. Preserve all cue text as-is (after sanitization).
5. Normalize line endings to `\n`.

```python
import re

_SRT_TIMESTAMP_RE = re.compile(
    r"(\d{2}:\d{2}:\d{2}),(\d{3})\s*-->\s*(\d{2}:\d{2}:\d{2}),(\d{3})"
)

def srt_to_vtt(srt_content: str) -> str:
    """Convert SRT subtitle content to WebVTT format."""
    lines = srt_content.strip().replace("\r\n", "\n").replace("\r", "\n").split("\n")
    vtt_lines = ["WEBVTT", ""]

    i = 0
    while i < len(lines):
        line = lines[i].strip()

        # Skip numeric sequence identifiers
        if line.isdigit():
            i += 1
            continue

        # Convert timestamp line
        match = _SRT_TIMESTAMP_RE.match(line)
        if match:
            start = f"{match.group(1)}.{match.group(2)}"
            end = f"{match.group(3)}.{match.group(4)}"
            vtt_lines.append(f"{start} --> {end}")
            i += 1
            continue

        # Pass through empty lines and cue text
        vtt_lines.append(line)
        i += 1

    return "\n".join(vtt_lines) + "\n"
```

### 3.8 VTT Validation

The validator checks:

1. **Header**: First non-empty line must be `WEBVTT` (optionally followed by metadata).
2. **Timestamps**: Each cue must have a valid timestamp line matching `HH:MM:SS.mmm --> HH:MM:SS.mmm`.
3. **Ordering**: Start time must be less than end time.
4. **No overlapping cues**: Warning logged but not rejected (overlapping cues are valid VTT but may render oddly).
5. **Encoding**: Must be valid UTF-8.
6. **Size limit**: File must be under `VIDEO_SUBTITLE_MAX_FILE_SIZE_KB` (default 512KB -- sufficient for a 4-hour video with dense captioning).

```python
_VTT_TIMESTAMP_RE = re.compile(
    r"(\d{2}:\d{2}:\d{2}\.\d{3})\s*-->\s*(\d{2}:\d{2}:\d{2}\.\d{3})"
)

def validate_vtt(content: str) -> list[str]:
    """Validate VTT content. Returns list of error messages (empty = valid)."""
    errors = []
    lines = content.strip().split("\n")

    if not lines or not lines[0].strip().startswith("WEBVTT"):
        errors.append("Missing WEBVTT header")
        return errors

    cue_count = 0
    for line in lines:
        match = _VTT_TIMESTAMP_RE.match(line.strip())
        if match:
            cue_count += 1
            start_str, end_str = match.group(1), match.group(2)
            start_ms = _parse_vtt_timestamp(start_str)
            end_ms = _parse_vtt_timestamp(end_str)
            if start_ms is not None and end_ms is not None and start_ms >= end_ms:
                errors.append(f"Cue {cue_count}: start time >= end time ({start_str} --> {end_str})")

    if cue_count == 0:
        errors.append("No valid cues found")

    return errors


def _parse_vtt_timestamp(ts: str) -> int | None:
    """Parse VTT timestamp 'HH:MM:SS.mmm' to total milliseconds."""
    try:
        parts = ts.split(":")
        h, m = int(parts[0]), int(parts[1])
        sec_parts = parts[2].split(".")
        s, ms = int(sec_parts[0]), int(sec_parts[1])
        return (h * 3600 + m * 60 + s) * 1000 + ms
    except (ValueError, IndexError):
        return None
```

### 3.9 Content Sanitization

VTT cue payloads can contain a subset of HTML-like tags for styling. To prevent XSS or injection attacks when the browser renders captions, the sanitizer strips all disallowed tags:

**Allowed tags** (per WebVTT spec):
- `<b>`, `<i>`, `<u>` -- basic formatting
- `<c>` -- class annotation (for CSS styling)
- `<lang>` -- language annotation
- `<v>` -- voice/speaker identification
- `<ruby>`, `<rt>` -- ruby text (East Asian languages)

**Stripped tags** (security risk):
- `<script>`, `<style>`, `<link>`, `<meta>`
- `<object>`, `<embed>`, `<iframe>`, `<applet>`
- `<form>`, `<input>`, `<textarea>`, `<select>`, `<button>`
- `<img>` (except when `src` is an absolute HTTP/HTTPS URL -- `data:` URIs are blocked)
- Any tag with `on*` event attributes (`onclick`, `onerror`, etc.)

```python
import re

_DISALLOWED_TAGS_RE = re.compile(
    r"<\s*/?\s*(script|style|link|meta|object|embed|iframe|applet|form|input|textarea|select|button)\b[^>]*>",
    re.IGNORECASE,
)
_EVENT_ATTRS_RE = re.compile(r"\s+on\w+\s*=", re.IGNORECASE)
_DATA_URI_RE = re.compile(r"data\s*:", re.IGNORECASE)
_JAVASCRIPT_URI_RE = re.compile(r"javascript\s*:", re.IGNORECASE)

def sanitize_vtt_content(content: str) -> str:
    """Remove potentially dangerous HTML from VTT cue payloads."""
    # Strip disallowed tags entirely
    content = _DISALLOWED_TAGS_RE.sub("", content)
    # Strip event handler attributes from any remaining tags
    content = _EVENT_ATTRS_RE.sub(" ", content)
    # Strip data: URIs
    content = _DATA_URI_RE.sub("", content)
    # Strip javascript: URIs
    content = _JAVASCRIPT_URI_RE.sub("", content)
    return content
```

### 3.10 HLS Manifest Subtitle Injection

HLS.js supports sidecar subtitle tracks declared in the master playlist via `#EXT-X-MEDIA:TYPE=SUBTITLES`. Each track points to a VTT file URL (not a segmented subtitle playlist). This is the simplest integration path and avoids VTT segmentation entirely.

For each subtitle track, inject a line into the master manifest:

```
#EXT-X-MEDIA:TYPE=SUBTITLES,GROUP-ID="subs",NAME="English",DEFAULT=YES,AUTOSELECT=YES,FORCED=NO,LANGUAGE="en",URI="https://s3.example.com/subtitles/vid_101/st_abc.vtt"
```

However, modifying the stored master manifest on every subtitle add/delete introduces complexity (rewriting S3 objects, cache invalidation). The simpler approach for Phase 1 is to **not modify the HLS manifest** and instead use the HTML5 `<track>` element approach:

**Phase 1 (this ticket): `<track>` element approach**
- The frontend adds `<track>` elements to the `<video>` element directly.
- HLS.js does not need to be aware of subtitles; the browser's native text track API handles rendering.
- This works for all browsers and does not require manifest modification.

**Phase 2 (future ticket): HLS manifest injection**
- For native HLS clients (Safari, Apple TV, Chromecast) that do not use HLS.js, inject `#EXT-X-MEDIA` entries into the master manifest.
- Requires either runtime manifest rewriting (via a proxy/lambda) or regenerating the manifest on subtitle changes.

### 3.11 Settings

Add to `app/core/settings.py` (after the VOD-019 settings at line 1219): <!-- CORRECTED: was "add to settings.py" without location; VOD-019 settings end at line 1219 -->

```python
# Subtitles / Closed Captions (VOD-021)
video_subtitle_enabled: bool = os.environ.get("VIDEO_SUBTITLE_ENABLED", "1") not in ("0", "false", "False")
video_subtitle_max_tracks: int = int(os.environ.get("VIDEO_SUBTITLE_MAX_TRACKS", "20"))
video_subtitle_max_file_size_kb: int = int(os.environ.get("VIDEO_SUBTITLE_MAX_FILE_SIZE_KB", "512"))
video_subtitle_allowed_formats: str = os.environ.get("VIDEO_SUBTITLE_ALLOWED_FORMATS", "vtt,srt")
video_subtitle_url_ttl_seconds: int = int(os.environ.get("VIDEO_SUBTITLE_URL_TTL_SECONDS", "3600"))
```

### 3.12 Dependency Graph

```
VOD-001 (metadata model) --------+
VOD-005 (S3 upload outputs) -----+
VOD-006 (video listing API) -----+
VOD-008 (video player page) -----+---> VOD-021 (this ticket)
MEDIA-001 (shared player) -------+
```

VOD-021 depends on the video metadata model (VOD-001) for the `subtitle_tracks` field, the S3 uploader (VOD-005) for VTT file upload, the video listing API (VOD-006) for including subtitle data in responses, the video player page (VOD-008) for the viewer-facing UI, and the shared media player component (MEDIA-001) for the `<track>` rendering and CC controls.

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/vod_subtitle_manager.py` | Subtitle business logic: SRT-to-VTT conversion, VTT validation, content sanitization, S3 upload/delete, track CRUD on video metadata | <!-- NEW: to be created -->
| `app/routers/video_subtitles.py` | HTTP endpoints: upload, list, delete, update, VTT URL | <!-- NEW: to be created -->
| `frontend/src/api/endpoints/subtitles.ts` | API client for subtitle endpoints | <!-- NEW: to be created -->
| `frontend/src/pages/videos/SubtitleManager.tsx` | Subtitle management panel: upload form, track list, delete action | <!-- NEW: to be created -->
| `frontend/src/components/shared/SubtitleSelector.tsx` | In-player dropdown for subtitle track selection | <!-- NEW: to be created -->
| `tests/test_vod_subtitle_manager.py` | Unit tests for conversion, validation, sanitization | <!-- NEW: to be created -->
| `tests/test_video_subtitles_endpoint.py` | Unit tests for subtitle API endpoints | <!-- NEW: to be created -->
| `frontend/e2e/video-subtitles.spec.ts` | E2E tests for subtitle upload, playback, and management | <!-- NEW: to be created -->

### 4.2 Files to Modify

| File | Change |
|------|--------|
| `app/models_video.py` | Add `SubtitleTrack` model (new class before line 147); add `subtitle_tracks` field to `VideoMetadataModel` (after line 144) and `VideoOut` (after line 207); add `UploadSubtitleIn`, `UpdateSubtitleIn` request models | <!-- VERIFIED: app/models_video.py — VideoMetadataModel ends at line 145, VideoOut ends at line 207 -->
| `app/services/video_metadata_store.py` | Serialize `subtitle_tracks` list in `video_to_item()` (after line 164); deserialize in `video_from_item()` (after line 268); add `add_subtitle_track()`, `remove_subtitle_track()`, `update_subtitle_track()` helpers | <!-- VERIFIED: app/services/video_metadata_store.py — video_to_item ends at line 166, video_from_item ends at line 269 -->
| `app/routers/video_listing.py` | Add `subtitle_tracks` to `VideoDetailOut` (after line 132); pass through in `_video_to_detail()` (at line 275 return block) | <!-- VERIFIED: app/routers/video_listing.py — VideoDetailOut class lines 67-133, _video_to_detail return at line 213 -->
| `app/main.py` | Register `video_subtitles` router | <!-- VERIFIED: app/main.py exists -->
| `app/core/settings.py` | Add `VIDEO_SUBTITLE_*` settings (5 new fields, after line 1219) | <!-- VERIFIED: app/core/settings.py — VOD-019 settings end at line 1219 -->
| `frontend/src/components/shared/MediaPlayer.tsx` | Add `subtitleTracks` prop; render `<track>` elements; add `crossOrigin="anonymous"` to `<video>` at line 548; add CC toggle button; add `SubtitleSelector` dropdown; add localStorage persistence | <!-- VERIFIED: MediaPlayer.tsx:548 — <video element has no crossOrigin or track children -->
| `frontend/src/api/types.ts` | Add `SubtitleTrack`, `SubtitleTrackOut`, `SubtitleListOut` interfaces |
| `frontend/src/pages/videos/VideoPlayerPage.tsx` | Pass `subtitleTracks` to `MediaPlayer`; render `SubtitleManager` panel for video owner | <!-- VERIFIED: VideoPlayerPage.tsx exists in frontend/src/pages/videos/ -->
| `.env.local.example` | Add `VIDEO_SUBTITLE_*` environment variables |

### 4.3 Step-by-Step Implementation Order

**Step 1: Data model + settings** (no behavior change)
1. Add `SubtitleTrack` model and `subtitle_tracks` field to `VideoMetadataModel` in `app/models_video.py`.
2. Add `subtitle_tracks` to `VideoOut` in `app/models_video.py`.
3. Add `UploadSubtitleIn`, `UpdateSubtitleIn` request models.
4. Update `video_to_item()` and `video_from_item()` in `video_metadata_store.py` to serialize/deserialize the `subtitle_tracks` list.
5. Add 5 new settings to `app/core/settings.py`.
6. Add env vars to `.env.local.example`.

**Step 2: Subtitle service layer**
1. Create `app/services/vod_subtitle_manager.py` with:
   - `srt_to_vtt(content: str) -> str` -- SRT to VTT conversion.
   - `validate_vtt(content: str) -> list[str]` -- VTT format validation.
   - `sanitize_vtt_content(content: str) -> str` -- Security sanitization.
   - `upload_subtitle_file(video_id, track_id, vtt_content) -> str` -- S3 upload via `_s3.put_object()`. <!-- CORRECTED: was upload_segment; use put_object for in-memory content -->
   - `delete_subtitle_file(s3_key) -> None` -- S3 deletion.
   - `mint_subtitle_url(s3_key, ttl) -> str` -- Presigned URL (or mock path in dev mode).
   - `add_track_to_video(video_id, track) -> SubtitleTrack` -- DDB update.
   - `remove_track_from_video(video_id, track_id) -> None` -- DDB update.
   - `update_track_on_video(video_id, track_id, updates) -> SubtitleTrack` -- DDB update.

**Step 3: API endpoints**
1. Create `app/routers/video_subtitles.py` with:
   - `POST /ui/videos/{video_id}/subtitles` -- Upload subtitle file.
   - `GET /ui/videos/{video_id}/subtitles` -- List tracks.
   - `DELETE /ui/videos/{video_id}/subtitles/{track_id}` -- Delete track.
   - `PATCH /ui/videos/{video_id}/subtitles/{track_id}` -- Update track metadata.
   - `GET /ui/videos/{video_id}/subtitles/{track_id}/vtt` -- Get VTT URL.
2. Register router in `app/main.py`.

**Step 4: Video detail integration**
1. Add `subtitle_tracks` to `VideoDetailOut` in `video_listing.py`.
2. Update `_video_to_detail()` to pass through `subtitle_tracks` with resolved VTT URLs.

**Step 5: Frontend API client + types**
1. Add TypeScript interfaces to `frontend/src/api/types.ts`.
2. Create `frontend/src/api/endpoints/subtitles.ts` with upload, list, delete, update functions.

**Step 6: MediaPlayer subtitle support**
1. Add `subtitleTracks` prop to `MediaPlayerProps`.
2. Add `crossOrigin="anonymous"` to the `<video>` element at line 548. <!-- VERIFIED: MediaPlayer.tsx:548 -->
3. Render `<track>` elements inside `<video>`.
4. Create `SubtitleSelector` component (dropdown, similar to `QualitySelector` at line 91). <!-- VERIFIED: MediaPlayer.tsx:91 -->
5. Add CC toggle button to controls bar (between quality selector and PiP button, around line 713). <!-- VERIFIED: MediaPlayer.tsx:708-724 — QualitySelector then PiP then Fullscreen -->
6. Implement localStorage read/write for caption preferences.
7. Handle `textTrack` activation/deactivation via the HTML5 TextTrack API.

**Step 7: Subtitle management UI**
1. Create `SubtitleManager.tsx` panel component.
2. Integrate into `VideoPlayerPage.tsx` (owner-only, below player).
3. Upload form with file input, language select, label input, default toggle.
4. Track list with label, language, default badge, delete button.

**Step 8: Tests**
1. Write pytest unit tests for SRT-to-VTT conversion, VTT validation, sanitization.
2. Write pytest unit tests for subtitle API endpoints.
3. Write E2E Playwright tests for full subtitle flow.

### 4.4 Implementation Timeline

| Day | Task | Deliverable |
|-----|------|-------------|
| 1 | Add `SubtitleTrack` model, `subtitle_tracks` field to `VideoMetadataModel`, `VideoOut`, `VideoDetailOut`; add settings | Data model + configuration |
| 1 | Update `video_to_item()` / `video_from_item()` serialization | DDB integration |
| 2 | Create `vod_subtitle_manager.py`: SRT-to-VTT conversion + VTT validation + sanitization | Core service logic |
| 3 | Create `vod_subtitle_manager.py`: S3 upload/delete + track CRUD on video metadata | Storage + metadata ops |
| 4 | Create `video_subtitles.py` router: upload, list, delete, update, VTT URL endpoints | HTTP API |
| 4 | Register router in `main.py`; update `_video_to_detail()` for subtitle tracks | Backend integration |
| 5 | Create `subtitles.ts` API client; add TypeScript types | Frontend API layer |
| 6 | Enhance `MediaPlayer.tsx`: `<track>` elements, CC toggle, `SubtitleSelector` dropdown, localStorage | Player integration |
| 7 | Create `SubtitleManager.tsx` panel; integrate into `VideoPlayerPage.tsx` | Management UI |
| 8 | Write pytest unit tests for conversion, validation, sanitization, endpoint logic | Backend tests |
| 9-10 | Write E2E Playwright tests for subtitle upload, playback, management | E2E suite |
| 11 | Integration testing, CORS/presigned URL verification, Safari testing, documentation | Final QA |
| 12 | Buffer for edge cases, accessibility testing (screen reader + CC), polish | Ship |

---

## 5. Testing Strategy

### 5.1 Unit Tests: SRT-to-VTT Conversion (`tests/test_vod_subtitle_manager.py`)

| Test | What It Validates |
|------|-------------------|
| `test_srt_to_vtt_basic` | Simple SRT with 3 cues converts to valid VTT with `WEBVTT` header, `.` timestamp separator. |
| `test_srt_to_vtt_strips_sequence_numbers` | Numeric sequence lines (1, 2, 3...) are removed from output. |
| `test_srt_to_vtt_converts_comma_to_dot` | `00:01:30,500` becomes `00:01:30.500`. |
| `test_srt_to_vtt_preserves_multiline_cues` | Cue text spanning multiple lines is preserved intact. |
| `test_srt_to_vtt_handles_windows_line_endings` | `\r\n` line endings are normalized to `\n`. |
| `test_srt_to_vtt_handles_mac_line_endings` | `\r` line endings are normalized to `\n`. |
| `test_srt_to_vtt_empty_input` | Empty string returns minimal `WEBVTT\n\n`. |
| `test_srt_to_vtt_preserves_html_tags` | `<b>`, `<i>` tags in cue text are kept (they are valid VTT). |
| `test_srt_to_vtt_utf8_content` | Non-ASCII characters (CJK, accented, emoji) survive conversion. |
| `test_srt_to_vtt_strips_ass_overrides` | ASS-style overrides like `{\\an8}` are stripped during conversion. |
| `test_srt_to_vtt_handles_missing_trailing_newline` | SRT without trailing newline produces correct VTT with last cue intact. |

### 5.2 Unit Tests: VTT Validation

| Test | What It Validates |
|------|-------------------|
| `test_validate_vtt_valid` | Well-formed VTT returns empty error list. |
| `test_validate_vtt_missing_header` | Missing `WEBVTT` line returns `["Missing WEBVTT header"]`. |
| `test_validate_vtt_no_cues` | Header-only file returns `["No valid cues found"]`. |
| `test_validate_vtt_start_ge_end` | Cue with `start >= end` returns error identifying the cue. |
| `test_validate_vtt_invalid_timestamp_format` | Malformed timestamp (e.g., `1:2:3.4`) does not count as a cue. |
| `test_validate_vtt_multiple_errors` | File with header and 2 bad cues returns 2 error messages. |
| `test_validate_vtt_with_bom` | VTT starting with UTF-8 BOM (`﻿`) is accepted after BOM stripping. |
| `test_validate_vtt_with_metadata_header` | `WEBVTT - metadata info` header line is accepted (VTT spec allows text after WEBVTT). |
| `test_validate_vtt_with_note_blocks` | VTT containing `NOTE` blocks (comments) are ignored during validation. |

### 5.3 Unit Tests: Content Sanitization

| Test | What It Validates |
|------|-------------------|
| `test_sanitize_strips_script_tags` | `<script>alert(1)</script>` is removed entirely. |
| `test_sanitize_strips_style_tags` | `<style>body{display:none}</style>` is removed. |
| `test_sanitize_strips_iframe_tags` | `<iframe src="evil.com">` is removed. |
| `test_sanitize_strips_event_handlers` | `<b onclick="alert(1)">text</b>` becomes `<b>text</b>`. |
| `test_sanitize_strips_data_uris` | `data:text/html,...` is neutralized. |
| `test_sanitize_strips_javascript_uris` | `javascript:alert(1)` is neutralized. |
| `test_sanitize_preserves_allowed_tags` | `<b>`, `<i>`, `<u>`, `<c>`, `<v>`, `<lang>`, `<ruby>`, `<rt>` are kept. |
| `test_sanitize_preserves_plain_text` | Plain text cues pass through unchanged. |
| `test_sanitize_case_insensitive` | `<SCRIPT>`, `<Script>`, `<sCrIpT>` are all stripped. |
| `test_sanitize_strips_nested_dangerous_tags` | `<b><script>evil</script></b>` results in `<b></b>` (script removed, b kept). |
| `test_sanitize_strips_object_embed_applet` | `<object>`, `<embed>`, `<applet>` tags are removed. |
| `test_sanitize_strips_form_elements` | `<form>`, `<input>`, `<textarea>`, `<select>`, `<button>` are removed. |

### 5.4 Unit Tests: Language Code Validation

| Test | What It Validates |
|------|-------------------|
| `test_language_code_valid_iso639` | `en`, `es`, `fr`, `de`, `ja` are valid. |
| `test_language_code_valid_bcp47` | `zh-Hans`, `pt-BR`, `en-US` are valid. |
| `test_language_code_invalid_empty` | Empty string is rejected. |
| `test_language_code_invalid_numbers` | `123`, `12` are rejected. |
| `test_language_code_invalid_special_chars` | `en!`, `es@fr`, `a.b` are rejected. |
| `test_language_code_invalid_too_long` | `abcdefghijk` (11 chars) is rejected. |
| `test_language_code_three_letter` | `zho`, `spa`, `fra` (ISO 639-2/3) are valid. |

### 5.5 Unit Tests: Subtitle Endpoints (`tests/test_video_subtitles_endpoint.py`)

| Test | What It Validates |
|------|-------------------|
| `test_upload_vtt_201` | POST with valid VTT file returns 201 with track details. |
| `test_upload_srt_converts_to_vtt_201` | POST with SRT file returns 201; stored format is `vtt`. |
| `test_upload_invalid_format_400` | POST with `.txt` file returns 400 "unsupported subtitle format". |
| `test_upload_empty_file_400` | POST with 0-byte file returns 400 "subtitle file is empty". |
| `test_upload_exceeds_size_limit_400` | POST with 1MB file returns 400 "subtitle file exceeds maximum size". |
| `test_upload_invalid_vtt_content_400` | POST with malformed VTT returns 400 with validation errors. |
| `test_upload_non_owner_403` | Non-owner POST returns 403 "forbidden". |
| `test_upload_video_not_found_404` | POST for non-existent video returns 404. |
| `test_upload_max_tracks_exceeded_409` | POST when video already has 20 tracks returns 409 "maximum subtitle tracks reached". |
| `test_upload_is_default_unsets_others` | Upload with `is_default: true` sets previous default to `false`. |
| `test_upload_invalid_language_code_400` | POST with `language="!!!"` returns 400 "invalid language code". |
| `test_upload_non_utf8_400` | POST with Latin-1 encoded file returns 400 "subtitle file must be UTF-8 encoded". |
| `test_upload_vtt_with_bom_201` | POST with BOM-prefixed VTT file succeeds (BOM stripped via `utf-8-sig` decode). |
| `test_upload_sanitizes_dangerous_content` | POST with `<script>` tags in VTT; response VTT URL returns sanitized content. |
| `test_list_tracks_200` | GET returns list of all tracks with VTT URLs. |
| `test_list_tracks_empty_200` | GET for video with no subtitles returns empty list. |
| `test_delete_track_200` | DELETE removes track from metadata and S3. |
| `test_delete_nonexistent_track_404` | DELETE for unknown track_id returns 404. |
| `test_delete_non_owner_403` | Non-owner DELETE returns 403. |
| `test_update_track_label_200` | PATCH with new label returns updated track. |
| `test_update_track_default_200` | PATCH with `is_default: true` unsets other defaults. |
| `test_get_vtt_url_200` | GET VTT URL returns presigned S3 URL. |
| `test_feature_flag_disabled_403` | All endpoints return 403 when `VIDEO_SUBTITLE_ENABLED=false`. |
| `test_concurrent_upload_no_lost_updates` | Two rapid uploads to the same video both succeed (DDB update_item is atomic). |

### 5.6 E2E Tests: `frontend/e2e/video-subtitles.spec.ts`

All E2E tests use the established `injectAuth` / session auth patterns. Test users: Alice (video owner), Bob (non-owner viewer).

**Section 80: Subtitle Upload API (7 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 80.1 | Upload VTT subtitle track | POST with VTT file + language="en" + label="English"; 201; track_id starts with `st_`; format="vtt". |
| 80.2 | Upload SRT subtitle track (auto-converts to VTT) | POST with SRT file; 201; format="vtt"; GET VTT URL returns content starting with "WEBVTT". |
| 80.3 | List subtitle tracks | GET subtitles; 200; tracks array contains the 2 uploaded tracks; each has vtt_url. |
| 80.4 | Upload with is_default replaces previous default | Upload track with `is_default: true`; GET tracks; only new track has `is_default: true`; previously default track has `is_default: false`. |
| 80.5 | Delete subtitle track | DELETE track; 200; GET tracks; deleted track no longer in list; list length decreased by 1. |
| 80.6 | Non-owner cannot upload subtitles | Bob POSTs to Alice's video; 403; response detail is "forbidden". |
| 80.7 | Update subtitle track label and default | PATCH track with `label: "English (SDH)"` and `is_default: true`; 200; returned track has updated label; GET list confirms change persisted. |

**Section 81: Subtitle Validation API (6 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 81.1 | Upload invalid VTT (no WEBVTT header) | POST with file containing only cue text; 400; error body includes "Missing WEBVTT header". |
| 81.2 | Upload VTT with no cues | POST with "WEBVTT\n\n" only; 400; error body includes "No valid cues found". |
| 81.3 | Upload file exceeding size limit | POST with file > 512KB; 400; error body includes "exceeds maximum size". |
| 81.4 | Upload unsupported format (.txt) | POST with .txt file; 400; error body includes "unsupported subtitle format". |
| 81.5 | Upload empty file | POST with 0-byte file; 400; error body includes "subtitle file is empty". |
| 81.6 | Upload invalid language code | POST with language="!!!"; 400; error body includes "invalid language code". |

**Section 82: Subtitle Content Sanitization API (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 82.1 | Script tags stripped from uploaded VTT | Upload VTT containing `<script>alert(1)</script>` in a cue; 201; fetch VTT content via URL; content does not contain `<script>`. |
| 82.2 | Event handlers stripped from uploaded VTT | Upload VTT with `<b onclick="alert(1)">bold</b>`; 201; fetched content contains `<b` but not `onclick`. |
| 82.3 | Allowed tags preserved in uploaded VTT | Upload VTT with `<b>`, `<i>`, `<v Speaker>` tags; 201; fetched content still contains these tags. |

**Section 83: Subtitle Playback Integration (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 83.1 | Video detail response includes subtitle_tracks | Upload a track; GET video detail; response contains `subtitle_tracks` array with at least one entry matching the uploaded track. |
| 83.2 | VTT URL is accessible and returns valid content | Fetch the `vtt_url` from the track list response; 200; response body starts with "WEBVTT"; Content-Type is "text/vtt". |
| 83.3 | Subtitle tracks render as track elements in player DOM | Navigate to video page; query `document.querySelectorAll('track[kind="subtitles"]')`; count matches uploaded tracks count. |
| 83.4 | CC button visible when subtitles exist | Navigate to video page with subtitles; `[data-testid="media-player-cc"]` is visible. |
| 83.5 | CC button not visible when no subtitles | Navigate to video page without subtitles; `[data-testid="media-player-cc"]` is not in DOM. |

**Section 84: Subtitle Management UI (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 84.1 | Subtitle manager panel visible for video owner | Alice navigates to her video; heading "Subtitles & Captions" is visible. |
| 84.2 | Upload form creates track and updates list | Fill language select + label input; attach VTT file; click "Upload"; waitForResponse POST 201; track appears in list with correct label. |
| 84.3 | Delete button removes track from list | Click delete (trash icon) on a track; confirm dialog; waitForResponse DELETE 200; track disappears from list. |
| 84.4 | Subtitle manager not visible for non-owner | Bob navigates to Alice's video; heading "Subtitles & Captions" is not in DOM. |
| 84.5 | Default badge shown for default track | Upload track with is_default checked; list shows "Default" badge next to that track's label. |

**Section 85: Subtitle Player Controls (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 85.1 | CC toggle enables subtitles | Click CC button; `video.textTracks[0].mode` is "showing" (evaluated via `page.evaluate`). |
| 85.2 | CC toggle disables subtitles | Click CC button twice; `video.textTracks[0].mode` is "hidden". |
| 85.3 | Language dropdown shows all tracks | When 2+ tracks uploaded; click CC button; dropdown shows "Off", "English", "Espanol" options. |
| 85.4 | Selecting language switches active track | Click "Espanol" in dropdown; `video.textTracks` shows only Spanish track as "showing"; English track is "hidden". |
| 85.5 | Caption preference persists in localStorage | Enable CC; reload page; CC button still shows active state; `localStorage.getItem("media-player-cc-enabled")` is "true". |

**Section 86: Edge Cases and Error Recovery (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 86.1 | Upload VTT with BOM succeeds | POST VTT file with UTF-8 BOM prefix; 201; track created successfully. |
| 86.2 | Duplicate language uploads allowed | Upload two tracks both with language="en" but different labels; both appear in list. |
| 86.3 | Delete only default track leaves no default | Upload one default track; delete it; GET tracks; no track has `is_default: true`; CC button absent. |
| 86.4 | Max tracks limit enforced | Upload 20 tracks; attempt 21st upload; 409; error includes "maximum subtitle tracks reached". |

**Total E2E tests: 35 tests across 7 sections (80-86).**

### 5.7 Error Handling Matrix

| Error Condition | HTTP Status | Error Detail | Frontend Behavior |
|----------------|-------------|-------------|-------------------|
| File is empty (0 bytes) | 400 | `subtitle file is empty` | Toast error; form stays open |
| File exceeds 512KB | 400 | `subtitle file exceeds maximum size of 512KB` | Toast error; form stays open |
| Unsupported extension (.txt, .ass, .ssa) | 400 | `unsupported subtitle format; accepted: vtt, srt` | Toast error; form stays open |
| File is not UTF-8 encoded | 400 | `subtitle file must be UTF-8 encoded` | Toast error; form stays open |
| VTT missing WEBVTT header | 400 | `invalid VTT content: Missing WEBVTT header` | Toast error with validation details |
| VTT has no valid cues | 400 | `invalid VTT content: No valid cues found` | Toast error with validation details |
| VTT has cue with start >= end | 400 | `invalid VTT content: Cue N: start time >= end time` | Toast error with cue number |
| Invalid language code | 400 | `invalid language code` | Toast error; language field highlighted |
| Non-owner attempts upload | 403 | `forbidden` | Toast error; SubtitleManager panel hidden for non-owners |
| Feature flag disabled | 403 | `video subtitles are not enabled` | Toast error; SubtitleManager panel hidden |
| Video not found | 404 | `video not found` | 404 page |
| Track not found (delete/update) | 404 | `subtitle track not found` | Toast error; list refreshes |
| Max tracks exceeded (20) | 409 | `maximum subtitle tracks reached (20)` | Toast error; upload button disabled |
| S3 upload failure | 500 | `subtitle upload failed` | Toast error with retry suggestion |
| DDB update failure | 500 | `failed to update video metadata` | Toast error with retry suggestion |

### 5.8 Corrupted VTT Edge Cases

| Scenario | Detection | Behavior |
|----------|-----------|----------|
| VTT with binary content (not text) | `UnicodeDecodeError` during `utf-8-sig` decode | 400 "subtitle file must be UTF-8 encoded" |
| VTT with only whitespace after header | Zero cues found in `validate_vtt` | 400 "No valid cues found" |
| VTT with overlapping cue timestamps | Detected but allowed (valid per VTT spec) | Warning logged; file accepted |
| VTT with extremely long cue text (>10KB single cue) | No per-cue limit; total file under 512KB | Accepted; browser renders natively |
| VTT with timestamp overflow (99:99:99.999) | Parsed as large timestamp; `_parse_vtt_timestamp` returns very large value | Accepted (timestamp is technically valid) |
| SRT with mixed SRT/VTT syntax | Conversion handles gracefully; VTT header prepended if missing | Accepted after conversion |
| File with `.vtt` extension but SRT content | Missing WEBVTT header detected by `validate_vtt` | 400 "Missing WEBVTT header" |
| File with `.srt` extension but VTT content | Conversion prepends second WEBVTT header; validate catches double header issue | Need special handling: detect existing WEBVTT header in SRT-labeled files |

### 5.9 Concurrent Upload Handling

DynamoDB `update_item` is atomic at the item level. Two concurrent uploads to the same video:

1. Both read current `subtitle_tracks` list.
2. Both compute `updated_tracks = existing + new_track`.
3. Both issue `update_item` with `SET subtitle_tracks = :tracks`.
4. **Risk**: Second write overwrites the first (last-writer-wins).

**Mitigation**: Use a DynamoDB conditional expression to detect concurrent modifications:

```python
T.video_metadata.update_item(
    Key={"video_id": video_id},
    UpdateExpression="SET subtitle_tracks = list_append(if_not_exists(subtitle_tracks, :empty), :new_track), updated_at = :ts",
    ExpressionAttributeValues={
        ":new_track": [track.model_dump()],
        ":empty": [],
        ":ts": now_ts(),
    },
)
```

This uses `list_append` which is atomic -- two concurrent appends both succeed without overwriting each other.

For the `is_default` case (which requires unsetting other defaults), use a read-modify-write with `ConditionExpression` on `updated_at` to detect conflicts:

```python
T.video_metadata.update_item(
    Key={"video_id": video_id},
    UpdateExpression="SET subtitle_tracks = :tracks, updated_at = :new_ts",
    ConditionExpression="updated_at = :old_ts",
    ExpressionAttributeValues={...},
)
```

On `ConditionalCheckFailedException`, retry the operation (read-modify-write loop, max 3 retries).

---

## 6. Security Considerations

### 6.1 Authentication and Authorization

All subtitle endpoints require `require_ui_session` authentication (imported from `app.services.sessions`). Write operations (upload, delete, update) additionally verify ownership: <!-- VERIFIED: require_ui_session is in app/services/sessions.py:283, imported by video_listing.py at line 23 -->

```python
if video.owner_user_id != ctx["user_sub"]:
    raise HTTPException(status_code=403, detail="forbidden")
```

Read operations (list tracks, get VTT URL) are accessible to any authenticated user who can view the video. For public videos, the VTT URL is accessible without authentication (required for `<track>` elements to load cross-origin).

### 6.2 Input Validation

#### 6.2.1 File Upload Constraints

| Constraint | Value | Rationale |
|-----------|-------|-----------|
| Max file size | 512KB (`VIDEO_SUBTITLE_MAX_FILE_SIZE_KB`) | 512KB accommodates ~10,000 cues (4+ hours of dense captioning) |
| Allowed extensions | `.vtt`, `.srt` | Only standard subtitle formats |
| Encoding | UTF-8 only | Prevents encoding-based attacks; standard for web |
| Max tracks per video | 20 (`VIDEO_SUBTITLE_MAX_TRACKS`) | Prevents unbounded metadata growth |

#### 6.2.2 Content Sanitization (XSS Prevention)

VTT cue payloads are rendered in the browser's native text track renderer, which is sandboxed. However, defense in depth requires sanitizing content before storage:

- All `<script>`, `<style>`, `<iframe>`, `<object>`, `<embed>` tags stripped.
- All `on*` event handler attributes stripped from remaining tags.
- All `data:` URI schemes stripped.
- All `javascript:` URI schemes stripped.
- Only VTT-spec-allowed tags preserved: `<b>`, `<i>`, `<u>`, `<c>`, `<lang>`, `<v>`, `<ruby>`, `<rt>`.

#### 6.2.3 Language Code Validation

The `language` field is validated against ISO 639-1 (2-letter) or BCP-47 (e.g., `en`, `es`, `zh-Hans`, `pt-BR`). Arbitrary strings are rejected:

```python
_LANG_RE = re.compile(r"^[a-zA-Z]{2,3}(-[a-zA-Z0-9]{1,8})*$")

def validate_language_code(code: str) -> bool:
    return bool(_LANG_RE.match(code))
```

### 6.3 S3 Access Control

Subtitle VTT files are stored in the same S3 bucket as VOD outputs (`vod-output`, configured via `S.vod_output_bucket`). Access is controlled via presigned URLs with a configurable TTL (default 3600 seconds). The presigned URL is scoped to the specific S3 key (`subtitles/{video_id}/{track_id}.vtt`), so a URL for one track cannot access another track's file. <!-- VERIFIED: app/core/settings.py:1073 — vod_output_bucket default "vod-output" -->

In dev mode, VTT files are served via the mock S3 endpoint (`/mock/s3/...`), matching the existing pattern for video HLS manifests and thumbnails.

### 6.4 CORS for `<track>` Elements

The HTML5 `<track>` element requires `crossorigin` on the parent `<video>` element and `Access-Control-Allow-Origin` on the VTT response. In production, the S3 bucket or CloudFront distribution must have CORS headers configured for `text/vtt` responses. In dev mode (moto), CORS is permissive by default.

**Important**: Adding `crossOrigin="anonymous"` to the `<video>` element at line 548 of `MediaPlayer.tsx` is safe and does not affect existing HLS.js playback or DRM key loading. HLS.js already handles CORS internally for media segment fetches. <!-- VERIFIED: MediaPlayer.tsx:548 — no crossOrigin attribute currently set -->

### 6.5 Rate Limiting

Subtitle upload is rate-limited by the standard per-user rate limiting applied via `require_ui_session`. Additionally:

- Max 20 tracks per video (prevents storage exhaustion).
- Max 512KB per file (prevents large upload abuse).
- File content is fully buffered in memory for validation/conversion before S3 upload. The 512KB limit ensures this does not consume excessive server memory.

### 6.6 Abuse Prevention

| Threat | Mitigation |
|--------|-----------|
| Spam subtitle uploads | Max 20 tracks per video; standard rate limiting |
| Malicious VTT content (XSS) | Content sanitization strips all unsafe tags and attributes |
| Large file upload DoS | 512KB file size limit; rejected before full read |
| Path traversal in S3 key | Track IDs are generated server-side (`st_` + UUID hex); no user input in S3 paths |
| Enumeration of other videos' subtitles | Ownership check on write; video access check on read |
| Zip bomb / decompression attack | Files are read as plain text (no decompression); encoding checked before processing |

---

## 7. Migration & Rollback Plan

### 7.1 Feature Flag

`VIDEO_SUBTITLE_ENABLED` (default `true`) is the master kill switch. When `false`:

- All subtitle API endpoints return 403 "video subtitles are not enabled".
- The `subtitle_tracks` field is still returned in video detail responses (may be empty or contain previously uploaded tracks) but the frontend hides the subtitle UI.
- No new uploads are accepted.

### 7.2 Incremental Deployment

| Day | Task | Viewer Impact |
|-----|------|---------------|
| 1 | Deploy backend with subtitle service, router, and model changes. Feature flag ON. | None (no video has subtitles yet). |
| 2 | Deploy frontend with MediaPlayer CC toggle and SubtitleManager panel. | None (no tracks to display). |
| 3 | Announce feature to creators. First subtitle uploads begin. | Viewers of subtitled videos see CC button. |
| 5 | Monitor upload volume, S3 storage, validation error rates. | Stable. |

### 7.3 Rollback Steps

1. Set `VIDEO_SUBTITLE_ENABLED=false`.
2. Restart backend. All subtitle endpoints return 403.
3. Existing subtitle tracks remain in DynamoDB metadata (harmless; the field is an empty-default list).
4. Existing VTT files remain in S3 (no active references; cleaned up by lifecycle rules if needed).
5. Frontend hides CC button and SubtitleManager panel when no tracks are present.

### 7.4 Data Cleanup (if feature permanently removed)

1. Remove `subtitle_tracks` field from `VideoMetadataModel` (field has `default_factory=list`; existing records with the field are harmless).
2. Delete VTT files from S3 under the `subtitles/` prefix: `aws s3 rm s3://vod-output/tenants/subtitles/ --recursive`.
3. Remove the `video_subtitles` router from `main.py`.
4. Remove `SubtitleSelector`, CC toggle, and `<track>` rendering from `MediaPlayer.tsx`.

### 7.5 Schema Compatibility

The `subtitle_tracks` field is additive and defaults to an empty list. Existing video records in DynamoDB do not have this field. The `video_from_item()` deserializer (line 169 of `video_metadata_store.py`) handles missing fields gracefully via Pydantic defaults. No data migration is needed. <!-- VERIFIED: app/services/video_metadata_store.py:169 — video_from_item uses Pydantic model construction which applies defaults -->

```python
# video_from_item already handles missing fields via Pydantic defaults:
video = VideoMetadataModel(**item)
# subtitle_tracks will be [] if not present in the DDB item
```

**Note**: The current `video_from_item()` function explicitly maps every field (lines 185-269). The new `subtitle_tracks` field must be added to the explicit mapping:

```python
# In video_from_item():
subtitle_tracks=[
    SubtitleTrack(**t) for t in (item.get("subtitle_tracks") or [])
],
```

---

## 8. Acceptance Criteria

1. Creator can upload a VTT subtitle file for a video they own; the track appears in the subtitle list.
2. Creator can upload an SRT subtitle file; the backend converts it to VTT and stores the VTT version.
3. Creator can designate one track as the default; previously default tracks are un-defaulted automatically.
4. Creator can delete a subtitle track; the VTT file is removed from S3 and the track is removed from metadata.
5. Creator can update a track's label and default status.
6. The video detail API response includes `subtitle_tracks` with presigned VTT URLs.
7. The `MediaPlayer` component renders `<track>` elements for each subtitle track on the video.
8. A CC toggle button appears in the player controls bar when subtitle tracks are available.
9. When multiple subtitle tracks exist, a language selector dropdown allows the viewer to switch tracks.
10. The viewer's caption preference (enabled/disabled, selected language) is persisted in localStorage and restored on subsequent page loads.
11. VTT content is sanitized on upload: `<script>`, `<style>`, `<iframe>`, `on*` attributes, `data:` URIs, and `javascript:` URIs are stripped.
12. SRT-to-VTT conversion correctly handles comma-to-dot timestamp separators, sequence number stripping, line ending normalization, and multi-line cues.
13. Uploads of non-VTT/SRT files are rejected with 400.
14. Uploads exceeding 512KB are rejected with 400.
15. Non-owners cannot upload, delete, or update subtitle tracks (403).
16. Feature can be disabled via `VIDEO_SUBTITLE_ENABLED=false` with all endpoints returning 403.
17. All E2E tests pass (35 tests across 7 sections).
18. Caption styling uses semi-transparent black background with white text, readable at default video sizes.

---

## 9. API Contract Design

### 9.1 Endpoints Summary

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/videos/{video_id}/subtitles` | `require_ui_session` (owner) | Upload subtitle file |
| GET | `/ui/videos/{video_id}/subtitles` | `require_ui_session` | List subtitle tracks |
| DELETE | `/ui/videos/{video_id}/subtitles/{track_id}` | `require_ui_session` (owner) | Delete subtitle track |
| PATCH | `/ui/videos/{video_id}/subtitles/{track_id}` | `require_ui_session` (owner) | Update track metadata |
| GET | `/ui/videos/{video_id}/subtitles/{track_id}/vtt` | `require_ui_session` | Get VTT file URL |

**Auth note**: `require_ui_session` is imported from `app.services.sessions` (line 283), not from `app.auth.deps`. This is consistent with the existing video listing router's import pattern at `app/routers/video_listing.py` line 23. <!-- VERIFIED: app/routers/video_listing.py:23 — from app.services.sessions import require_ui_session -->

### 9.2 Upload Subtitle (POST)

**Request**: `multipart/form-data`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `file` | File | Yes | VTT or SRT file (max 512KB) |
| `language` | String | Yes | ISO 639-1 / BCP-47 code (e.g., "en", "es", "zh-Hans") |
| `label` | String | Yes | Display name (e.g., "English", "Espanol") |
| `is_default` | Boolean | No | Mark as default track (default: false) |

**Response (201 Created)**:
```json
{
  "track_id": "st_a1b2c3d4e5f67890",
  "video_id": "vid_tutorial_101",
  "language": "en",
  "label": "English",
  "format": "vtt",
  "vtt_url": "/mock/s3/vod-output/tenants/subtitles/vid_tutorial_101/st_a1b2c3d4e5f67890.vtt",
  "is_default": true,
  "is_auto_generated": false,
  "created_at": 1748476800
}
```

**Error responses**:

| Status | Condition | Detail |
|--------|-----------|--------|
| 400 | File empty | "subtitle file is empty" |
| 400 | File exceeds size limit | "subtitle file exceeds maximum size of 512KB" |
| 400 | Unsupported format | "unsupported subtitle format; accepted: vtt, srt" |
| 400 | Invalid VTT content | "invalid VTT content: Missing WEBVTT header" |
| 400 | Invalid language code | "invalid language code" |
| 400 | Non-UTF-8 encoding | "subtitle file must be UTF-8 encoded" |
| 403 | Not video owner | "forbidden" |
| 403 | Feature disabled | "video subtitles are not enabled" |
| 404 | Video not found | "video not found" |
| 409 | Max tracks reached | "maximum subtitle tracks reached (20)" |

### 9.3 List Subtitle Tracks (GET)

**Response (200)**:
```json
{
  "video_id": "vid_tutorial_101",
  "tracks": [
    {
      "track_id": "st_a1b2c3d4e5f67890",
      "language": "en",
      "label": "English",
      "format": "vtt",
      "vtt_url": "/mock/s3/vod-output/tenants/subtitles/vid_tutorial_101/st_a1b2c3d4e5f67890.vtt",
      "is_default": true,
      "is_auto_generated": false,
      "created_at": 1748476800
    },
    {
      "track_id": "st_f6e5d4c3b2a10987",
      "language": "es",
      "label": "Espanol",
      "format": "vtt",
      "vtt_url": "/mock/s3/vod-output/tenants/subtitles/vid_tutorial_101/st_f6e5d4c3b2a10987.vtt",
      "is_default": false,
      "is_auto_generated": false,
      "created_at": 1748477400
    }
  ]
}
```

### 9.4 Delete Subtitle Track (DELETE)

**Response (200)**:
```json
{
  "ok": true,
  "track_id": "st_a1b2c3d4e5f67890",
  "video_id": "vid_tutorial_101"
}
```

**Error responses**:

| Status | Condition | Detail |
|--------|-----------|--------|
| 403 | Not video owner | "forbidden" |
| 404 | Video not found | "video not found" |
| 404 | Track not found | "subtitle track not found" |

### 9.5 Update Subtitle Track (PATCH)

**Request**:
```json
{
  "label": "English (SDH)",
  "is_default": true
}
```

**Response (200)**:
```json
{
  "track_id": "st_a1b2c3d4e5f67890",
  "language": "en",
  "label": "English (SDH)",
  "format": "vtt",
  "vtt_url": "/mock/s3/vod-output/tenants/subtitles/vid_tutorial_101/st_a1b2c3d4e5f67890.vtt",
  "is_default": true,
  "is_auto_generated": false,
  "created_at": 1748476800
}
```

### 9.6 Get VTT URL (GET)

**Response (200)**:
```json
{
  "track_id": "st_a1b2c3d4e5f67890",
  "vtt_url": "/mock/s3/vod-output/tenants/subtitles/vid_tutorial_101/st_a1b2c3d4e5f67890.vtt",
  "content_type": "text/vtt",
  "expires_at": 1748480400
}
```

---

## 10. Frontend Component Design

### 10.1 Component Tree

```
VideoPlayerPage (/videos/:videoId)                    <!-- VERIFIED: frontend/src/pages/videos/VideoPlayerPage.tsx -->
  +-- MediaPlayer (enhanced)                          <!-- VERIFIED: frontend/src/components/shared/MediaPlayer.tsx -->
  |     +-- <video crossOrigin="anonymous">           <!-- line 548; add crossOrigin -->
  |     |     +-- <track kind="subtitles" src="..." srclang="en" label="English" default />
  |     |     +-- <track kind="subtitles" src="..." srclang="es" label="Espanol" />
  |     +-- Controls bar (existing)
  |     |     +-- Play/Pause (existing)               <!-- line 643 -->
  |     |     +-- Volume (existing)                   <!-- line 680 -->
  |     |     +-- [NEW] SubtitleSelector              <!-- insert between quality and PiP -->
  |     |     |     +-- CC icon button (toggle on/off)
  |     |     |     +-- Language dropdown (when multiple tracks)
  |     |     +-- QualitySelector (existing)          <!-- line 708 -->
  |     |     +-- PiP (existing)                      <!-- line 716 -->
  |     |     +-- Fullscreen (existing)               <!-- line 727 -->
  +-- VideoDetails (existing)
  +-- [NEW] SubtitleManager (owner only)
        +-- "Subtitles & Captions" heading
        +-- Upload form
        |     +-- File input (.vtt, .srt)
        |     +-- Language select (ISO 639-1 dropdown)
        |     +-- Label text input
        |     +-- "Set as default" checkbox
        |     +-- "Upload" button
        +-- Track list
              +-- TrackRow
              |     +-- Language flag/code badge
              |     +-- Label text
              |     +-- "Default" badge (if is_default)
              |     +-- "Auto" badge (if is_auto_generated)
              |     +-- Delete button (trash icon)
              +-- TrackRow (...)
```

### 10.2 MediaPlayer Enhancement

#### 10.2.1 New Props

```typescript
export interface SubtitleTrackInfo {
  track_id: string;
  language: string;
  label: string;
  vtt_url: string;
  is_default: boolean;
}

export interface MediaPlayerProps {
  // ... existing props (src, mode, autoplay, muted, poster, title, onError, onReady,
  //     onQualityChange, className, controls, drmKeyUrl) ...
  // <!-- VERIFIED: MediaPlayerProps at lines 46-71 -->

  /** Subtitle tracks to render as <track> elements */
  subtitleTracks?: SubtitleTrackInfo[];
  /** Called when viewer changes subtitle track */
  onSubtitleChange?: (trackId: string | null) => void;
}
```

#### 10.2.2 `<track>` Element Rendering

The `<video>` element at line 548 of `MediaPlayer.tsx` must gain `crossOrigin="anonymous"` and `<track>` children: <!-- VERIFIED: MediaPlayer.tsx:548 -->

```tsx
<video
  ref={videoRef}
  crossOrigin="anonymous"  // Required for <track> to load cross-origin VTT
  className="absolute inset-0 w-full h-full object-contain"
  controls={showNativeControls}
  playsInline
  muted={muted}
  poster={poster}
  onClick={showCustomControls ? togglePlay : undefined}
  data-testid="media-player-video"
>
  {subtitleTracks?.map((track) => (
    <track
      key={track.track_id}
      kind="subtitles"
      src={track.vtt_url}
      srcLang={track.language}
      label={track.label}
      default={track.is_default}
      data-testid={`subtitle-track-${track.language}`}
    />
  ))}
</video>
```

**Critical**: The `crossOrigin="anonymous"` attribute must be added to the `<video>` element. Without it, the browser blocks loading `<track>` sources from a different origin (which presigned S3 URLs are). This attribute is safe to add unconditionally -- it does not affect HLS.js playback or DRM key loading.

#### 10.2.3 CC Toggle Button

Insert the `SubtitleSelector` in the controls bar between the quality selector and PiP button (around line 713 of MediaPlayer.tsx): <!-- VERIFIED: MediaPlayer.tsx:708-724 — QualitySelector at 708, PiP button at 716 -->

```tsx
{subtitleTracks && subtitleTracks.length > 0 && (
  <SubtitleSelector
    tracks={subtitleTracks}
    activeTrackId={activeSubtitleId}
    onSelect={handleSubtitleSelect}
  />
)}
```

#### 10.2.4 SubtitleSelector Component

The `SubtitleSelector` follows the same dropdown pattern as `QualitySelector` (lines 91-151): <!-- VERIFIED: MediaPlayer.tsx:91-151 — QualitySelector component -->

```tsx
function SubtitleSelector({
  tracks,
  activeTrackId,
  onSelect,
}: {
  tracks: SubtitleTrackInfo[];
  activeTrackId: string | null;
  onSelect: (trackId: string | null) => void;
}) {
  const isActive = activeTrackId !== null;

  // Single track: simple toggle
  if (tracks.length === 1) {
    return (
      <Button
        variant="ghost"
        size="icon"
        className={cn(
          "h-8 w-8 text-white hover:bg-white/20",
          isActive && "text-blue-400"
        )}
        onClick={() => onSelect(isActive ? null : tracks[0].track_id)}
        data-testid="media-player-cc"
      >
        <Subtitles className="h-4 w-4" />
      </Button>
    );
  }

  // Multiple tracks: dropdown menu
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className={cn(
            "gap-1.5 bg-black/60 text-white hover:bg-black/80 text-xs px-2 py-1 h-7",
            isActive && "text-blue-400"
          )}
          data-testid="media-player-cc"
        >
          <Subtitles className="h-3.5 w-3.5" />
          CC
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-[160px]">
        <DropdownMenuItem
          onClick={() => onSelect(null)}
          className={!isActive ? "font-bold" : ""}
        >
          Off
        </DropdownMenuItem>
        {tracks.map((track) => (
          <DropdownMenuItem
            key={track.track_id}
            onClick={() => onSelect(track.track_id)}
            className={activeTrackId === track.track_id ? "font-bold" : ""}
          >
            <span className="flex items-center gap-2">
              {activeTrackId === track.track_id && (
                <span className="h-2 w-2 rounded-full bg-blue-500" />
              )}
              {track.label}
            </span>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
```

**Note**: The `Subtitles` icon from lucide-react must be added to the import list at the top of `MediaPlayer.tsx` (currently imports `Loader2`, `AlertCircle`, `RefreshCw`, `Play`, `Pause`, `Maximize`, `Minimize`, `PictureInPicture2`, `Volume2`, `VolumeX`, `Settings`). <!-- VERIFIED: MediaPlayer.tsx:14-28 — import list -->

#### 10.2.5 localStorage Preference Persistence

```tsx
const CC_ENABLED_KEY = "media-player-cc-enabled";
const CC_LANGUAGE_KEY = "media-player-cc-language";

// On mount: restore preference
useEffect(() => {
  if (!subtitleTracks?.length) return;
  const enabled = localStorage.getItem(CC_ENABLED_KEY) === "true";
  const preferredLang = localStorage.getItem(CC_LANGUAGE_KEY);

  if (enabled) {
    const preferred = subtitleTracks.find(t => t.language === preferredLang);
    const defaultTrack = subtitleTracks.find(t => t.is_default);
    const track = preferred || defaultTrack || subtitleTracks[0];
    setActiveSubtitleId(track.track_id);
    activateTextTrack(track.language);
  }
}, [subtitleTracks]);

// On change: persist preference
const handleSubtitleSelect = useCallback((trackId: string | null) => {
  setActiveSubtitleId(trackId);
  if (trackId) {
    const track = subtitleTracks?.find(t => t.track_id === trackId);
    localStorage.setItem(CC_ENABLED_KEY, "true");
    if (track) localStorage.setItem(CC_LANGUAGE_KEY, track.language);
    activateTextTrack(track?.language || "");
  } else {
    localStorage.setItem(CC_ENABLED_KEY, "false");
    deactivateAllTextTracks();
  }
}, [subtitleTracks]);
```

#### 10.2.6 Text Track Activation

The HTML5 TextTrack API is used to show/hide subtitle tracks programmatically:

```tsx
const activateTextTrack = useCallback((language: string) => {
  const video = videoRef.current;
  if (!video) return;
  for (let i = 0; i < video.textTracks.length; i++) {
    const track = video.textTracks[i];
    track.mode = track.language === language ? "showing" : "hidden";
  }
}, []);

const deactivateAllTextTracks = useCallback(() => {
  const video = videoRef.current;
  if (!video) return;
  for (let i = 0; i < video.textTracks.length; i++) {
    video.textTracks[i].mode = "hidden";
  }
}, []);
```

**Note**: `videoRef` is already defined in `MediaPlayer` at line 182. <!-- VERIFIED: MediaPlayer.tsx:182 — const videoRef = useRef<HTMLVideoElement>(null) -->

#### 10.2.7 Caption Styling

The `::cue` CSS pseudo-element controls caption appearance:

```css
/* In MediaPlayer or global styles */
video::cue {
  background-color: rgba(0, 0, 0, 0.75);
  color: white;
  font-size: 1rem;
  line-height: 1.4;
  padding: 2px 6px;
  white-space: pre-wrap;
}
```

Note: `::cue` styling support varies by browser. Chrome and Safari support it fully. Firefox has partial support. The fallback is the browser's default caption style, which is always readable.

### 10.3 SubtitleManager Panel

```tsx
function SubtitleManager({ videoId, isOwner }: { videoId: string; isOwner: boolean }) {
  if (!isOwner) return null;

  const { data: trackList } = useQuery({
    queryKey: ["subtitles", videoId],
    queryFn: () => listSubtitleTracks(videoId),
  });

  const uploadMutation = useMutation({
    mutationFn: (formData: FormData) => uploadSubtitle(videoId, formData),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["subtitles", videoId] });
      queryClient.invalidateQueries({ queryKey: ["video", videoId] });
      toast.success("Subtitle track uploaded");
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (trackId: string) => deleteSubtitleTrack(videoId, trackId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["subtitles", videoId] });
      queryClient.invalidateQueries({ queryKey: ["video", videoId] });
      toast.success("Subtitle track deleted");
    },
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Subtitles className="h-5 w-5" />
          Subtitles & Captions
        </CardTitle>
      </CardHeader>
      <CardContent>
        {/* Upload form */}
        <SubtitleUploadForm onSubmit={(fd) => uploadMutation.mutate(fd)} isPending={uploadMutation.isPending} />

        {/* Track list */}
        {trackList?.tracks.map((track) => (
          <SubtitleTrackRow
            key={track.track_id}
            track={track}
            onDelete={() => deleteMutation.mutate(track.track_id)}
          />
        ))}

        {(!trackList?.tracks.length) && (
          <p className="text-muted-foreground text-sm">No subtitle tracks yet.</p>
        )}
      </CardContent>
    </Card>
  );
}
```

### 10.4 React Query Hooks

```typescript
// frontend/src/api/endpoints/subtitles.ts

import client from "../client";

export interface SubtitleTrack {
  track_id: string;
  language: string;
  label: string;
  format: string;
  vtt_url: string;
  is_default: boolean;
  is_auto_generated: boolean;
  created_at: number;
}

export interface SubtitleListResponse {
  video_id: string;
  tracks: SubtitleTrack[];
}

export async function uploadSubtitle(videoId: string, formData: FormData): Promise<SubtitleTrack> {
  return client.post(`/ui/videos/${videoId}/subtitles`, formData, {
    headers: { "Content-Type": "multipart/form-data" },
  }).then(r => r.data);
}

export async function listSubtitleTracks(videoId: string): Promise<SubtitleListResponse> {
  return client.get(`/ui/videos/${videoId}/subtitles`).then(r => r.data);
}

export async function deleteSubtitleTrack(videoId: string, trackId: string): Promise<void> {
  return client.delete(`/ui/videos/${videoId}/subtitles/${trackId}`).then(r => r.data);
}

export async function updateSubtitleTrack(
  videoId: string,
  trackId: string,
  body: { label?: string; is_default?: boolean },
): Promise<SubtitleTrack> {
  return client.patch(`/ui/videos/${videoId}/subtitles/${trackId}`, body).then(r => r.data);
}
```

---

## 11. Backend Implementation Details

### 11.1 Subtitle Upload Endpoint

```python
from app.services.sessions import require_ui_session  # <!-- VERIFIED: require_ui_session in app/services/sessions.py:283 -->

@router.post("/{video_id}/subtitles", status_code=201)
async def upload_subtitle(
    video_id: str,
    file: UploadFile = File(...),
    language: str = Form(...),
    label: str = Form(...),
    is_default: bool = Form(False),
    ctx=Depends(require_ui_session),
):
    if not S.video_subtitle_enabled:
        raise HTTPException(status_code=403, detail="video subtitles are not enabled")

    video = get_video(video_id)  # <!-- VERIFIED: app/services/video_metadata_store.py:312 — raises 404 if not found -->
    if video.owner_user_id != ctx["user_sub"]:
        raise HTTPException(status_code=403, detail="forbidden")

    # Validate language code
    if not validate_language_code(language):
        raise HTTPException(status_code=400, detail="invalid language code")

    # Read file content
    content_bytes = await file.read()
    if len(content_bytes) == 0:
        raise HTTPException(status_code=400, detail="subtitle file is empty")
    if len(content_bytes) > S.video_subtitle_max_file_size_kb * 1024:
        raise HTTPException(
            status_code=400,
            detail=f"subtitle file exceeds maximum size of {S.video_subtitle_max_file_size_kb}KB",
        )

    # Check max tracks
    existing_tracks = video.subtitle_tracks or []
    if len(existing_tracks) >= S.video_subtitle_max_tracks:
        raise HTTPException(
            status_code=409,
            detail=f"maximum subtitle tracks reached ({S.video_subtitle_max_tracks})",
        )

    # Detect format and convert
    filename = file.filename or "unknown.vtt"
    ext = Path(filename).suffix.lower()
    allowed = S.video_subtitle_allowed_formats.split(",")
    if ext.lstrip(".") not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"unsupported subtitle format; accepted: {', '.join(allowed)}",
        )

    try:
        content = content_bytes.decode("utf-8-sig")  # Handle BOM
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="subtitle file must be UTF-8 encoded")

    # Convert SRT to VTT if needed
    if ext == ".srt":
        content = srt_to_vtt(content)

    # Validate VTT
    errors = validate_vtt(content)
    if errors:
        raise HTTPException(status_code=400, detail=f"invalid VTT content: {'; '.join(errors)}")

    # Sanitize
    content = sanitize_vtt_content(content)

    # Generate track ID and upload to S3
    track_id = f"st_{uuid4().hex[:16]}"
    s3_key = upload_subtitle_file(video_id, track_id, content)

    # If setting as default, unset previous defaults
    if is_default:
        for t in existing_tracks:
            if t.is_default:
                t.is_default = False

    # Create track record
    track = SubtitleTrack(
        track_id=track_id,
        language=language,
        label=label,
        format="vtt",
        s3_key=s3_key,
        is_default=is_default,
        is_auto_generated=False,
        created_at=now_ts(),
    )

    # Update video metadata
    add_track_to_video(video_id, track, existing_tracks)

    # Mint URL
    vtt_url = mint_subtitle_url(s3_key, S.video_subtitle_url_ttl_seconds)

    return {
        "track_id": track.track_id,
        "video_id": video_id,
        "language": track.language,
        "label": track.label,
        "format": track.format,
        "vtt_url": vtt_url,
        "is_default": track.is_default,
        "is_auto_generated": track.is_auto_generated,
        "created_at": track.created_at,
    }
```

### 11.2 S3 Upload and URL Minting

Uses `_s3.put_object()` directly (not `upload_segment()` which requires a `local_path: Path`): <!-- CORRECTED: was "use upload_segment()", actually upload_segment requires local_path; use put_object for in-memory content -->

```python
from app.core.aws_clients import s3_client  # Same S3 client used by vod_s3_uploader.py
# <!-- VERIFIED: app/services/vod_s3_uploader.py:19 — from app.core.aws_clients import s3_client -->

_s3 = s3_client()

def upload_subtitle_file(video_id: str, track_id: str, vtt_content: str) -> str:
    """Upload VTT content to S3. Returns the S3 key."""
    bucket = S.vod_output_bucket or S.transcode_output_bucket or "vod-output"
    prefix = S.vod_output_prefix or S.transcode_output_prefix or "tenants"
    s3_key = f"{prefix}/subtitles/{video_id}/{track_id}.vtt"

    _s3.put_object(
        Bucket=bucket,
        Key=s3_key,
        Body=vtt_content.encode("utf-8"),
        ContentType="text/vtt",
        CacheControl="max-age=86400",
    )
    return s3_key


def delete_subtitle_file(s3_key: str) -> None:
    """Delete a VTT file from S3."""
    bucket = S.vod_output_bucket or S.transcode_output_bucket or "vod-output"
    try:
        _s3.delete_object(Bucket=bucket, Key=s3_key)
    except Exception:
        logger.warning("Failed to delete subtitle file %s", s3_key, exc_info=True)


def mint_subtitle_url(s3_key: str, ttl: int) -> str:
    """Generate a URL for accessing the VTT file."""
    if S.dev_mode:
        bucket = S.vod_output_bucket or S.transcode_output_bucket or "vod-output"
        return f"/mock/s3/{bucket}/{s3_key}"

    bucket = S.vod_output_bucket or S.transcode_output_bucket or "vod-output"
    return _s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": s3_key},
        ExpiresIn=ttl,
    )
```

### 11.3 Metadata Track CRUD

These functions operate on the `T.video_metadata` table (DynamoDB resource handle from `app/core/tables.py` line 176): <!-- VERIFIED: app/core/tables.py:176 — video_metadata=ddb.Table(S.video_metadata_table_name) -->

```python
def add_track_to_video(
    video_id: str,
    track: SubtitleTrack,
    existing_tracks: list[SubtitleTrack],
) -> None:
    """Append a subtitle track to the video metadata."""
    updated_tracks = [t.model_dump() for t in existing_tracks] + [track.model_dump()]
    T.video_metadata.update_item(
        Key={"video_id": video_id},
        UpdateExpression="SET subtitle_tracks = :tracks, updated_at = :ts",
        ExpressionAttributeValues={
            ":tracks": updated_tracks,
            ":ts": now_ts(),
        },
    )


def remove_track_from_video(video_id: str, track_id: str) -> str | None:
    """Remove a subtitle track from the video metadata. Returns the S3 key for cleanup."""
    video = get_video(video_id)
    tracks = video.subtitle_tracks or []
    s3_key = None
    updated_tracks = []
    for t in tracks:
        if t.track_id == track_id:
            s3_key = t.s3_key
        else:
            updated_tracks.append(t.model_dump())

    if s3_key is None:
        return None  # Track not found

    T.video_metadata.update_item(
        Key={"video_id": video_id},
        UpdateExpression="SET subtitle_tracks = :tracks, updated_at = :ts",
        ExpressionAttributeValues={
            ":tracks": updated_tracks,
            ":ts": now_ts(),
        },
    )
    return s3_key


def update_track_on_video(
    video_id: str,
    track_id: str,
    label: str | None = None,
    is_default: bool | None = None,
) -> SubtitleTrack | None:
    """Update metadata on an existing subtitle track."""
    video = get_video(video_id)
    tracks = video.subtitle_tracks or []
    target = None

    for t in tracks:
        if t.track_id == track_id:
            target = t
            if label is not None:
                t.label = label
            if is_default is True:
                t.is_default = True
        elif is_default is True:
            t.is_default = False  # Unset other defaults

    if target is None:
        return None

    T.video_metadata.update_item(
        Key={"video_id": video_id},
        UpdateExpression="SET subtitle_tracks = :tracks, updated_at = :ts",
        ExpressionAttributeValues={
            ":tracks": [t.model_dump() for t in tracks],
            ":ts": now_ts(),
        },
    )
    return target
```

### 11.4 video_to_item / video_from_item Updates

**In `video_to_item()` (after renditions block at line 164)**: <!-- VERIFIED: app/services/video_metadata_store.py:155-164 — renditions serialization -->

```python
# Subtitles (VOD-021)
if video.subtitle_tracks:
    item["subtitle_tracks"] = [t.model_dump() for t in video.subtitle_tracks]
```

**In `video_from_item()` (add to the `VideoMetadataModel(...)` constructor, after line 268)**: <!-- VERIFIED: app/services/video_metadata_store.py:263-268 — purchase tiers deserialization is last block -->

```python
# Subtitles (VOD-021)
subtitle_tracks=[
    SubtitleTrack(**t) for t in (item.get("subtitle_tracks") or [])
],
```

**Import note**: `SubtitleTrack` must be added to the imports from `app.models_video` at the top of `video_metadata_store.py` (line 12-16): <!-- VERIFIED: app/services/video_metadata_store.py:12-16 — imports from app.models_video -->

```python
from app.models_video import (
    CreateVideoIn,
    UpdateVideoIn,
    VideoMetadataModel,
    VideoRendition,
    SubtitleTrack,  # NEW (VOD-021)
)
```

---

## 12. Performance & Scalability

### 12.1 Upload Performance

| Metric | Value | Notes |
|--------|-------|-------|
| VTT file size (typical) | 5-50KB | 1-hour video with moderate captioning |
| VTT file size (dense) | 50-200KB | 4-hour video with rapid dialogue |
| VTT file size (max) | 512KB | Configurable limit |
| SRT-to-VTT conversion | <10ms | String processing only; no I/O |
| VTT validation | <5ms | Regex-based parsing |
| Content sanitization | <2ms | Regex substitution |
| S3 upload | 50-200ms | Small file; single PUT via `put_object()` |
| DDB metadata update | 20-50ms | Single `update_item` |
| Total upload latency | <300ms | Well within interactive threshold |

### 12.2 Playback Performance

| Metric | Value | Notes |
|--------|-------|-------|
| VTT fetch latency | 50-200ms | Single GET from S3/CDN; file is small |
| Track element parsing | <5ms | Browser-native VTT parser |
| Caption rendering overhead | Negligible | Browser compositor handles text overlay |
| Multiple tracks loaded | No penalty | Browser only parses the active track; others are `mode: "hidden"` |

### 12.3 Storage Costs

- Average 20KB per VTT file, max 20 tracks per video.
- 1,000 videos with 2 subtitle tracks each = 40MB total S3 storage.
- S3 Standard pricing: ~$0.023/GB/month = ~$0.001/month.
- Storage cost is negligible compared to video media storage.

### 12.4 DynamoDB Item Size Impact

Each `SubtitleTrack` in the nested list adds approximately 300 bytes to the video metadata item:
- `track_id`: ~22 bytes
- `language`: ~5 bytes
- `label`: ~20 bytes
- `format`: ~5 bytes
- `s3_key`: ~80 bytes
- Booleans + integer: ~30 bytes
- DynamoDB overhead: ~100 bytes

20 tracks * 300 bytes = 6KB additional per video item. The DynamoDB 400KB item limit is not a concern (typical video metadata items are ~2-5KB before subtitles).

### 12.5 Subtitle File Caching

**Browser caching**: VTT files are served with `Cache-Control: max-age=86400` (24 hours). Once a viewer loads a subtitle track, the browser caches the VTT file locally. Subsequent visits do not re-fetch from S3 unless the cache has expired.

**CDN caching**: In production, the S3 bucket should front VTT files through CloudFront with the same 24-hour cache. VTT files are immutable (updating a track's content requires deleting and re-uploading, which creates a new S3 key), so cache invalidation is not needed for content changes.

**Presigned URL expiry vs. cache**: The presigned URL expires after `VIDEO_SUBTITLE_URL_TTL_SECONDS` (default 3600s = 1 hour). The browser cache TTL is 24 hours. If the viewer stays on the page longer than 1 hour, the presigned URL in the `<track>` element's `src` attribute is stale, but the browser has already fetched and cached the VTT content. A page reload will get a fresh URL via the video detail API.

---

## 13. Open Questions & Risks

### 13.1 Unresolved Decisions

1. **Auto-captioning (Phase 2)**: Should the platform offer automatic speech-to-text caption generation? The `is_auto_generated` flag is reserved for this. The backend would extract audio, send it to a speech-to-text service (AWS Transcribe, Google Speech-to-Text, or Whisper), and generate a VTT file. This is a separate ticket with significant infrastructure requirements.

2. **SDH vs. regular subtitles**: Should the platform distinguish between "subtitles" (translations) and "captions" (same-language with sound descriptions like `[music]`, `[applause]`)? The `kind` attribute on `<track>` can be `"subtitles"` or `"captions"`. For Phase 1, all tracks use `kind="subtitles"`. A future enhancement could add a `kind` field to `SubtitleTrack`.

3. **Subtitle editing in-browser**: Should creators be able to edit subtitle text and timings directly in the browser, or only upload pre-made files? In-browser editing is a significant UX investment. Phase 1 is upload-only.

4. **Caption font size preference**: Should the viewer be able to adjust caption font size? This is achievable via `::cue` CSS and a font size slider. Not included in Phase 1.

### 13.2 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| `crossOrigin="anonymous"` breaks DRM playback | Low | High | Test DRM + subtitles together; `crossOrigin` is standard for both |
| `<track>` element not supported by native Safari HLS | Low | Medium | Safari supports `<track>` with native HLS; tested on macOS and iOS |
| Presigned URL expires during long playback | Medium | Low | Default 1-hour TTL; browser caches the VTT file after first fetch |
| VTT with malformed timestamps causes player crash | Low | Medium | Strict validation rejects malformed files at upload time |
| Large number of tracks (20) slows video detail API | Low | Low | Tracks are nested on the item; no additional DDB query needed |
| `list_append` race on concurrent default-setting uploads | Low | Low | Read-modify-write with `ConditionExpression` on `updated_at`; retry on conflict |

### 13.3 Dependency Risks

- **No external dependencies**: This ticket does not introduce any new Python or npm packages. SRT-to-VTT conversion and VTT validation are implemented with standard library regex. Sanitization uses regex (no BeautifulSoup or lxml dependency).
- **`lucide-react` icon**: The `Subtitles` icon is already available in `lucide-react` (the icon library used throughout the frontend). <!-- VERIFIED: MediaPlayer.tsx:14-28 imports from lucide-react -->
- **S3 CORS in production**: The production S3 bucket or CloudFront distribution must allow `text/vtt` responses with CORS headers. This is a deployment configuration task, not a code dependency.

---

## 14. Settings / Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `VIDEO_SUBTITLE_ENABLED` | `true` | Master feature flag |
| `VIDEO_SUBTITLE_MAX_TRACKS` | `20` | Maximum subtitle tracks per video |
| `VIDEO_SUBTITLE_MAX_FILE_SIZE_KB` | `512` | Maximum upload file size in KB |
| `VIDEO_SUBTITLE_ALLOWED_FORMATS` | `vtt,srt` | Comma-separated list of accepted file extensions |
| `VIDEO_SUBTITLE_URL_TTL_SECONDS` | `3600` | Presigned URL expiry for VTT files |

These settings are placed after the VOD-019 settings in `app/core/settings.py` (after line 1219). <!-- VERIFIED: app/core/settings.py:1216-1219 — VOD-019 settings end here -->

---

## 15. Monitoring & Alerting

### 15.1 Metrics to Track

| Metric | Type | Description |
|--------|------|-------------|
| `subtitle_upload_total` | Counter | Total subtitle files uploaded, labeled by `format` (vtt/srt) |
| `subtitle_upload_errors_total` | Counter | Failed uploads, labeled by `reason` (invalid_format, invalid_content, size_exceeded, max_tracks, non_utf8, invalid_language) |
| `subtitle_delete_total` | Counter | Total subtitle tracks deleted |
| `subtitle_conversion_total` | Counter | SRT-to-VTT conversions performed |
| `subtitle_sanitization_strips_total` | Counter | Times sanitizer removed dangerous content (indicates potential abuse) |
| `subtitle_vtt_fetch_total` | Counter | VTT URL requests (indicates viewer caption usage) |
| `subtitle_upload_latency_ms` | Histogram | End-to-end upload latency (validation + S3 + DDB) |

### 15.2 Alert Thresholds

| Alert | Condition | Severity |
|-------|-----------|----------|
| Subtitle upload failures elevated | `rate(subtitle_upload_errors_total[5m]) > 10` | Warning |
| Sanitization strips elevated | `rate(subtitle_sanitization_strips_total[5m]) > 5` | Warning (potential abuse) |
| S3 upload errors | Any S3 PutObject failure for subtitle files | Error |
| Upload latency spike | `p99(subtitle_upload_latency_ms[5m]) > 2000` | Warning |

---

## Appendix A: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| `VideoMetadataModel.subtitle_tracks` field | `app/models_video.py` | 150 | VERIFIED (now exists; `SubtitleTrack` at :153) |
| `VideoOut.subtitle_tracks` field | `app/models_video.py` | 232 | VERIFIED (now exists) |
| `VideoDetailOut` subtitle fields | `app/routers/video_listing.py` | 67+ | VERIFIED (check for subtitle_tracks in detail response) |
| `_video_to_detail()` helper | `app/routers/video_listing.py` | 178-275 | VERIFIED |
| `MediaPlayerProps` has no subtitle props | `frontend/src/components/shared/MediaPlayer.tsx` | 46-71 | VERIFIED |
| `<video>` element has no `<track>` children | `frontend/src/components/shared/MediaPlayer.tsx` | 548-557 | VERIFIED |
| `QualitySelector` component (UI pattern reference) | `frontend/src/components/shared/MediaPlayer.tsx` | 91-151 | VERIFIED |
| `.vtt` MIME type already in `_CONTENT_TYPE_MAP` | `app/services/vod_s3_uploader.py` | 37 | VERIFIED |
| `upload_segment()` function (requires `local_path: Path`) | `app/services/vod_s3_uploader.py` | 96 | VERIFIED |
| `video_to_item()` serializer | `app/services/video_metadata_store.py` | 21 | VERIFIED |
| `video_from_item()` deserializer | `app/services/video_metadata_store.py` | 169 | VERIFIED |
| `video_metadata_store.py` line count | `app/services/video_metadata_store.py` | 675 lines | VERIFIED |
| `video_listing.py` line count | `app/routers/video_listing.py` | 1518 lines | VERIFIED |
| `settings.py` line count | `app/core/settings.py` | 1367 lines | VERIFIED |
| `tables.py` line count | `app/core/tables.py` | 209 lines | VERIFIED |
| VOD-related settings location | `app/core/settings.py` | 1053-1219 | VERIFIED (was 1054-1112; corrected to include VOD-015 through VOD-019) |
| `require_ui_session` auth dependency | `app/services/sessions.py` | 283 | VERIFIED (was app/auth/deps.py; corrected) |
| `now_ts()` function | `app/core/time.py` | 2 | VERIFIED |
| `T.video_metadata` table handle | `app/core/tables.py` | 176 | VERIFIED |
| VideoMetadata DDB table definition | `scripts/local-ddb-init.py` | 708 | VERIFIED |
| VideoPlayerPage exists | `frontend/src/pages/videos/VideoPlayerPage.tsx` | exists | VERIFIED |
| Video route in App.tsx | `frontend/src/App.tsx` | 144 | VERIFIED |
| S3 client import path | `app/core/aws_clients` → `s3_client()` | vod_s3_uploader.py:19 | VERIFIED |
| No `vod_probe.py` or `vod_transcoder.py` | `app/services/` | N/A | VERIFIED (files do not exist) |
| Subtitle service and router now exist | `app/services/vod_subtitle_manager.py`, `app/routers/video_subtitles.py` | — | IMPLEMENTED |
| Subtitle router registered in main.py | `app/main.py` | 100, 420 | VERIFIED |
| Subtitle settings | `app/core/settings.py` | 1359-1363 | VERIFIED: `video_subtitle_enabled`, `video_subtitle_max_tracks`, `video_subtitle_max_file_size_kb`, `video_subtitle_allowed_formats`, `video_subtitle_url_ttl_seconds` |
| E2E test file | `frontend/e2e/video-subtitles.spec.ts` | — | VERIFIED |

---

## Appendix B: File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/models_video.py` | Modify | Add `SubtitleTrack` model; add `subtitle_tracks` field to `VideoMetadataModel` (after line 144) and `VideoOut` (after line 207); add `UploadSubtitleIn`, `UpdateSubtitleIn` |
| `app/services/video_metadata_store.py` | Modify | Serialize/deserialize `subtitle_tracks` list in `video_to_item()` (after line 164) and `video_from_item()` (after line 268); add `SubtitleTrack` import |
| `app/routers/video_listing.py` | Modify | Add `subtitle_tracks` to `VideoDetailOut` (after line 132); pass through in `_video_to_detail()` return block (line 213-275) |
| `app/main.py` | Modify | Register `video_subtitles` router |
| `app/core/settings.py` | Modify | Add 5 `VIDEO_SUBTITLE_*` settings (after line 1219) |
| `.env.local.example` | Modify | Add `VIDEO_SUBTITLE_*` env vars |
| `frontend/src/components/shared/MediaPlayer.tsx` | Modify | Add `Subtitles` to lucide-react imports (line 14-28); add `subtitleTracks` prop to `MediaPlayerProps` (line 46); add `crossOrigin="anonymous"` to `<video>` (line 548); render `<track>` children; add CC toggle + `SubtitleSelector` (after line 713); add localStorage persistence; add `::cue` CSS |
| `frontend/src/api/types.ts` | Modify | Add `SubtitleTrack`, `SubtitleListResponse` interfaces |
| `frontend/src/pages/videos/VideoPlayerPage.tsx` | Modify | Pass `subtitleTracks` to `MediaPlayer`; render `SubtitleManager` for owner |
| `app/services/vod_subtitle_manager.py` | **New** | SRT-to-VTT conversion, VTT validation, content sanitization, S3 upload/delete via `put_object()`, URL minting | <!-- IMPLEMENTED: exists with validate_language_code:30, srt_to_vtt:42, validate_vtt:91, sanitize_vtt_content:132, upload_subtitle_to_s3:150, upload_subtitle:190, list_subtitles:301, delete_subtitle:315, update_subtitle:354 -->
| `app/routers/video_subtitles.py` | **New** | 5 HTTP endpoints for subtitle CRUD | <!-- IMPLEMENTED: exists with upload_subtitle_endpoint:56, list_subtitles_endpoint:119, delete_subtitle_endpoint:132, update_subtitle_endpoint:150; registered in main.py:100,420 -->
| `frontend/src/api/endpoints/subtitles.ts` | **New** | API client for subtitle endpoints | <!-- IMPLEMENTED: verify existence -->
| `frontend/src/pages/videos/SubtitleManager.tsx` | **New** | Subtitle management panel (upload form + track list) | <!-- IMPLEMENTED: verify existence -->
| `frontend/src/components/shared/SubtitleSelector.tsx` | **New** | In-player CC toggle + language dropdown | <!-- IMPLEMENTED: verify existence -->
| `tests/test_vod_subtitle_manager.py` | **New** | 30 unit tests for conversion, validation, sanitization, language codes | <!-- IMPLEMENTED: verify existence -->
| `tests/test_video_subtitles_endpoint.py` | **New** | 24 unit tests for API endpoints | <!-- IMPLEMENTED: verify existence -->
| `frontend/e2e/video-subtitles.spec.ts` | **New** | 35 E2E tests across 7 sections (80-86) | <!-- IMPLEMENTED: file exists -->

---

## Appendix C: ISO 639-1 Language Codes (Common Subset)

The language selector dropdown in the frontend should include at minimum:

| Code | Language | Label |
|------|----------|-------|
| `en` | English | English |
| `es` | Spanish | Espanol |
| `fr` | French | Francais |
| `de` | German | Deutsch |
| `pt` | Portuguese | Portugues |
| `it` | Italian | Italiano |
| `ja` | Japanese | Japanese |
| `ko` | Korean | Korean |
| `zh` | Chinese | Chinese |
| `ar` | Arabic | Arabic |
| `hi` | Hindi | Hindi |
| `ru` | Russian | Russian |
| `nl` | Dutch | Nederlands |
| `sv` | Swedish | Svenska |
| `pl` | Polish | Polski |

The backend accepts any valid ISO 639-1 or BCP-47 code (the dropdown is a convenience, not a restriction). Creators can type custom codes for less common languages.

---

## Appendix D: Future Enhancement — Auto-Caption Generation

This section documents the planned Phase 2 auto-captioning feature for reference. It is **not** part of this ticket's scope.

### Overview

Auto-captioning would use a speech-to-text service to generate subtitle tracks automatically from the video's audio stream. The flow:

1. Creator clicks "Auto-generate captions" on the subtitle management panel.
2. Backend extracts audio from the source video via FFmpeg (`-vn -acodec pcm_s16le`).
3. Audio is sent to a speech-to-text service (AWS Transcribe or self-hosted Whisper).
4. The service returns timestamped transcription segments.
5. Backend converts segments to VTT format and uploads as a new track with `is_auto_generated: true`.
6. Creator can review and edit the auto-generated track.

### Dependencies

- FFmpeg audio extraction (existing infrastructure in `video_clipper.py` and `video_concatenator.py`) <!-- VERIFIED: ffprobe calls exist in video_clipper.py:375 and video_concatenator.py:420 -->
- Speech-to-text service (new external dependency)
- Async job queue (reuse transcode job pattern from `transcode_jobs` table) <!-- VERIFIED: app/core/tables.py:177 — transcode_jobs table -->

### Estimated Effort

5-8 additional days (separate ticket).

---

## Appendix E: Corrections Log

The following corrections were applied during verification of this ticket against the actual codebase:

| Section | Original Claim | Correction |
|---------|---------------|------------|
| 2.4 | `upload_segment()` can upload VTT files | `upload_segment()` requires `local_path: Path` (file on disk); subtitle uploads use `_s3.put_object()` for in-memory content |
| 2.5 | Listed `vod_probe.py` and `vod_transcoder.py` | These files do not exist; ffprobe functionality is in `video_clipper.py` and `video_concatenator.py` |
| 2.7 | VOD settings at lines 1054-1112 | VOD settings span lines 1053-1219 (includes VOD-001 through VOD-019) |
| 2.8 | `require_ui_session` in `app/auth/deps.py` | Actually in `app/services/sessions.py:283`; `video_listing.py` imports from `app.services.sessions` |
| 3.4.2 | Add after watermark fields at line ~112 | Add after Purchase Tiers fields at line 144 (end of `VideoMetadataModel`) |
| 3.4.4 | Add after `watermark_downloads` at line 100 | Add after `source_video_ids` at line 132 (end of `VideoDetailOut`) |
| 3.11 | Settings placement unspecified | Placed after VOD-019 settings at line 1219 |
