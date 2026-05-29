# VOD-007: Build Frontend Video Upload Page

**Ticket**: VOD-007
**Status**: Implemented
**Author**: Engineering
**Date**: 2026-05-24

---

## 1. Overview & Motivation

### Problem Statement

Users need a dedicated page at `/videos` where they can upload video files, track upload progress in real time, fill in metadata (title, description, visibility), and cancel in-progress uploads. The platform currently supports file uploads via the File Manager (`/files`) using presigned S3 URLs, but video uploads have unique requirements: much larger file sizes (up to 10 GB), mandatory progress tracking via XHR progress events (the Fetch API does not expose upload progress), post-upload processing status polling, and a video-specific metadata form.

### User Stories

1. **As a content creator**, I want to drag a video file onto the page and see it begin uploading immediately with a progress bar, so I know how long the upload will take.
2. **As a content creator**, I want to fill in a title, description, and visibility setting for my video before or during upload, so my video is properly catalogued when processing completes.
3. **As a content creator**, I want to cancel an in-progress upload if I selected the wrong file, without needing to refresh the page.
4. **As a content creator**, I want to see my video library (previously uploaded videos) with thumbnails, durations, titles, and processing status badges, so I can manage my content.
5. **As a content creator**, I want to see a clear processing indicator after upload completes, so I understand the video is not yet playable.
6. **As a content creator**, I want to edit the title of an already-uploaded video or delete it from my library.
7. **As a content creator**, I want to copy the playback URL of a ready video to share it.

### Why a Dedicated Page

The existing File Manager upload flow (`FilesPage.tsx`) is designed for general-purpose file storage with encryption support, folder navigation, and ZIP extraction. Video uploads differ in several ways:

- **Size**: Videos can be 10 GB; the File Manager's `PRESIGN_THRESHOLD` is 5 MB and the presigned upload path uses a simple `fetch()` PUT without progress tracking.
- **Progress**: `XMLHttpRequest` is required for upload progress events (`xhr.upload.onprogress`). The Fetch API does not expose upload progress in any browser as of 2026.
- **Metadata**: Videos require title, description, and visibility fields that do not exist in the file manager schema.
- **Post-processing**: Videos transition through `uploaded` -> `processing` -> `ready` states. The UI must poll until processing completes.
- **Cancellation**: `XMLHttpRequest.abort()` provides clean cancellation. Fetch-based uploads cannot be cancelled without an `AbortController` workaround that lacks progress.

---

## 2. Current State Analysis

### 2.1 Existing Upload Patterns

#### File Manager Presigned Upload (`frontend/src/pages/files/FilesPage.tsx`, lines 808-821)

```typescript
if (uploadFileObj.size > PRESIGN_THRESHOLD) {
  const presign = await fsPresignUpload(targetPath, uploadFileObj.type || undefined);
  await fetch(presign.upload_url, {
    method: "PUT",
    headers: { "Content-Type": presign.content_type },
    body: uploadFileObj,
  });
  await completeUpload(presign.path, presign.key, presign.ticket_id, presign.content_type, ...);
}
```

**Limitations for video**: Uses `fetch()` which provides no upload progress events. No cancellation support. No metadata form. Designed for files < 100 MB in practice.

#### File Manager API Client (`frontend/src/api/endpoints/files.ts`, lines 235-265)

- `fsPresignUpload(path, contentType)` — POST to `/v1/fs/presign-upload`, returns `{ upload_url, bucket, key, ticket_id, path, content_type }`
- `completeUpload(path, key, ticketId, contentType, opts)` — POST to `/v1/fs/complete-upload`

These provide the pattern we will follow, adapted for the VOD endpoints defined in VOD-002.

#### UploadZone Component (`frontend/src/pages/files/UploadZone.tsx`)

A reusable drag-and-drop wrapper with:
- `onDragEnter` / `onDragLeave` / `onDragOver` / `onDrop` handlers
- `dragCountRef` to handle nested drag enter/leave events
- Visual overlay with dashed border and `Upload` icon when dragging

This component is tightly coupled to the file manager (calls `uploadFile()` directly). We will extract the drag-and-drop interaction pattern into a new `VideoUploadZone` that accepts video files and delegates to our upload state machine.

#### CreatePost Form (`frontend/src/pages/feed/CreatePost.tsx`)

Demonstrates the metadata form pattern:
- `useState` for form fields (body, images, lock settings)
- `useMutation` for the submit action
- Toast notifications for success/error
- Upload progress state (`uploading`, `uploadProgress`)

#### API Client (`frontend/src/api/client.ts`)

The `api` wrapper uses Fetch internally with automatic CSRF token injection, 401 retry, and error handling. For the S3 PUT step we bypass this wrapper (same as `FilesPage.tsx`) because the upload URL points to S3/mock-S3, not the backend API.

### 2.2 Available UI Components

| Component | Path | Usage |
|-----------|------|-------|
| `PageHeader` | `components/shared/PageHeader.tsx` | Page title + action buttons |
| `EmptyState` | `components/shared/EmptyState.tsx` | No-content placeholder with icon + CTA |
| `StatusBadge` | `components/shared/StatusBadge.tsx` | Colored status pills (success/warning/danger/info/neutral) |
| `ConfirmDialog` | `components/shared/ConfirmDialog.tsx` | Confirmation modal |
| `Card` / `CardContent` | `components/ui/card.tsx` | Content container |
| `Button` | `components/ui/button.tsx` | Primary action buttons |
| `Input` / `Textarea` | `components/ui/input.tsx`, `components/ui/textarea.tsx` | Form inputs |
| `Dialog` / `DialogContent` | `components/ui/dialog.tsx` | Modal dialogs |
| `Badge` | `components/ui/badge.tsx` | Inline labels |
| `Skeleton` | `components/ui/skeleton.tsx` | Loading placeholders |
| `Tabs` / `TabsList` / `TabsTrigger` | `components/ui/tabs.tsx` | Tabbed views |
| `Select` | `components/ui/select.tsx` | Dropdown select |
| `DropdownMenu` | `components/ui/dropdown-menu.tsx` | Action menus |
| `Tooltip` | `components/ui/tooltip.tsx` | Hover tooltips |

### 2.3 State Management Patterns

- **React Query** (`@tanstack/react-query`): All server state (video list, video detail) via `useQuery` with query keys like `["vod", "videos"]`.
- **Zustand**: App-level stores (auth, impersonation, offline). Upload state is page-local, not global — use `useState` / `useReducer`.
- **Toast notifications**: `sonner` library via `toast.success()`, `toast.error()`, `toast.loading()`.
- **Form state**: `useState` for simple forms (consistent with `CreatePost`). React Hook Form + Zod for complex validation (used in Settings/Security pages but overkill here).

### 2.4 Backend Endpoints (from VOD-002)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/vod/upload/presign` | POST | Get presigned S3 URL + ticket |
| `/v1/vod/upload/complete` | POST | Confirm upload, create video asset |
| `/v1/vod/videos` | GET | List user's videos (paginated) |
| `/v1/vod/videos/{video_id}` | GET | Get single video asset |
| `/v1/vod/videos/{video_id}` | DELETE | Delete video |
| `/v1/vod/videos/{video_id}` | PATCH | Update title/description (assumed) |

---

## 3. Technical Design

### 3.1 Component Hierarchy

```
VideosPage.tsx
├── PageHeader (title="Videos", actions=[UploadButton])
├── UploadPanel (conditional — shown when upload(s) active)
│   └── UploadItem[] (one per queued/active/completed upload)
│       ├── ProgressBar (percentage + bytes transferred)
│       ├── MetadataForm (title, description, visibility)
│       └── CancelButton / RetryButton
├── VideoLibraryGrid
│   ├── VideoCard[] (thumbnail, title, duration, status badge)
│   │   └── VideoCardMenu (edit title, delete, copy URL)
│   └── EmptyState (when no videos)
├── EditVideoDialog (edit title/description modal)
├── ConfirmDialog (delete confirmation)
└── VideoUploadZone (drag overlay — wraps entire page content)
```

### 3.2 Upload State Machine

Each upload goes through a state machine managed by `useReducer`:

```
            ┌──────────┐
            │  IDLE    │  (file selected, not started)
            └────┬─────┘
                 │ start
                 v
            ┌──────────┐
            │ PRESIGNING│  (requesting presigned URL)
            └────┬─────┘
                 │ presign success
                 v
            ┌──────────────┐
            │  UPLOADING   │  (XHR PUT in progress, progress %)
            └──┬───────┬───┘
               │       │ cancel / error
               │       v
               │  ┌──────────┐
               │  │ CANCELLED│
               │  │  / ERROR │
               │  └──────────┘
               │ upload complete (xhr.status=200)
               v
            ┌──────────────┐
            │  CONFIRMING  │  (POST /complete)
            └────┬─────────┘
                 │ confirm success
                 v
            ┌──────────────┐
            │  PROCESSING  │  (status="processing", polling)
            └────┬─────────┘
                 │ status="ready"
                 v
            ┌──────────────┐
            │    READY     │  (upload fully complete)
            └──────────────┘
```

**Reducer state shape**:

```typescript
interface UploadItem {
  id: string;                    // client-generated UUID
  file: File;
  status: "idle" | "presigning" | "uploading" | "confirming" | "processing" | "ready" | "cancelled" | "error";
  progress: number;              // 0-1 float
  bytesUploaded: number;
  totalBytes: number;
  presign: VideoPresignResponse | null;
  videoAsset: VideoAsset | null;
  error: string | null;
  xhrRef: XMLHttpRequest | null; // for cancellation
  // Metadata form fields
  title: string;
  description: string;
  visibility: "public" | "private" | "unlisted";
}

type UploadAction =
  | { type: "ADD_FILES"; files: File[] }
  | { type: "SET_STATUS"; id: string; status: UploadItem["status"] }
  | { type: "SET_PROGRESS"; id: string; progress: number; bytesUploaded: number }
  | { type: "SET_PRESIGN"; id: string; presign: VideoPresignResponse }
  | { type: "SET_ASSET"; id: string; asset: VideoAsset }
  | { type: "SET_ERROR"; id: string; error: string }
  | { type: "SET_XHR"; id: string; xhr: XMLHttpRequest }
  | { type: "CANCEL"; id: string }
  | { type: "UPDATE_METADATA"; id: string; field: string; value: string }
  | { type: "REMOVE"; id: string };
```

### 3.3 Upload Flow Implementation

```typescript
async function startUpload(item: UploadItem, dispatch: Dispatch<UploadAction>) {
  // Step 1: Presign
  dispatch({ type: "SET_STATUS", id: item.id, status: "presigning" });
  let presign: VideoPresignResponse;
  try {
    presign = await presignVideoUpload({
      filename: item.file.name,
      content_type: item.file.type || "video/mp4",
      file_size_bytes: item.file.size,
      title: item.title || undefined,
      description: item.description || undefined,
    });
    dispatch({ type: "SET_PRESIGN", id: item.id, presign });
  } catch (err) {
    dispatch({ type: "SET_ERROR", id: item.id, error: extractErrorMessage(err) });
    return;
  }

  // Step 2: Upload via XHR (for progress + cancellation)
  dispatch({ type: "SET_STATUS", id: item.id, status: "uploading" });
  try {
    await uploadToS3WithProgress(item, presign, dispatch);
  } catch (err) {
    if ((err as Error).message === "cancelled") {
      dispatch({ type: "SET_STATUS", id: item.id, status: "cancelled" });
    } else {
      dispatch({ type: "SET_ERROR", id: item.id, error: extractErrorMessage(err) });
    }
    return;
  }

  // Step 3: Confirm
  dispatch({ type: "SET_STATUS", id: item.id, status: "confirming" });
  try {
    const asset = await completeVideoUpload({
      ticket_id: presign.ticket_id,
      key: presign.key,
    });
    dispatch({ type: "SET_ASSET", id: item.id, asset });
    if (asset.status === "processing") {
      dispatch({ type: "SET_STATUS", id: item.id, status: "processing" });
    } else {
      dispatch({ type: "SET_STATUS", id: item.id, status: "ready" });
    }
  } catch (err) {
    dispatch({ type: "SET_ERROR", id: item.id, error: extractErrorMessage(err) });
  }
}
```

### 3.4 XHR Upload with Progress and Cancellation

```typescript
function uploadToS3WithProgress(
  item: UploadItem,
  presign: VideoPresignResponse,
  dispatch: Dispatch<UploadAction>,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    dispatch({ type: "SET_XHR", id: item.id, xhr });

    xhr.upload.addEventListener("progress", (e) => {
      if (e.lengthComputable) {
        dispatch({
          type: "SET_PROGRESS",
          id: item.id,
          progress: e.loaded / e.total,
          bytesUploaded: e.loaded,
        });
      }
    });

    xhr.addEventListener("load", () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        dispatch({ type: "SET_PROGRESS", id: item.id, progress: 1, bytesUploaded: item.file.size });
        resolve();
      } else {
        reject(new Error(`S3 upload failed: HTTP ${xhr.status}`));
      }
    });

    xhr.addEventListener("error", () => reject(new Error("Network error during upload")));
    xhr.addEventListener("abort", () => reject(new Error("cancelled")));

    xhr.open("PUT", presign.upload_url);
    xhr.setRequestHeader("Content-Type", presign.content_type);
    xhr.send(item.file);
  });
}
```

### 3.5 Cancellation

When the user clicks "Cancel":
1. Dispatch `{ type: "CANCEL", id }` which calls `xhrRef.abort()` on the stored XHR reference.
2. The XHR `abort` event fires, the promise rejects with `"cancelled"`, and the state transitions to `cancelled`.
3. The presigned URL ticket expires naturally (15-minute TTL) — no explicit cleanup needed.
4. If the upload already completed the PUT to S3 but has not confirmed, the orphaned S3 object is cleaned up by TTL lifecycle rules on the bucket (or the ticket expiration prevents confirmation).

### 3.6 Processing Status Polling

After upload confirmation returns `status: "processing"`:

```typescript
const { data: videoStatus } = useQuery({
  queryKey: ["vod", "video", videoId],
  queryFn: () => getVideo(videoId),
  refetchInterval: (query) =>
    query.state.data?.status === "processing" ? 5000 : false,
  enabled: !!videoId && status === "processing",
});

// When status changes from "processing" to "ready":
useEffect(() => {
  if (videoStatus?.status === "ready") {
    dispatch({ type: "SET_STATUS", id, status: "ready" });
    toast.success(`"${videoStatus.title}" is ready to play`);
    queryClient.invalidateQueries({ queryKey: ["vod", "videos"] });
  }
}, [videoStatus?.status]);
```

### 3.7 Form Validation

| Field | Constraints | Validation |
|-------|-------------|------------|
| File | Required; max 10 GB; must be `video/*` MIME type | Client-side via `accept="video/*"` on input + size check before presign |
| Title | Optional; max 500 chars | `maxLength` on input; trimmed on submit |
| Description | Optional; max 5000 chars | `maxLength` on textarea |
| Visibility | Required; enum `public` / `private` / `unlisted` | `<Select>` with default `"private"` |

**Client-side file validation** (before presign request):

```typescript
const ALLOWED_VIDEO_TYPES = new Set([
  "video/mp4", "video/quicktime", "video/x-msvideo", "video/x-matroska",
  "video/webm", "video/mpeg", "video/ogg", "video/x-flv", "video/3gpp",
]);
const MAX_VIDEO_SIZE = 10 * 1024 * 1024 * 1024; // 10 GB

function validateVideoFile(file: File): string | null {
  if (!file.type || !ALLOWED_VIDEO_TYPES.has(file.type)) {
    return `Unsupported video format: ${file.type || "unknown"}. Accepted: MP4, MOV, AVI, MKV, WebM.`;
  }
  if (file.size > MAX_VIDEO_SIZE) {
    return `File too large (${formatBytes(file.size)}). Maximum: 10 GB.`;
  }
  if (file.size === 0) {
    return "File is empty.";
  }
  return null;
}
```

### 3.8 Error Handling

| Error Scenario | User Feedback | Recovery |
|----------------|---------------|----------|
| Invalid file type | Toast error + item stays in "error" state | Remove item, pick a new file |
| File too large | Toast error at selection time (before presign) | Remove item |
| Presign API failure (quota/rate limit) | Toast with server message, "error" state | Retry button |
| Network failure during S3 PUT | "error" state with "Network error" message | Retry button (re-presigns + re-uploads) |
| S3 PUT returns non-200 | "error" state | Retry button |
| Confirm API failure | "error" state with server message | Retry button (re-calls complete) |
| Upload cancelled by user | "cancelled" state with "Upload cancelled" | Remove from list or retry |

### 3.9 Video Library Grid

The library section uses `useQuery` to fetch paginated videos:

```typescript
const { data, isLoading, fetchNextPage, hasNextPage } = useInfiniteQuery({
  queryKey: ["vod", "videos"],
  queryFn: ({ pageParam }) => listVideos(pageParam),
  getNextPageParam: (lastPage) => lastPage.next_cursor,
  initialPageParam: undefined as string | undefined,
});
```

Each `VideoCard` displays:
- Thumbnail image (or placeholder gradient with Film icon if not yet generated)
- Title (or filename if no title)
- Duration badge (e.g., "3:42")
- Status badge: "Processing" (warning), "Ready" (success), "Error" (danger)
- Relative upload time ("2 hours ago")

Card actions (via `DropdownMenu`):
- Edit title/description
- Copy playback URL (only when status = "ready")
- Delete (with `ConfirmDialog`)

### 3.10 Drag-and-Drop Zone

The entire page content is wrapped in a `VideoUploadZone` component that reuses the interaction pattern from `UploadZone.tsx`:

```typescript
function VideoUploadZone({ onFilesDropped, children }: Props) {
  const [dragOver, setDragOver] = useState(false);
  const dragCountRef = useRef(0);

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    dragCountRef.current = 0;
    setDragOver(false);
    const files = Array.from(e.dataTransfer.files).filter(
      (f) => f.type.startsWith("video/")
    );
    if (files.length > 0) onFilesDropped(files);
  };

  // ... dragEnter/dragLeave/dragOver handlers (same as UploadZone.tsx)

  return (
    <div className="relative" onDragEnter={...} onDragLeave={...} onDragOver={...} onDrop={...}>
      {children}
      {dragOver && (
        <div className="absolute inset-0 z-30 flex items-center justify-center
          rounded-lg border-2 border-dashed border-primary bg-primary/5 backdrop-blur-sm">
          <div className="flex flex-col items-center gap-2 text-primary">
            <Upload className="h-10 w-10" />
            <p className="text-sm font-medium">Drop video files here to upload</p>
          </div>
        </div>
      )}
    </div>
  );
}
```

Non-video files dropped are silently ignored. The drag overlay only appears when `dataTransfer.types` includes `"Files"`.

---

## 4. Implementation Plan

### 4.1 Files to Create

<!-- NOTE: Key files below ALREADY EXIST. The page directory is `frontend/src/pages/videos/` (not `pages/vod/`).
     Existing files: VideosPage.tsx, VideoPlayerPage.tsx, ForYouTab.tsx, SimilarVideos.tsx, CreatorSuggestions.tsx, WatermarkedDownloadButton.tsx.
     API endpoints file: frontend/src/api/endpoints/vod.ts (112 lines).
     E2E test file: frontend/e2e/video-upload.spec.ts (not vod-upload.spec.ts).
     Routes in App.tsx: /videos (line 164), /videos/:videoId (line 165).
-->

| File | Purpose |
|------|---------|
| `frontend/src/pages/videos/VideosPage.tsx` | Main page component (upload panel + library grid) |
| `frontend/src/pages/videos/VideoUploadZone.tsx` | Drag-and-drop wrapper |
| `frontend/src/pages/videos/UploadPanel.tsx` | Active uploads list with progress bars |
| `frontend/src/pages/videos/UploadItem.tsx` | Single upload row (progress, metadata, cancel) |
| `frontend/src/pages/videos/VideoLibraryGrid.tsx` | Grid of uploaded video cards |
| `frontend/src/pages/videos/VideoCard.tsx` | Individual video card (thumbnail, title, status) |
| `frontend/src/pages/videos/EditVideoDialog.tsx` | Modal for editing title/description |
| `frontend/src/pages/videos/uploadReducer.ts` | Upload state machine reducer + types |
| `frontend/src/pages/videos/uploadUtils.ts` | XHR upload helper, file validation, byte formatting |
| `frontend/src/api/endpoints/vod.ts` | API client wrappers for VOD endpoints |
| `frontend/e2e/vod-upload.spec.ts` | E2E Playwright tests |

### 4.2 Files to Modify

| File | Change |
|------|--------|
| `frontend/src/App.tsx` | Add lazy import for `VideosPage`; add route `<Route path="videos" element={<VideosPage />} />` inside the protected AppShell block |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Videos" nav item with `Film` icon in Media group |
| `frontend/src/components/layout/AppShell.tsx` | Add "Videos" to MobileSidebar `MORE_LINKS` |
| `frontend/src/api/types.ts` | Add `VideoAsset`, `VideoPresignResponse`, `VideoPresignRequest` interfaces |

### 4.3 Step-by-Step Implementation Order

**Phase 1: API Layer**

1. Create `frontend/src/api/endpoints/vod.ts` with typed wrappers for presign, complete, list, get, delete, and update endpoints.
2. Add TypeScript interfaces to `frontend/src/api/types.ts`.

**Phase 2: Upload State Machine**

3. Create `frontend/src/pages/videos/uploadReducer.ts` — the reducer, action types, initial state factory, and upload item interface.
4. Create `frontend/src/pages/videos/uploadUtils.ts` — XHR upload function, file validation, `formatBytes`, `formatDuration` helpers.

**Phase 3: UI Components**

5. Create `VideoUploadZone.tsx` — drag-and-drop wrapper component.
6. Create `UploadItem.tsx` — single upload row with progress bar, metadata inputs, and cancel/retry buttons.
7. Create `UploadPanel.tsx` — renders a list of `UploadItem` components.
8. Create `VideoCard.tsx` — video thumbnail card for the library grid.
9. Create `VideoLibraryGrid.tsx` — responsive grid of `VideoCard` components with infinite scroll.
10. Create `EditVideoDialog.tsx` — modal form for editing video metadata post-upload.

**Phase 4: Page Assembly**

11. Create `VideosPage.tsx` — composes all sub-components, manages upload state via `useReducer`, orchestrates the upload flow, contains the file input element.

**Phase 5: Routing & Navigation**

12. Modify `App.tsx` — add lazy import and route.
13. Modify `Sidebar.tsx` and `AppShell.tsx` — add "Videos" navigation entry.

**Phase 6: E2E Tests**

14. Create `frontend/e2e/vod-upload.spec.ts`.

### 4.4 Dependencies

| Dependency | Required By | Notes |
|------------|-------------|-------|
| VOD-002 (upload endpoints) | Phase 1 | API endpoints must exist for the frontend to call |
| VOD-006 (video list/get/delete endpoints) | Phase 3 (VideoLibraryGrid) | Library grid needs the list endpoint; can stub initially |
| `lucide-react` icons (`Film`, `Upload`, `X`, `Loader2`, `Copy`, `Trash2`, `Pencil`, `MoreVertical`, `Play`) | Phase 3 | Already installed in the project |
| `@tanstack/react-query` | Phase 3 | Already installed (`useQuery`, `useInfiniteQuery`, `useMutation`) |
| `sonner` | Phase 3 | Already installed (toast notifications) |

### 4.5 API Client Implementation (`frontend/src/api/endpoints/vod.ts`)

```typescript
import { api } from "../client";
import type { VideoAsset, VideoPresignRequest, VideoPresignResponse } from "../types";

export const presignVideoUpload = (body: VideoPresignRequest) =>
  api.post<VideoPresignResponse>("/v1/vod/upload/presign", body);

export const completeVideoUpload = (body: { ticket_id: string; key: string; content_type?: string }) =>
  api.post<{ ok: boolean; video_id: string; status: string } & VideoAsset>(
    "/v1/vod/upload/complete",
    body,
  );

export const listVideos = (cursor?: string) =>
  api.get<{ videos: VideoAsset[]; next_cursor?: string }>(
    "/v1/vod/videos",
    cursor ? { cursor } : undefined,
  );

export const getVideo = (videoId: string) =>
  api.get<VideoAsset>(`/v1/vod/videos/${videoId}`);

export const updateVideo = (videoId: string, body: { title?: string; description?: string }) =>
  api.patch<VideoAsset>(`/v1/vod/videos/${videoId}`, body);

export const deleteVideo = (videoId: string) =>
  api.del<{ ok: boolean }>(`/v1/vod/videos/${videoId}`);
```

### 4.6 TypeScript Interfaces (`frontend/src/api/types.ts` additions)

```typescript
export interface VideoPresignRequest {
  filename: string;
  content_type: string;
  file_size_bytes: number;
  title?: string;
  description?: string;
}

export interface VideoPresignResponse {
  upload_url: string;
  bucket: string;
  key: string;
  ticket_id: string;
  content_type: string;
  expires_at: string;
  max_size_bytes: number;
}

export interface VideoAsset {
  video_id: string;
  title: string;
  description?: string;
  filename: string;
  size_bytes: number;
  content_type: string;
  duration_seconds?: number;
  thumbnail_url?: string;
  status: "uploaded" | "processing" | "ready" | "error";
  created_at: string;
  updated_at?: string;
  playback_url?: string;
}
```

---

## 5. Testing Strategy

### 5.1 Unit Tests (Vitest)

**File**: `frontend/src/pages/videos/__tests__/uploadReducer.test.ts`

| Test Case | Description |
|-----------|-------------|
| `ADD_FILES creates upload items with idle status` | Reducer creates one UploadItem per file with correct initial state |
| `SET_PROGRESS updates progress and bytesUploaded` | Progress value between 0-1 correctly stored |
| `CANCEL transitions to cancelled and stores null xhr` | Verifies status transition |
| `SET_ERROR stores error message` | Error message preserved in state |
| `REMOVE deletes item from state` | Item no longer in array after removal |
| `UPDATE_METADATA updates title/description fields` | Field values correctly stored |

**File**: `frontend/src/pages/videos/__tests__/uploadUtils.test.ts`

| Test Case | Description |
|-----------|-------------|
| `validateVideoFile accepts video/mp4` | Returns null for valid MP4 file |
| `validateVideoFile rejects application/pdf` | Returns error string for non-video |
| `validateVideoFile rejects file over 10GB` | Returns size error |
| `validateVideoFile rejects 0-byte file` | Returns empty file error |
| `formatBytes formats GB/MB/KB correctly` | e.g., 1073741824 -> "1.0 GB" |
| `formatDuration formats seconds to mm:ss` | e.g., 222 -> "3:42" |

### 5.2 E2E Tests with Playwright

**File**: `frontend/e2e/vod-upload.spec.ts`

Tests follow the established patterns: `injectAuth` for session injection, `page.request` for API calls with CSRF header, and session data from `e2e_session_setup.py`.

```typescript
import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";

// Session bootstrap (same pattern as files.spec.ts)
interface SessionData { /* ... */ }
let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> { /* ... */ }
async function injectAuth(page: Page, userId: string) { /* ... */ }

// Helper: POST to VOD API with CSRF
async function vodPost(page: Page, path: string, body: object, userId = ALICE_ID) {
  const session = getSessions()[userId];
  return page.request.post(`${API}/v1/vod${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function vodGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/v1/vod${path}`, { params });
}
```

**Section 1: Upload API (presign + complete flow)**

| # | Test | Assertion |
|---|------|-----------|
| 1.1 | Presign returns upload URL for valid video | 200, `upload_url` truthy, `key` contains `vod/` |
| 1.2 | Presign rejects non-video content type | 422 (Pydantic pattern validation) |
| 1.3 | Presign rejects file over size limit | 422 (Pydantic `le` validation) |
| 1.4 | Full presign -> PUT -> complete flow | 200, asset has `video_id`, `status` in ["uploaded","processing"] |
| 1.5 | Complete rejects mismatched S3 key | 403 |
| 1.6 | Complete rejects nonexistent ticket | 403 or 404 |

**Section 2: Video Library API (CRUD)**

| # | Test | Assertion |
|---|------|-----------|
| 2.1 | List videos returns uploaded video | 200, array contains video from section 1 |
| 2.2 | Get single video by ID | 200, matches expected fields |
| 2.3 | Update video title | 200, title changed |
| 2.4 | Delete video | 200, subsequent GET returns 404 |

**Section 3: Upload Page UI**

| # | Test | Assertion |
|---|------|-----------|
| 3.1 | Page loads with "Videos" heading | `getByRole("heading", { name: "Videos" })` visible |
| 3.2 | Empty state shown when no videos | "No videos yet" text visible, "Upload" CTA visible |
| 3.3 | File input accepts video files | Click upload button, attach file, presign request sent |
| 3.4 | Upload progress bar appears during upload | Progress element/bar visible during PUT |
| 3.5 | Upload completes and video appears in grid | After complete, video card appears with title |
| 3.6 | Cancel button aborts in-progress upload | Click cancel, status shows "Cancelled" |

**Section 4: Drag-and-Drop UI**

| # | Test | Assertion |
|---|------|-----------|
| 4.1 | Drag overlay appears on file drag | Dispatch drag events, overlay with "Drop video" text visible |
| 4.2 | Drop triggers upload flow | Drop event with video file initiates presign |
| 4.3 | Non-video files are rejected on drop | Drop event with PDF, no presign request |

**Section 5: Video Card Actions**

| # | Test | Assertion |
|---|------|-----------|
| 5.1 | Edit title via card menu | Menu -> Edit -> change title -> save -> title updated |
| 5.2 | Delete video via card menu | Menu -> Delete -> confirm -> card removed |
| 5.3 | Copy URL via card menu | Menu -> Copy URL -> clipboard contains URL (only for ready videos) |

### 5.3 E2E Test Implementation Details

**Simulating file upload in Playwright** (for both button click and API-level tests):

```typescript
test("3.3 File input accepts video files", async ({ page }) => {
  await injectAuth(page, ALICE_ID);
  await page.goto(`${BASE}/videos`);

  // Create a small synthetic video file
  const videoBuffer = Buffer.alloc(256, 0x00);

  // Intercept the presign request to verify it is called
  const presignPromise = page.waitForResponse(
    (r) => r.url().includes("/v1/vod/upload/presign") && r.status() === 200
  );

  // Trigger file input
  const fileChooserPromise = page.waitForEvent("filechooser");
  await page.getByRole("button", { name: /upload/i }).click();
  const fileChooser = await fileChooserPromise;
  await fileChooser.setFiles({
    name: "test-video.mp4",
    mimeType: "video/mp4",
    buffer: videoBuffer,
  });

  // Verify presign was called
  const presignResp = await presignPromise;
  expect(presignResp.status()).toBe(200);
});
```

**Simulating drag-and-drop in Playwright**:

```typescript
test("4.1 Drag overlay appears on file drag", async ({ page }) => {
  await injectAuth(page, ALICE_ID);
  await page.goto(`${BASE}/videos`);

  // Simulate dragenter event
  await page.locator("[data-testid='video-upload-zone']").dispatchEvent("dragenter", {
    dataTransfer: { types: ["Files"], files: [] },
  });

  // Verify overlay appears
  await expect(page.getByText("Drop video files here")).toBeVisible();
});
```

### 5.4 Edge Cases to Test

| Edge Case | Expected Behavior |
|-----------|-------------------|
| Upload 0-byte file | Client-side rejection before presign (toast error: "File is empty") |
| Upload > 10 GB file | Client-side rejection (toast error with size limit message) |
| Upload non-video file via file picker | Blocked by `accept="video/*"` attribute; if bypassed, client validation rejects |
| Upload while offline | Network error toast; item enters "error" state with retry button |
| Cancel during presign step | Request aborted; item enters "cancelled" state |
| Cancel during S3 PUT | XHR aborted; item enters "cancelled" state |
| Multiple simultaneous uploads | All uploads tracked independently in reducer; progress bars update independently |
| Browser tab close during upload | `beforeunload` event shows confirmation dialog warning about in-progress uploads |
| Presign URL expiry (15 min) before upload start | S3 PUT returns 403; item enters "error" state; retry re-presigns |
| Backend returns 429 (rate limit) | Error state with "Too many uploads. Please wait." message |
| Video stuck in "processing" forever | After 10 minutes of polling, show warning "Processing is taking longer than expected" |
| Retry after error | Re-runs full flow (presign + upload + confirm) |
| Title with special characters (emoji, unicode) | Preserved correctly through API round-trip |
| Very long filename (255 chars) | Truncated in UI display; full value sent to API |

### 5.5 Accessibility Considerations

- Progress bar uses `role="progressbar"` with `aria-valuenow`, `aria-valuemin=0`, `aria-valuemax=100`
- Upload button labeled with accessible text ("Upload video")
- Drag-and-drop zone has `aria-label="Video upload drop zone"`
- Status badges use `aria-label` for screen readers (e.g., "Status: Processing")
- Cancel button labeled "Cancel upload for {filename}"
- Keyboard-accessible: Tab to upload button, Enter to trigger file picker

### 5.6 Performance Considerations

- **Large file reads**: The `File` object is passed directly to `xhr.send()` — the browser streams it from disk without loading the entire file into memory.
- **Progress throttling**: XHR progress events can fire hundreds of times per second on fast connections. Throttle dispatch to at most once per 100ms using `requestAnimationFrame` or a timestamp guard.
- **Video library thumbnails**: Use `loading="lazy"` on `<img>` elements in the grid to avoid loading all thumbnails on page load.
- **Infinite scroll**: Use `IntersectionObserver` via React Query's `useInfiniteQuery` + a sentinel element at the bottom of the grid.

---

## Appendix: File Reference

| Path | Role |
|------|------|
| `frontend/src/pages/files/FilesPage.tsx:808-821` | Reference: presigned upload flow with Fetch |
| `frontend/src/pages/files/UploadZone.tsx` | Reference: drag-and-drop interaction pattern |
| `frontend/src/pages/feed/CreatePost.tsx` | Reference: form with file attachment + upload progress |
| `frontend/src/api/endpoints/files.ts:235-265` | Reference: presign + complete API wrappers |
| `frontend/src/api/client.ts` | API client with CSRF, auth, error handling |
| `frontend/src/components/shared/PageHeader.tsx` | Reusable page header |
| `frontend/src/components/shared/EmptyState.tsx` | Reusable empty state placeholder |
| `frontend/src/components/shared/StatusBadge.tsx` | Reusable status badge (success/warning/danger) |
| `frontend/src/components/shared/ConfirmDialog.tsx` | Reusable confirmation dialog |
| `frontend/src/App.tsx` | Route registration (add `/videos` route here) |
| `frontend/src/components/layout/Sidebar.tsx` | Navigation sidebar (add "Videos" item here) |
| `frontend/e2e/files.spec.ts` | Reference: E2E test patterns (injectAuth, CSRF, API helpers) |

## Codebase References

| File | Line(s) | What |
|------|---------|------|
| `frontend/src/pages/videos/VideosPage.tsx` | -- | **Already exists**: video management page |
| `frontend/src/pages/videos/VideoPlayerPage.tsx` | -- | **Already exists**: video player page |
| `frontend/src/pages/videos/ForYouTab.tsx` | -- | **Already exists**: discovery tab |
| `frontend/src/pages/videos/SimilarVideos.tsx` | -- | **Already exists**: similar videos component |
| `frontend/src/pages/videos/WatermarkedDownloadButton.tsx` | -- | **Already exists**: watermarked download UI |
| `frontend/src/api/endpoints/vod.ts` | 81-84 | **Already exists**: `presignVideoUpload`, `completeVideoUpload` |
| `frontend/src/App.tsx` | 51, 164 | `VideosPage` lazy import and route (`/videos`) |
| `frontend/src/App.tsx` | 55, 165 | `VideoPlayerPage` lazy import and route (`/videos/:videoId`) |
| `frontend/e2e/video-upload.spec.ts` | -- | **Already exists**: E2E upload tests |
| `docs/tickets/VOD-002-video-upload-endpoint.md` | Backend endpoint specification (API contract) |

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What's Needed | Status | Can Overlap? |
|--------|--------------|--------|--------------|
| VOD-002 | Backend presign + complete endpoints (`POST /ui/videos/upload/presign`, `POST /ui/videos/upload/complete`) | Implemented | No -- frontend upload requires working backend endpoints |
| VOD-006 | `GET /ui/videos` listing endpoint for video grid; `PATCH` and `DELETE` for card actions | Implemented | Soft dependency -- upload works without listing; grid shows empty until videos exist |

### Depended On By

| Ticket | What It Needs from VOD-007 |
|--------|---------------------------|
| VOD-008 | Navigation from video card to player page (`/videos/:videoId`) |
| VOD-009 | `/videos` route registered in `App.tsx` for sidebar navigation |
| VOD-011 | Upload UI E2E tests (file input, drag-and-drop, progress) |
| VOD-015 | Clip dialog launched from video card actions menu |
| VOD-016 | Concat dialog launched from video selection UI |
| VOD-017 | Gallery publish action in video card actions menu |

### Merge Strategy

**Sequential after VOD-002 + VOD-006** -- The upload page depends on both the upload API and the listing API. Can be merged as soon as both backend endpoints exist. No feature flag needed; the `/videos` route is additive.

### Merge Checklist

- [ ] `presignVideoUpload` and `completeVideoUpload` API wrappers in `frontend/src/api/endpoints/vod.ts`
- [ ] `VideosPage` lazy-loaded in `App.tsx` at `/videos`
- [ ] File input accepts `video/*` MIME types
- [ ] Client-side validation rejects non-video files and files > 10 GB
- [ ] XHR progress events throttled (max 1 dispatch per 100ms)
- [ ] `beforeunload` handler warns about in-progress uploads
- [ ] Drag-and-drop zone has `aria-label` for accessibility
- [ ] `just e2e` passes (vod-upload.spec.ts and video-upload.spec.ts)
