# PLATFORM-015: Universal Drag-and-Drop Support — File Uploads, Reordering, and Visual Drop Zones

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-28  
**Priority**: Medium  
**Estimated effort**: 10-14 days

---

## 1. Overview & Motivation

### The Gap

The platform has partial drag-and-drop support in two areas, but lacks a universal, consistent drag-and-drop experience across the application:

1. **File Manager UploadZone**: The `UploadZone` component (`frontend/src/pages/files/UploadZone.tsx`, line 17) <!-- CORRECTED: was "line 13"; UploadZone function is at line 17 --> wraps the file table and supports drag-and-drop file upload. It tracks `dragOver` state (line 18) <!-- CORRECTED: was "line 14"; dragOver state at line 18 --> using a `dragCountRef` (line 19) <!-- CORRECTED: was "line 15"; dragCountRef at line 19 --> to handle nested drag enter/leave events. When files are dropped, it calls `handleFiles` which uploads each file (line 21) <!-- CORRECTED: was "line 17"; handleFiles function at line 21, uploadFile call at line 51 -->. The visual overlay (line 137) <!-- CORRECTED: was "line 71"; dragOver overlay at line 137 --> shows a dashed border with "Drop files here to upload" text.

2. **Image Editor Canvas**: The `ImageEditorDialog` (`frontend/src/pages/files/ImageEditorDialog.tsx`, line 23) <!-- VERIFIED: ImageEditorDialog.tsx:23; dragStart state is at line 29 --> uses `dragStart` state for crop selection drawing on a canvas element, but this is canvas-level drag tracking, not a file drop target.

3. **ComposeBar File Input**: The `ComposeBar` (`frontend/src/pages/messages/ComposeBar.tsx`) uses a hidden `<input type="file">` with an `onChange` handler (`handleFileChange`, line 632) <!-- VERIFIED: ComposeBar.tsx:632 --> that processes selected files. There is **no drag-and-drop** support on the compose bar or the conversation view. Users must click the paperclip button to attach files.

4. **Broadcast Product Shelf Reorder**: The backend supports reordering broadcast product shelf items via `PATCH /sessions/{session_id}/products/reorder` (`app/routers/broadcast.py`, line 1945) <!-- CORRECTED: was "line 1931"; reorder route at line 1945 --> which accepts a `BroadcastShelfReorderIn` body with `item_order: List[str]` (line 1845) <!-- CORRECTED: was "line 1833"; BroadcastShelfReorderIn at line 1845 -->. The service function `reorder_shelf` (`app/services/broadcast_product_shelf.py`, line 188) <!-- VERIFIED: broadcast_product_shelf.py:188 --> updates `display_order` for each item. The frontend has NO drag-and-drop reordering UI --- reordering requires manual API calls.

5. **No drag-and-drop in feed/posts**: Users cannot drag images from their desktop onto the post composer to attach them.

6. **No kanban drag-and-drop for tickets**: Tickets have status fields (open, in_progress, waiting_on_user, done) <!-- CORRECTED: was "open, pending, resolved, closed", actually _TICKET_STATUSES = ("open", "in_progress", "waiting_on_user", "done") at tickets.py:15 --> but no kanban board view with drag-and-drop status transitions.

7. **No file/folder drag-and-drop reordering**: The file manager shows files in a table or grid but users cannot reorder or drag files between folders.

### Why This Is Needed

1. **Natural interaction**: Drag-and-drop is the most intuitive way to upload files and reorder items. Users expect to drag a photo from their desktop onto a chat window to send it.
2. **Efficiency**: Drag-and-drop reordering is 3-5x faster than manual position inputs for lists of 5+ items.
3. **Feature parity**: Every major messaging platform (Slack, Discord, WhatsApp Web) supports drag-and-drop file upload in conversations.
4. **Creator workflow**: Broadcasters need to quickly reorder their product shelf during a live stream. Drag-and-drop is the only practical way to do this in real-time.

### Architecture After This Change

```
Drag-and-Drop Architecture
============================

1. FILE UPLOAD (drop files from OS)
   +--------------------------------------------------+
   | Global Drop Zone (AppShell level)                 |
   |   - Detects file drag from OS (dataTransfer)      |
   |   - Shows full-screen overlay with context        |
   |   - Routes to current page's handler:             |
   |     /messages -> attach to ComposeBar             |
   |     /files -> upload to current directory         |
   |     /feed -> attach to CreatePost                 |
   |     /broadcast -> attach as overlay image         |
   +--------------------------------------------------+

2. ITEM REORDERING (drag items within the UI)
   +--------------------------------------------------+
   | @dnd-kit library integration                      |
   |   - DndContext at page level                      |
   |   - SortableContext for list reordering           |
   |   - useSortable for each draggable item           |
   |   - DragOverlay for drag preview                  |
   |                                                   |
   | Surfaces:                                         |
   |   - Broadcast product shelf (reorder items)       |
   |   - File manager (move files between folders)     |
   |   - Ticket kanban board (change status)           |
   |   - Playlist items (reorder tracks)               |
   +--------------------------------------------------+

3. VISUAL FEEDBACK
   +--------------------------------------------------+
   | Drop Zone Indicators                              |
   |   - Border: 2px dashed primary color              |
   |   - Background: primary/5 with backdrop blur      |
   |   - Icon: Upload / Move / Plus depending on type  |
   |   - Label: context-aware text                     |
   |   - Invalid drop: red border + "Cannot drop here" |
   +--------------------------------------------------+
```

### Interaction Flow: File Drop in Messages

```
User drags file from OS desktop
    |
    v
Browser fires dragenter on <html>
    |
    v
AppDropZone component
    |--- Check e.dataTransfer.types includes "Files"
    |       |--- NO: ignore (text drag, tab drag, etc.)
    |       |--- YES: continue
    |
    |--- Increment dragCountRef (nested element handling)
    |--- Set isDraggingFile = true
    |--- Determine context from location.pathname
    |       |--- /messages/* -> "message" context
    |
    v
DropOverlay renders with "Drop to attach to message"
    |
    v
User drops file onto overlay
    |
    v
AppDropZone handleDrop
    |--- Reset dragCountRef, isDraggingFile = false
    |--- Extract files from e.dataTransfer.files
    |--- Validate file count (<= 20), file size (<= 100MB)
    |
    v
Route to ConversationView's drop handler
    |--- Classify file by MIME type (image/video/audio/other)
    |--- If image: call onSendImage(file)
    |--- If video: call onSendVideoAttachment(file)
    |--- If other: call onSendFileShare(file)
    |
    v
ComposeBar shows file preview
    |--- pendingFile state set
    |--- User clicks Send
    |
    v
API call: POST /messaging/conversations/{id}/image-messages (multipart)
```

### Interaction Flow: Kanban Drag

```
User clicks and drags ticket card in "Open" column
    |
    v
@dnd-kit DndContext onDragStart
    |--- activeId = ticket.id
    |--- DragOverlay renders mini ticket card
    |
    v
User drags over "In Progress" column header
    |
    v
@dnd-kit collision detection (closestCenter)
    |--- overId = "column-in_progress"
    |--- Column highlights with droppable indicator
    |
    v
User releases mouse over "In Progress" column
    |
    v
DndContext onDragEnd
    |--- active.id = ticket.id
    |--- over.id = "column-in_progress"
    |--- Optimistic update: move card to In Progress column
    |--- API call: PATCH /ui/tickets/{ticket_id}/status { status: "in_progress" }
    |       |
    |       v
    |     Backend validates status transition
    |     Updates ticket record in DDB
    |       |
    |       v
    |     Response 200: { ok: true }
    |       |--- UI confirmed
    |       |
    |     Response 400: "Invalid status transition"
    |       |--- Revert optimistic update
    |       |--- Toast error: "Cannot move to In Progress"

<!-- CORRECTED: was "Pending" column references, updated to "In Progress" to match actual _TICKET_STATUSES which are: open, in_progress, waiting_on_user, done (no "pending" status exists) -->
```

---

## 2. Current State Analysis

### 2.1 UploadZone Component (`frontend/src/pages/files/UploadZone.tsx`)

The `UploadZone` (line 17) <!-- CORRECTED: was "line 13"; UploadZone function at line 17 --> is the only production-ready drop zone in the codebase. It uses native browser drag events (`onDragEnter`, `onDragLeave`, `onDragOver`, `onDrop`) and wraps child content:

```tsx
export function UploadZone({ currentPath, onUploadComplete, children }: UploadZoneProps) {
  const [dragOver, setDragOver] = React.useState(false);
  const dragCountRef = React.useRef(0);

  const handleFiles = async (files: FileList | File[]) => {
    const fileArray = Array.from(files);
    for (const file of fileArray) {
      const targetPath = currentPath.endsWith("/")
        ? currentPath + file.name
        : currentPath + "/" + file.name;
      const toastId = toast.loading(`Uploading ${file.name}...`);
      try {
        await uploadFile(file, targetPath);
        toast.success(`Uploaded ${file.name}`, { id: toastId });
      } catch {
        toast.error(`Failed to upload ${file.name}`, { id: toastId });
      }
    }
    onUploadComplete();
  };
```

Key implementation details:
- **dragCountRef** (line 19) <!-- CORRECTED: was "line 15"; dragCountRef at line 19 -->: Counter to handle nested drag enter/leave events from child elements. Incremented on `dragEnter`, decremented on `dragLeave`. The overlay only shows when the count is > 0. This is a standard workaround for the browser's bubbling drag events.
- **handleDrop** (line 104) <!-- CORRECTED: was "line 51"; handleDrop at line 104 -->: Resets `dragCountRef` to 0 and processes `e.dataTransfer.files`.
- **Visual overlay** (line 137) <!-- CORRECTED: was "line 71"; drag overlay at line 137 -->: Shows when `dragOver` is true --- a dashed border with backdrop blur and an `Upload` icon from lucide-react.
- **Sequential upload**: Files are uploaded one at a time in a `for` loop. No parallelism. For 10 files, each taking 500ms, total upload time is 5 seconds. Parallel upload would reduce this to ~2 seconds.

### 2.2 ComposeBar File Handling (`frontend/src/pages/messages/ComposeBar.tsx`)

The `ComposeBar` uses a hidden `<input type="file">` element for file selection:

```tsx
const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
  const file = e.target.files?.[0];
  e.target.value = "";
  if (!file) return;
  if (pendingFile) URL.revokeObjectURL(pendingFile.previewUrl);
  let kind: "image" | "video" | "audio" | null = null;
  if ((file.type.startsWith("image/") || file.type === "application/pdf") && onSendImage) kind = "image";
  else if (file.type.startsWith("video/") && onSendVideoAttachment) kind = "video";
  else if (file.type.startsWith("audio/") && onSendAudioRecording) kind = "audio";
  if (!kind) return;
  const previewUrl = URL.createObjectURL(file);
  setPendingFile({ file, previewUrl, kind });
};
```

This handler (line 632) <!-- VERIFIED: ComposeBar.tsx:632 -->:
1. Takes only the first file (`files?.[0]`)
2. Resets the input value for re-selection
3. Classifies the file by MIME type (image/video/audio)
4. Creates an object URL for preview
5. Sets `pendingFile` state for display in the compose area

There is **no `onDragOver`/`onDrop` handler** on the ComposeBar or its parent `ConversationView`. Users cannot drop files into the chat.

The file type classification logic is reusable for drag-and-drop. The same MIME type checks should be applied to dropped files, and unsupported types should show a clear error.

### 2.3 Broadcast Product Shelf Reorder (`app/services/broadcast_product_shelf.py`)

The reorder function (line 188) <!-- VERIFIED: broadcast_product_shelf.py:188 -->:

```python
def reorder_shelf(session_id: str, item_order: List[str], *, is_live: bool = False) -> None:
    """Update display_order for all items based on the provided ordering."""
    for idx, item_id in enumerate(item_order):
        T.broadcast_product_shelf.update_item(
            Key={"session_id": session_id, "SK": f"ITEM#{item_id}"},
            UpdateExpression="SET display_order = :order",
            ExpressionAttributeValues={":order": idx},
        )
    if is_live:
        updated = list_shelf_products(session_id)
        broadcast_sse_publish(session_id, {"_type": "shelf:reorder", "items": updated})
```

The backend is ready for reorder operations:
- Accepts an ordered list of item IDs
- Updates `display_order` atomically per item
- Publishes SSE event if the session is live (real-time update for viewers)
- The route (`app/routers/broadcast.py`, line 1945) <!-- CORRECTED: was "line 1931"; reorder route at line 1945 --> checks that only the session creator can reorder

The `BroadcastShelfReorderIn` model (line 1845) <!-- CORRECTED: was "line 1831"; BroadcastShelfReorderIn at line 1845 --> validates the input:

```python
class BroadcastShelfReorderIn(BaseModel):
    item_order: List[str] = Field(..., min_length=1, max_length=50)
```

### 2.4 File Manager Page (`frontend/src/pages/files/FilesPage.tsx`)

The `FilesPage` (line 1186) <!-- CORRECTED: was "line 1171"; UploadZone JSX at line 1186 --> wraps its content in the `UploadZone`:

```tsx
<UploadZone currentPath={currentPath} onUploadComplete={() => refetchTree()}>
  ...
</UploadZone>
```

The file table uses a standard HTML table with sortable column headers. There is no drag-and-drop reordering or drag-to-move-between-folders capability. The file manager does not support dragging files from the browser to the OS (download via drag).

The file manager has a `move_node` service function that moves files between paths:

```python
# app/services/filemanager.py
def move_node(user_id: str, source_path: str, target_path: str) -> Dict[str, Any]:
    """Move a file or folder to a new location."""
    # ... validates paths, checks permissions, updates DDB records
```

The corresponding API endpoint is `POST /ui/filemanager/nodes/move`. This endpoint already exists and can be used for drag-to-folder moves without any backend changes.

### 2.5 Newsfeed CreatePost (`frontend/src/pages/feed/CreatePost.tsx`)

The post composer has a `FilePickerDialog` integration for selecting images from the file manager, but no drag-and-drop zone for uploading images directly from the desktop.

The `CreatePost` component accepts images via two paths:
1. `FilePickerDialog` -> select from file manager -> re-upload via `uploadPostImage`
2. Direct upload via an `<input type="file">` hidden input

Adding a drag-and-drop zone follows the same pattern as option 2 but triggered by drop events instead of input change events.

### 2.6 Ticket Status Model

<!-- CORRECTED: The ticket describes TicketStatus as a `class TicketStatus(str, Enum)` with values OPEN, PENDING, IN_PROGRESS, RESOLVED, CLOSED. This is WRONG. The actual implementation uses a plain tuple of strings, not an Enum class. The values and transitions are also different. Corrected below. -->

The ticket status field supports the following values (from `app/services/tickets.py`, line 15):

```python
_TICKET_STATUSES = ("open", "in_progress", "waiting_on_user", "done")
```
<!-- VERIFIED: tickets.py:15 -->

The status transition rules (from `app/services/tickets.py`, lines 16-21):

```python
_STATUS_TRANSITIONS: dict[str, tuple[str, ...]] = {
    "open": ("in_progress", "done"),
    "in_progress": ("waiting_on_user", "done", "open"),
    "waiting_on_user": ("in_progress", "done", "open"),
    "done": ("open",),
}
```
<!-- VERIFIED: tickets.py:16-21 -->

The kanban board should enforce these transition rules. Invalid drops (e.g., dragging from "done" to "in_progress") should be visually rejected and not trigger an API call.

---

## 3. Technical Design

### 3.1 Library Choice: @dnd-kit

Use `@dnd-kit/core` and `@dnd-kit/sortable` for all reordering interactions. Benefits:
- React-first design with hooks-based API
- Accessible by default (keyboard drag-and-drop, screen reader announcements)
- Supports touch devices
- Custom collision detection strategies
- Drag overlay for visual preview
- Does NOT interfere with native file drag-and-drop (which uses browser events)

Native browser drag events continue to be used for file upload drop zones. The two systems coexist: `@dnd-kit` handles in-UI reordering, browser `onDragEnter`/`onDrop` handles OS file drops.

**Package installation**:

```bash
cd frontend && npm install @dnd-kit/core @dnd-kit/sortable @dnd-kit/utilities
```

Estimated bundle size impact: ~15KB gzipped (core: 8KB, sortable: 5KB, utilities: 2KB).

### 3.2 Global File Drop Zone

Create an `AppDropZone` component that wraps the entire app at the `AppShell` level. It detects when the user drags files from the OS into the browser window:

```tsx
interface DropContext {
  type: "message" | "files" | "feed" | "broadcast" | "default";
  label: string;
  icon: React.ComponentType<{ className?: string }>;
}

function getDropContext(pathname: string): DropContext {
  if (pathname.startsWith("/messages")) {
    return { type: "message", label: "Drop to attach to message", icon: MessageSquare };
  }
  if (pathname.startsWith("/files")) {
    return { type: "files", label: "Drop to upload to current folder", icon: FolderOpen };
  }
  if (pathname.startsWith("/feed")) {
    return { type: "feed", label: "Drop to attach to post", icon: FileText };
  }
  if (pathname.startsWith("/broadcast")) {
    return { type: "broadcast", label: "Drop to add overlay", icon: Image };
  }
  return { type: "default", label: "Drop to upload to Files", icon: Upload };
}

function AppDropZone({ children }: { children: React.ReactNode }) {
  const [isDraggingFile, setIsDraggingFile] = useState(false);
  const location = useLocation();
  const dragCount = useRef(0);

  const dropContext = useMemo(() => getDropContext(location.pathname), [location.pathname]);

  const handleDragEnter = useCallback((e: DragEvent) => {
    // Only activate for file drags (not text or in-UI drags)
    if (!e.dataTransfer?.types.includes("Files")) return;
    e.preventDefault();
    dragCount.current++;
    if (dragCount.current === 1) setIsDraggingFile(true);
  }, []);

  const handleDragLeave = useCallback((e: DragEvent) => {
    if (!e.dataTransfer?.types.includes("Files")) return;
    e.preventDefault();
    dragCount.current = Math.max(0, dragCount.current - 1);
    if (dragCount.current === 0) setIsDraggingFile(false);
  }, []);

  const handleDragOver = useCallback((e: DragEvent) => {
    if (!e.dataTransfer?.types.includes("Files")) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = "copy";
  }, []);

  const handleDrop = useCallback((e: DragEvent) => {
    e.preventDefault();
    dragCount.current = 0;
    setIsDraggingFile(false);

    const files = Array.from(e.dataTransfer?.files ?? []);
    if (files.length === 0) return;

    // Validate file count
    if (files.length > 20) {
      toast.error("Maximum 20 files per drop");
      return;
    }

    // Validate file sizes
    const oversized = files.filter((f) => f.size > MAX_UPLOAD_SIZE);
    if (oversized.length > 0) {
      toast.error(`${oversized.length} file(s) exceed the ${MAX_UPLOAD_SIZE_MB}MB limit`);
      // Continue with valid files
    }
    const validFiles = files.filter((f) => f.size <= MAX_UPLOAD_SIZE);
    if (validFiles.length === 0) return;

    // Route to page-specific handler via custom event
    const event = new CustomEvent("app-file-drop", {
      detail: { files: validFiles, context: dropContext.type },
    });
    window.dispatchEvent(event);
  }, [dropContext]);

  useEffect(() => {
    const el = document.documentElement;
    el.addEventListener("dragenter", handleDragEnter);
    el.addEventListener("dragleave", handleDragLeave);
    el.addEventListener("dragover", handleDragOver);
    el.addEventListener("drop", handleDrop);
    return () => {
      el.removeEventListener("dragenter", handleDragEnter);
      el.removeEventListener("dragleave", handleDragLeave);
      el.removeEventListener("dragover", handleDragOver);
      el.removeEventListener("drop", handleDrop);
    };
  }, [handleDragEnter, handleDragLeave, handleDragOver, handleDrop]);

  return (
    <>
      {children}
      {isDraggingFile && <DropOverlay context={dropContext} />}
    </>
  );
}

const MAX_UPLOAD_SIZE = 100 * 1024 * 1024; // 100MB
const MAX_UPLOAD_SIZE_MB = 100;
```

The `DropOverlay` renders a full-screen semi-transparent overlay with context-aware messaging:

```tsx
function DropOverlay({ context }: { context: DropContext }) {
  const Icon = context.icon;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm">
      <div className="flex flex-col items-center gap-4 rounded-xl border-2 border-dashed border-primary bg-primary/5 p-12">
        <Icon className="h-16 w-16 text-primary" />
        <p className="text-lg font-semibold text-primary">{context.label}</p>
        <p className="text-sm text-muted-foreground">Release to drop</p>
      </div>
    </div>
  );
}
```

| Current Page | Drop Message | Drop Action |
|-------------|-------------|-------------|
| `/messages` | "Drop to attach to message" | Set `pendingFile` in ComposeBar |
| `/files` | "Drop to upload to {currentPath}" | Call `uploadFile` |
| `/feed` | "Drop to attach to post" | Set attachment in CreatePost |
| `/broadcast` | "Drop to add overlay" | Add overlay image |
| Other | "Drop to upload to Files" | Call `uploadFile` to root |

### 3.3 Page-Level Drop Handlers

Each page listens for the `app-file-drop` custom event and handles files appropriately:

```tsx
// In ConversationView.tsx
useEffect(() => {
  const handler = (e: CustomEvent<{ files: File[]; context: string }>) => {
    if (e.detail.context !== "message") return;
    const file = e.detail.files[0]; // Take first file for messages
    if (!file) return;

    // Classify file type (same logic as handleFileChange)
    let kind: "image" | "video" | "audio" | null = null;
    if ((file.type.startsWith("image/") || file.type === "application/pdf") && onSendImage) kind = "image";
    else if (file.type.startsWith("video/") && onSendVideoAttachment) kind = "video";
    else if (file.type.startsWith("audio/") && onSendAudioRecording) kind = "audio";

    if (kind) {
      const previewUrl = URL.createObjectURL(file);
      setPendingFile({ file, previewUrl, kind });
    } else {
      toast.error(`Unsupported file type: ${file.type || "unknown"}`);
    }
  };

  window.addEventListener("app-file-drop", handler as EventListener);
  return () => window.removeEventListener("app-file-drop", handler as EventListener);
}, [onSendImage, onSendVideoAttachment, onSendAudioRecording]);
```

```tsx
// In CreatePost.tsx
useEffect(() => {
  const handler = (e: CustomEvent<{ files: File[]; context: string }>) => {
    if (e.detail.context !== "feed") return;
    const file = e.detail.files[0];
    if (!file) return;

    if (file.type.startsWith("image/")) {
      const previewUrl = URL.createObjectURL(file);
      setPostImage({ file, previewUrl });
    } else {
      toast.error("Only images can be attached to posts");
    }
  };

  window.addEventListener("app-file-drop", handler as EventListener);
  return () => window.removeEventListener("app-file-drop", handler as EventListener);
}, []);
```

### 3.4 ComposeBar Drop Zone (Local)

In addition to the global AppDropZone, add a local drop zone on the ConversationView for more precise targeting:

```tsx
// In ConversationView.tsx
const [dragOverChat, setDragOverChat] = useState(false);
const chatDragCount = useRef(0);

const handleChatDragEnter = (e: React.DragEvent) => {
  if (!e.dataTransfer.types.includes("Files")) return;
  e.preventDefault();
  e.stopPropagation(); // Prevent AppDropZone from showing
  chatDragCount.current++;
  if (chatDragCount.current === 1) setDragOverChat(true);
};

const handleChatDragLeave = (e: React.DragEvent) => {
  e.preventDefault();
  chatDragCount.current = Math.max(0, chatDragCount.current - 1);
  if (chatDragCount.current === 0) setDragOverChat(false);
};

const handleChatDrop = (e: React.DragEvent) => {
  e.preventDefault();
  e.stopPropagation();
  chatDragCount.current = 0;
  setDragOverChat(false);

  const files = Array.from(e.dataTransfer.files);
  if (files.length === 0) return;

  const file = files[0];
  // ... same classification logic as handleFileChange
};

return (
  <div
    onDragEnter={handleChatDragEnter}
    onDragLeave={handleChatDragLeave}
    onDragOver={(e) => { e.preventDefault(); e.stopPropagation(); }}
    onDrop={handleChatDrop}
    className="relative flex flex-col h-full"
  >
    {/* Message list */}
    {/* ComposeBar */}

    {dragOverChat && (
      <div className="absolute inset-0 z-20 flex items-center justify-center bg-background/60 backdrop-blur-sm rounded-lg border-2 border-dashed border-primary">
        <div className="flex flex-col items-center gap-2 text-primary">
          <Upload className="h-10 w-10" />
          <p className="text-sm font-medium">Drop file to attach</p>
        </div>
      </div>
    )}
  </div>
);
```

### 3.5 Multi-File Drop Support

The current `UploadZone.handleFiles` uploads files sequentially. Enhance it to:

1. **Parallel upload**: Upload up to 3 files in parallel using `Promise.allSettled`.
2. **Progress tracking**: Show a consolidated upload progress indicator with per-file status.
3. **File count limit**: Cap at 20 files per drop to prevent accidental mass uploads.
4. **Size validation**: Reject files > `MAX_UPLOAD_SIZE` (configurable, default 100MB) before uploading.

```typescript
const MAX_CONCURRENT_UPLOADS = 3;
const MAX_FILES_PER_DROP = 20;
const MAX_UPLOAD_SIZE = 100 * 1024 * 1024; // 100MB

async function handleFilesParallel(
  files: File[],
  currentPath: string,
  onUploadComplete: () => void,
) {
  const fileArray = Array.from(files).slice(0, MAX_FILES_PER_DROP);

  // Validate sizes
  const oversized = fileArray.filter((f) => f.size > MAX_UPLOAD_SIZE);
  const valid = fileArray.filter((f) => f.size <= MAX_UPLOAD_SIZE);

  if (oversized.length > 0) {
    toast.error(`${oversized.length} file(s) exceed the 100MB limit and were skipped`);
  }
  if (valid.length === 0) return;

  // Show consolidated progress toast
  const progressToastId = toast.loading(`Uploading ${valid.length} file(s)...`);
  let completed = 0;
  let failed = 0;

  // Upload with concurrency limit
  const queue = [...valid];
  const inFlight: Promise<void>[] = [];

  const uploadOne = async (file: File) => {
    const targetPath = currentPath.endsWith("/")
      ? currentPath + file.name
      : currentPath + "/" + file.name;
    try {
      await uploadFile(file, targetPath);
      completed++;
    } catch {
      failed++;
    }
    toast.loading(
      `Uploading: ${completed + failed}/${valid.length} (${failed} failed)`,
      { id: progressToastId },
    );
  };

  while (queue.length > 0) {
    while (inFlight.length < MAX_CONCURRENT_UPLOADS && queue.length > 0) {
      const file = queue.shift()!;
      const p = uploadOne(file).then(() => {
        const idx = inFlight.indexOf(p);
        if (idx >= 0) inFlight.splice(idx, 1);
      });
      inFlight.push(p);
    }
    if (inFlight.length > 0) {
      await Promise.race(inFlight);
    }
  }

  // Wait for remaining
  await Promise.allSettled(inFlight);

  if (failed === 0) {
    toast.success(`Uploaded ${completed} file(s)`, { id: progressToastId });
  } else {
    toast.warning(`Uploaded ${completed}/${valid.length} (${failed} failed)`, { id: progressToastId });
  }

  onUploadComplete();
}
```

### 3.6 Broadcast Product Shelf Drag Reorder

Create a `SortableShelf` component using `@dnd-kit`:

```tsx
import { DndContext, closestCenter, DragEndEvent, DragStartEvent, DragOverlay } from "@dnd-kit/core";
import { SortableContext, verticalListSortingStrategy, useSortable, arrayMove } from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import { restrictToVerticalAxis, restrictToParentElement } from "@dnd-kit/modifiers";

interface SortableShelfProps {
  sessionId: string;
  items: ShelfItem[];
  isLive: boolean;
}

function SortableShelf({ sessionId, items, isLive }: SortableShelfProps) {
  const [orderedItems, setOrderedItems] = useState(items);
  const [activeItem, setActiveItem] = useState<ShelfItem | null>(null);
  const queryClient = useQueryClient();

  const reorderMut = useMutation({
    mutationFn: (newOrder: string[]) => reorderShelfProducts(sessionId, newOrder),
    onError: () => {
      // Revert optimistic update
      setOrderedItems(items);
      toast.error("Failed to reorder products");
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["broadcast", sessionId, "shelf"] });
    },
  });

  // Sync with parent items prop
  useEffect(() => {
    setOrderedItems(items);
  }, [items]);

  const handleDragStart = (event: DragStartEvent) => {
    const item = orderedItems.find((i) => i.item_id === event.active.id);
    setActiveItem(item ?? null);
  };

  const handleDragEnd = (event: DragEndEvent) => {
    setActiveItem(null);
    const { active, over } = event;
    if (!over || active.id === over.id) return;

    const oldIdx = orderedItems.findIndex((i) => i.item_id === active.id);
    const newIdx = orderedItems.findIndex((i) => i.item_id === over.id);

    const reordered = arrayMove(orderedItems, oldIdx, newIdx);
    setOrderedItems(reordered); // Optimistic update

    const newOrder = reordered.map((i) => i.item_id);
    reorderMut.mutate(newOrder);
  };

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 5 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }),
  );

  return (
    <DndContext
      sensors={sensors}
      collisionDetection={closestCenter}
      modifiers={[restrictToVerticalAxis, restrictToParentElement]}
      onDragStart={handleDragStart}
      onDragEnd={handleDragEnd}
    >
      <SortableContext
        items={orderedItems.map((i) => i.item_id)}
        strategy={verticalListSortingStrategy}
      >
        {orderedItems.map((item) => (
          <SortableShelfItem key={item.item_id} item={item} />
        ))}
      </SortableContext>

      <DragOverlay>
        {activeItem && (
          <div className="opacity-80 shadow-lg">
            <ShelfItemCard item={activeItem} />
          </div>
        )}
      </DragOverlay>
    </DndContext>
  );
}
```

Each `SortableShelfItem` uses the `useSortable` hook:

```tsx
function SortableShelfItem({ item }: { item: ShelfItem }) {
  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({ id: item.item_id });

  const style: React.CSSProperties = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.3 : 1,
    zIndex: isDragging ? 10 : undefined,
  };

  return (
    <div ref={setNodeRef} style={style} className="relative">
      {/* Drag handle */}
      <div
        {...attributes}
        {...listeners}
        className="absolute left-0 top-0 bottom-0 w-8 flex items-center justify-center cursor-grab active:cursor-grabbing"
      >
        <GripVertical className="h-4 w-4 text-muted-foreground" />
      </div>
      <div className="pl-8">
        <ShelfItemCard item={item} />
      </div>
    </div>
  );
}
```

### 3.7 File Manager Drag-to-Folder

Enable dragging files from the file table and dropping them onto folder rows to move them:

```tsx
function DraggableFileRow({ file, onMove }: { file: FileNode; onMove: (source: string, target: string) => void }) {
  const [isDragOver, setIsDragOver] = useState(false);

  const handleDragStart = (e: React.DragEvent) => {
    e.dataTransfer.setData("application/x-file-path", file.path);
    e.dataTransfer.effectAllowed = "move";
  };

  const handleDragOver = (e: React.DragEvent) => {
    if (!file.is_directory) return; // Only folders are drop targets
    if (!e.dataTransfer.types.includes("application/x-file-path")) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = "move";
    setIsDragOver(true);
  };

  const handleDragLeave = () => setIsDragOver(false);

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    const sourcePath = e.dataTransfer.getData("application/x-file-path");
    if (!sourcePath || sourcePath === file.path) return;
    onMove(sourcePath, file.path);
  };

  return (
    <tr
      draggable={!file.is_directory}
      onDragStart={handleDragStart}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      className={cn(
        "cursor-default",
        !file.is_directory && "cursor-grab active:cursor-grabbing",
        isDragOver && "bg-primary/10 border-2 border-primary",
      )}
    >
      {/* ... file row content */}
    </tr>
  );
}
```

The `onMove` callback calls the existing backend endpoint:

```typescript
const handleFileMove = async (sourcePath: string, targetFolderPath: string) => {
  const fileName = sourcePath.split("/").pop() || "";
  const newPath = targetFolderPath.endsWith("/")
    ? targetFolderPath + fileName
    : targetFolderPath + "/" + fileName;

  try {
    await moveNode(sourcePath, newPath);
    toast.success(`Moved ${fileName} to ${targetFolderPath}`);
    refetchTree();
  } catch (err) {
    toast.error(`Failed to move ${fileName}`);
  }
};
```

### 3.8 Ticket Kanban Board

Add a kanban view option to the Tickets page with drag-and-drop status transitions:

```tsx
<!-- CORRECTED: was 5 columns (open, pending, in_progress, resolved, closed), actually 4 columns matching _TICKET_STATUSES: open, in_progress, waiting_on_user, done -->
const KANBAN_COLUMNS = [
  { id: "open", label: "Open", color: "bg-blue-500" },
  { id: "in_progress", label: "In Progress", color: "bg-purple-500" },
  { id: "waiting_on_user", label: "Waiting on User", color: "bg-yellow-500" },
  { id: "done", label: "Done", color: "bg-green-500" },
] as const;

function TicketKanbanBoard({ tickets }: { tickets: Ticket[] }) {
  const queryClient = useQueryClient();

  const updateStatusMut = useMutation({
    mutationFn: ({ ticketId, status }: { ticketId: string; status: string }) =>
      updateTicketStatus(ticketId, status),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["tickets"] }),
    onError: (_, variables) => {
      toast.error(`Cannot change status to ${variables.status}`);
    },
  });

  const handleDragEnd = (event: DragEndEvent) => {
    const { active, over } = event;
    if (!over) return;

    const ticketId = active.id as string;
    const newStatus = over.id as string;

    const ticket = tickets.find((t) => t.ticket_id === ticketId);
    if (!ticket || ticket.status === newStatus) return;

    // Check valid transition client-side (must match _STATUS_TRANSITIONS from tickets.py)
    const validTransitions = VALID_TRANSITIONS[ticket.status] ?? [];
    if (!validTransitions.includes(newStatus)) {
      toast.error(`Cannot move from ${ticket.status} to ${newStatus}`);
      return;
    }

    updateStatusMut.mutate({ ticketId, status: newStatus });
  };

  return (
    <DndContext
      collisionDetection={closestCenter}
      onDragEnd={handleDragEnd}
    >
      <div className="flex gap-4 overflow-x-auto pb-4">
        {KANBAN_COLUMNS.map((col) => {
          const columnTickets = tickets.filter((t) => t.status === col.id);
          return (
            <KanbanColumn
              key={col.id}
              column={col}
              tickets={columnTickets}
            />
          );
        })}
      </div>
    </DndContext>
  );
}

function KanbanColumn({ column, tickets }: { column: typeof KANBAN_COLUMNS[number]; tickets: Ticket[] }) {
  const { setNodeRef, isOver } = useDroppable({ id: column.id });

  return (
    <div
      ref={setNodeRef}
      className={cn(
        "w-72 shrink-0 rounded-lg bg-muted/50 p-3",
        isOver && "ring-2 ring-primary bg-primary/5",
      )}
    >
      <div className="flex items-center gap-2 mb-3">
        <div className={cn("w-3 h-3 rounded-full", column.color)} />
        <h3 className="text-sm font-semibold">{column.label}</h3>
        <Badge variant="outline" className="ml-auto">{tickets.length}</Badge>
      </div>
      <div className="space-y-2 min-h-[100px]">
        {tickets.map((ticket) => (
          <DraggableTicketCard key={ticket.ticket_id} ticket={ticket} />
        ))}
      </div>
    </div>
  );
}

function DraggableTicketCard({ ticket }: { ticket: Ticket }) {
  const { attributes, listeners, setNodeRef, transform, isDragging } = useDraggable({
    id: ticket.ticket_id,
  });

  return (
    <div
      ref={setNodeRef}
      {...attributes}
      {...listeners}
      style={{ transform: CSS.Translate.toString(transform) }}
      className={cn(
        "bg-card rounded-lg border p-3 cursor-grab active:cursor-grabbing shadow-sm",
        isDragging && "opacity-50 shadow-lg ring-2 ring-primary",
      )}
    >
      <p className="text-sm font-medium truncate">{ticket.subject}</p>
      <p className="text-xs text-muted-foreground mt-1 truncate">{ticket.description}</p>
      <div className="flex items-center gap-2 mt-2">
        <Badge variant="outline" className="text-[10px]">{ticket.priority}</Badge>
        {ticket.assigned_to && (
          <span className="text-[10px] text-muted-foreground">
            Assigned: {ticket.assigned_to.slice(0, 8)}...
          </span>
        )}
      </div>
    </div>
  );
}
```

### 3.9 Post Composer Drop Zone

Add a drop zone to the `CreatePost` component:

```tsx
const [dragOverPost, setDragOverPost] = useState(false);

<div
  onDragOver={(e) => {
    if (!e.dataTransfer.types.includes("Files")) return;
    e.preventDefault();
    setDragOverPost(true);
  }}
  onDragLeave={() => setDragOverPost(false)}
  onDrop={(e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOverPost(false);
    const file = e.dataTransfer.files[0];
    if (file?.type.startsWith("image/")) {
      const previewUrl = URL.createObjectURL(file);
      setPostImage({ file, previewUrl });
    } else {
      toast.error("Only images can be attached to posts");
    }
  }}
  className="relative"
>
  {dragOverPost && (
    <DropIndicator text="Drop image to attach" icon={Image} variant="upload" />
  )}
  <textarea ... />
</div>
```

### 3.10 Undo Reorder Toast

After a drag reorder (broadcast shelf, playlist), show a brief "Undo" toast:

```tsx
const handleDragEnd = (event: DragEndEvent) => {
  // ... reorder logic
  const previousOrder = [...orderedItems]; // Save previous state

  setOrderedItems(reordered);
  reorderMut.mutate(newOrder);

  // Show undo toast
  toast("Items reordered", {
    action: {
      label: "Undo",
      onClick: () => {
        setOrderedItems(previousOrder);
        const undoOrder = previousOrder.map((i) => i.item_id);
        reorderMut.mutate(undoOrder);
      },
    },
    duration: 5000,
  });
};
```

---

## 4. API Endpoints

No new backend endpoints are required. All drag-and-drop interactions use existing endpoints:

| Interaction | Endpoint | Method |
|------------|----------|--------|
| File upload (drop) | `/ui/filemanager/nodes` | POST (multipart) |
| Message image attach | `/messaging/conversations/{id}/image-messages` | POST (multipart) |
| Broadcast shelf reorder | `/broadcast/sessions/{id}/products/reorder` | PATCH |
| File move (drag to folder) | `/ui/filemanager/nodes/move` | POST |
| Ticket status change | `/ui/tickets/{id}/status` | PATCH |

### 4.1 Batch File Upload (Enhancement)

To support multi-file drop, add a batch upload endpoint:

```
POST /ui/filemanager/batch-upload
  Content-Type: multipart/form-data
  Fields:
    files[]: File (up to 20)
    target_path: str
  Auth: require_ui_session (CSRF required)
  Response 200: {
    uploaded: [{ path: str, name: str, size: int }],
    failed: [{ name: str, error: str }]
  }
  Response 400: { detail: "No files provided" }
  Response 413: { detail: "Total upload size exceeds 500MB" }
```

This is more efficient than uploading files one at a time because it avoids N separate HTTP round-trips. The backend processes files in parallel (or sequentially with a single DDB transaction for metadata).

Backend implementation:

```python
from fastapi import UploadFile, File as FastAPIFile

@router.post("/batch-upload")
async def batch_upload(
    files: List[UploadFile] = FastAPIFile(...),
    target_path: str = Form(...),
    session=Depends(require_ui_session),
):
    user_id = session["user_sub"]

    if len(files) > 20:
        raise HTTPException(400, "Maximum 20 files per batch")

    total_size = sum(f.size or 0 for f in files)
    if total_size > 500 * 1024 * 1024:
        raise HTTPException(413, "Total upload size exceeds 500MB")

    uploaded = []
    failed = []

    for f in files:
        try:
            dest = f"{target_path.rstrip('/')}/{f.filename}"
            content = await f.read()
            # ... store in S3, create DDB record
            uploaded.append({"path": dest, "name": f.filename, "size": len(content)})
        except Exception as exc:
            failed.append({"name": f.filename, "error": str(exc)})

    return {"uploaded": uploaded, "failed": failed}
```

---

## 5. Frontend Components

### 5.1 AppDropZone (Global)

**File**: `frontend/src/components/shared/AppDropZone.tsx` (new)

- Wraps the entire app at the `AppShell` level.
- Detects OS file drags (checks `e.dataTransfer.types.includes("Files")`).
- Shows context-aware full-screen overlay.
- Routes dropped files to the appropriate page handler via custom event.
- Uses `dragCountRef` pattern from `UploadZone` for reliable enter/leave tracking.

### 5.2 DropIndicator (Shared)

**File**: `frontend/src/components/shared/DropIndicator.tsx` (new)

- Reusable drop zone visual indicator.
- Props: `text`, `icon`, `variant` (upload/move/invalid).
- Renders a dashed border with icon and text.
- Used by AppDropZone, ComposeBar drop zone, CreatePost drop zone, and file-to-folder drop targets.

```tsx
interface DropIndicatorProps {
  text: string;
  icon?: React.ComponentType<{ className?: string }>;
  variant?: "upload" | "move" | "invalid";
}

export function DropIndicator({ text, icon: Icon = Upload, variant = "upload" }: DropIndicatorProps) {
  const colors = {
    upload: "border-primary bg-primary/5 text-primary",
    move: "border-blue-500 bg-blue-500/5 text-blue-500",
    invalid: "border-destructive bg-destructive/5 text-destructive",
  };

  return (
    <div className={cn(
      "absolute inset-0 z-20 flex items-center justify-center rounded-lg border-2 border-dashed backdrop-blur-sm",
      colors[variant],
    )}>
      <div className="flex flex-col items-center gap-2">
        <Icon className="h-10 w-10" />
        <p className="text-sm font-medium">{text}</p>
      </div>
    </div>
  );
}
```

### 5.3 Enhanced UploadZone

**File**: `frontend/src/pages/files/UploadZone.tsx`

- Add parallel upload with concurrency limit of 3.
- Add file size validation.
- Add file count cap (20).
- Add progress toast with per-file status.

### 5.4 SortableShelf Component

**File**: `frontend/src/pages/broadcast/SortableShelf.tsx` (new)

- Uses `@dnd-kit/core` and `@dnd-kit/sortable`.
- Renders broadcast product shelf items as draggable cards.
- Persists reorder to backend on drop.
- Shows drag overlay during drag.
- Includes undo toast after reorder.

### 5.5 TicketKanbanBoard Component

**File**: `frontend/src/pages/tickets/TicketKanbanBoard.tsx` (new)

- Four-column layout with `useDroppable` per column (open, in_progress, waiting_on_user, done).
- Each ticket card is `useDraggable`.
- Calls status change API on cross-column drop.
- Validates status transitions client-side before API call.
- Animates card movement.
- Includes view toggle (list/kanban) on TicketsPage.

### 5.6 Enhanced ComposeBar/ConversationView

**File**: `frontend/src/pages/messages/ConversationView.tsx`

- Add `onDragEnter`/`onDragLeave`/`onDrop` to the conversation container.
- Show drop overlay when files are dragged over the conversation.
- Route dropped files to `ComposeBar`'s file handling logic.
- Validate file type against supported MIME types.

### 5.7 Enhanced CreatePost

**File**: `frontend/src/pages/feed/CreatePost.tsx`

- Add drop zone handlers to the post form.
- Show "Drop image to attach" overlay when dragging over.
- Accept dropped images and PDFs.
- Reject non-image files with toast error.

### 5.8 View Toggle for Tickets

**File**: `frontend/src/pages/tickets/TicketsPage.tsx`

Add a view mode toggle:

```tsx
const [viewMode, setViewMode] = useState<"list" | "kanban">("list");

<div className="flex items-center gap-2 mb-4">
  <Button
    variant={viewMode === "list" ? "default" : "outline"}
    size="sm"
    onClick={() => setViewMode("list")}
  >
    <List className="h-4 w-4 mr-1" /> List
  </Button>
  <Button
    variant={viewMode === "kanban" ? "default" : "outline"}
    size="sm"
    onClick={() => setViewMode("kanban")}
  >
    <Columns className="h-4 w-4 mr-1" /> Board
  </Button>
</div>

{viewMode === "list" ? <TicketList tickets={tickets} /> : <TicketKanbanBoard tickets={tickets} />}
```

---

## 6. E2E Test Plan

### Section 130: File Manager Drag-and-Drop Upload

```
130.1  Drag a file over the file table: dashed border overlay appears
130.2  Drop a file: file is uploaded and appears in the file list
130.3  Drop 5 files simultaneously: all 5 are uploaded with progress toasts
130.4  Drop a file > 100MB: error toast, file not uploaded
130.5  Drag over and leave without dropping: overlay disappears
130.6  Drop 21 files: only first 20 are processed, warning toast shown
130.7  Drop a file while another upload is in progress: new file queued
130.8  Upload failure shows error toast with file name
```

### Section 131: Message Compose Drag-and-Drop

```
131.1  Drag an image file over the conversation view: drop overlay appears
131.2  Drop an image: file preview appears in ComposeBar
131.3  Drop a non-image file (unsupported type): error toast shown
131.4  Drop while ComposeBar is disabled: drop is rejected with toast
131.5  Drop a video file: video preview appears in ComposeBar
131.6  Drop a PDF: PDF preview appears in ComposeBar (treated as image type)
131.7  Drop multiple files: only first file is used (single-file attach)
131.8  Conversation drop zone takes priority over global AppDropZone
```

### Section 132: Broadcast Shelf Drag Reorder

```
132.1  Drag product A below product B: display_order updates
132.2  Drag while session is live: SSE event fired (shelf:reorder)
132.3  Drag to same position: no API call (optimization)
132.4  Reorder persists after page reload
132.5  Keyboard reorder: Space to pick up, Arrow Down to move, Space to drop
132.6  Undo toast appears after reorder, clicking Undo reverts
132.7  Drag handle (grip icon) is the only drag-start area
132.8  Drag overlay shows item card at reduced opacity
```

### Section 133: File Manager Drag-to-Folder

```
133.1  Drag file onto folder row: file is moved into the folder
133.2  Drag file onto non-folder row: no action (invalid drop)
133.3  Drag file onto current folder: no action (same location)
133.4  Folder row highlights when file is dragged over it
133.5  Move failure shows error toast
133.6  Cannot drag folders (only files are draggable)
```

### Section 134: Ticket Kanban Drag

```
134.1  Drag ticket card from "Open" to "In Progress": status updates
134.2  Drag ticket card from "In Progress" to "Done": status updates
134.3  Ticket card moves to the new column with animation
134.4  Status change persists (API confirms via GET)
134.5  Invalid transition (Done -> In Progress): rejected with toast <!-- NOTE: Per _STATUS_TRANSITIONS, "done" can only transition to "open" -->
134.6  View toggle switches between list and kanban
134.7  Kanban column shows ticket count badge
134.8  Ticket card shows subject, priority badge, and assignee
```

### Section 135: Post Composer Drag-and-Drop

```
135.1  Drag image over CreatePost form: drop overlay appears
135.2  Drop image: image preview appears in the post form
135.3  Drop non-image file: rejected with toast "Only images can be attached"
135.4  Drop while no post is being composed: overlay still appears (drag activates composer)
```

### Section 136: Global AppDropZone

```
136.1  Drag file over any page: full-screen overlay appears
136.2  Overlay message changes based on current page
136.3  Drop on /messages page routes to ComposeBar
136.4  Drop on /files page routes to file upload
136.5  Drop on unknown page shows "Drop to upload to Files"
136.6  Browser tab drag does NOT trigger overlay (no "Files" in dataTransfer.types)
136.7  Text selection drag does NOT trigger overlay
```

---

## 7. Edge Cases

1. **Browser tab drag**: Dragging a browser tab over the app should not trigger the file drop overlay. Filter by `e.dataTransfer.types` --- only activate when `"Files"` is in the types array, not when `"text/plain"` or `"text/uri-list"` is present. Chrome populates `types` with `["Files"]` for OS file drags and `["text/plain", "text/uri-list"]` for tab/link drags.

2. **Nested drop zones**: When the app has both a global `AppDropZone` and a page-specific drop zone (e.g., the file manager `UploadZone` or the ConversationView drop zone), the page-specific zone should take priority. Use `e.stopPropagation()` in the page-specific zone's `onDrop` handler to prevent the event from bubbling to `AppDropZone`. The AppDropZone uses document-level event listeners, so the page-specific zone's `stopPropagation` prevents the event from reaching the document.

3. **Drag during upload**: If the user drops a second batch of files while the first batch is still uploading, the new files should be queued after the current batch, not interrupt it. Use a shared upload queue (module-level `uploadQueue` array) to serialize batches.

4. **Touch device support**: `@dnd-kit` supports touch devices via `TouchSensor`. However, long-press to drag may conflict with the browser's text selection or context menu. Configure a minimum drag distance of 10px before initiating a drag on touch devices. The `PointerSensor` with `activationConstraint: { distance: 5 }` handles this:

   ```tsx
   useSensor(PointerSensor, { activationConstraint: { distance: 5 } })
   ```

5. **Accessibility**: All drag-and-drop interactions must have keyboard alternatives:
   - Reordering: `Space` to pick up, `Arrow Up/Down` to move, `Space` to drop, `Escape` to cancel. `@dnd-kit` provides built-in screen reader announcements via `KeyboardSensor`.
   - File upload: The existing file input remains as the keyboard-accessible alternative.
   - File move: Context menu "Move to..." option as alternative.
   - Ticket kanban: Status change dropdown as alternative (existing).

6. **Large files and slow networks**: Dropping a 500MB video file should show an upload progress bar, not freeze the UI. The current `uploadFile` function uses `fetch` which does not support progress events. Consider switching to `XMLHttpRequest` for large file uploads:

   ```typescript
   function uploadFileWithProgress(
     file: File,
     path: string,
     onProgress: (pct: number) => void,
   ): Promise<void> {
     return new Promise((resolve, reject) => {
       const xhr = new XMLHttpRequest();
       xhr.upload.onprogress = (e) => {
         if (e.lengthComputable) onProgress(Math.round((e.loaded / e.total) * 100));
       };
       xhr.onload = () => (xhr.status < 400 ? resolve() : reject(new Error(`HTTP ${xhr.status}`)));
       xhr.onerror = () => reject(new Error("Network error"));

       const formData = new FormData();
       formData.append("file", file);
       formData.append("path", path);

       xhr.open("POST", "/ui/filemanager/nodes");
       xhr.withCredentials = true;
       // CSRF header
       const csrfCookie = document.cookie.match(/ui_csrf=([^;]+)/)?.[1];
       if (csrfCookie) xhr.setRequestHeader("x-csrf-token", csrfCookie);
       xhr.send(formData);
     });
   }
   ```

7. **Drag preview for large items**: When dragging a ticket card or shelf item, the drag overlay should show a miniature version of the card, not a full-size clone. Use `@dnd-kit`'s `DragOverlay` with a scaled-down component. The overlay is rendered outside the sortable context and follows the cursor.

8. **Undo reorder**: After a drag reorder (broadcast shelf, playlist), provide a brief "Undo" toast (5 seconds) that reverts the order change. This prevents accidental reordering during a live broadcast.

9. **Concurrent reorder**: If two admins reorder the broadcast shelf simultaneously, the last write wins. The SSE event (`shelf:reorder`) notifies all connected clients of the new order. Add an optimistic revert if the API call fails (already implemented via `onError` in the mutation).

10. **File type restrictions**: The ComposeBar drop zone should respect the same MIME type restrictions as the file input. Dropping a `.exe` file into the chat should show "Unsupported file type" feedback, not silently ignore the drop. The classification logic in `handleFileChange` only accepts image, video, and audio types --- other types are silently rejected. Update to show a toast for rejected types.

11. **DnD-kit and native file drop coexistence**: `@dnd-kit` uses synthetic events and does not interfere with native browser `dragenter`/`dragover`/`drop` events. However, if a `DndContext` is active (user is dragging an in-UI item), native file drops should be ignored. Check `@dnd-kit`'s active state before activating the file drop overlay.

12. **Memory leaks from object URLs**: `URL.createObjectURL(file)` creates a blob URL that must be revoked when no longer needed. The ComposeBar already revokes the previous preview URL when a new file is selected. The drop handler must follow the same pattern. Failure to revoke blob URLs causes memory leaks proportional to file sizes.

---

## 8. Security Considerations

1. **File upload validation**: All dropped files pass through the same backend validation as files uploaded via the file input. The `uploadFile` function sends multipart form data that the backend validates for:
   - File size limits (server-side, not just client-side)
   - MIME type validation (the backend checks the file's magic bytes, not just the extension)
   - Malware scanning (if configured)
   - Path traversal prevention (the `targetPath` is validated to be within the user's directory)

2. **Cross-origin drag**: The HTML5 drag-and-drop API does not expose file contents during `dragenter`/`dragover` --- only `e.dataTransfer.types` is available. File contents are only accessible in the `drop` event handler. This prevents a malicious page from reading dragged file metadata via CSS attacks.

3. **Drop zone spoofing**: A malicious browser extension could programmatically trigger drop events. The backend validates all uploads via session auth + CSRF, so spoofed drops without proper auth fail at the server level.

4. **Reorder authorization**: The broadcast shelf reorder endpoint (`app/routers/broadcast.py`, line 1953) checks `ctx["user_sub"] != session.created_by` before allowing reorder. The ticket status change endpoint should similarly check that the user has permission to change the ticket's status (creator, assignee, or admin).

5. **Denial of service via rapid drops**: Dropping 100 files simultaneously triggers 100 upload requests. The client-side cap of 20 files per drop mitigates this. The backend should also enforce per-user upload rate limiting. The parallel upload concurrency limit (3) prevents the client from overwhelming the server with simultaneous connections.

6. **Data exfiltration via drag-out**: The file manager does NOT support dragging files out of the browser to the desktop. This is intentional --- files are accessed via download links, which go through auth and logging. Do not implement drag-to-desktop functionality without a security review.

7. **CSRF on reorder/move**: All mutation endpoints (reorder, move, upload) require CSRF tokens via the `x-csrf-token` header. The `api.patch` and `api.post` methods in `frontend/src/api/client.ts` automatically attach this header from the `ui_csrf` cookie. For the `XMLHttpRequest`-based upload (progress tracking), CSRF must be manually attached from the cookie.

8. **Custom dataTransfer types**: The file-to-folder drag uses `application/x-file-path` as the data transfer type. This is a custom MIME type that is only readable within the same origin (browsers prevent cross-origin access to custom data transfer types). This prevents a malicious external page from reading or injecting file paths.

9. **Kanban status validation**: The client-side `VALID_TRANSITIONS` map should be treated as a UX optimization, not a security measure. The backend must independently validate status transitions. The backend's validation is authoritative --- the client-side validation only prevents unnecessary API calls.

---

## Codebase References

> **NOTE**: Several components described in this ticket already exist: `AppDropZone`, `DropIndicator`, `TicketKanbanBoard`, and the enhanced `UploadZone` (with parallel upload, size validation, and file count cap). The `SortableShelf` component is not a separate file; `@dnd-kit` integration exists in `ProductShelfManager.tsx`.

| File | Line(s) | What |
|------|---------|------|
| `frontend/src/pages/files/UploadZone.tsx` | 17 | `UploadZone` component (drag-and-drop file upload) |
| `frontend/src/pages/files/UploadZone.tsx` | 18 | `dragOver` state |
| `frontend/src/pages/files/UploadZone.tsx` | 19 | `dragCountRef` (nested drag enter/leave counter) |
| `frontend/src/pages/files/UploadZone.tsx` | 21 | `handleFiles()` (parallel upload with concurrency limit) |
| `frontend/src/pages/files/UploadZone.tsx` | 104 | `handleDrop()` event handler |
| `frontend/src/pages/files/UploadZone.tsx` | 114-123 | `app-file-drop` custom event listener for global drop routing |
| `frontend/src/pages/files/UploadZone.tsx` | 137 | Visual drag overlay |
| `frontend/src/pages/files/ImageEditorDialog.tsx` | 23 | `ImageEditorDialog` component |
| `frontend/src/pages/files/ImageEditorDialog.tsx` | 29 | `dragStart` state (canvas crop selection, not file drop) |
| `frontend/src/pages/messages/ComposeBar.tsx` | 632 | `handleFileChange()` (file input handler; no drop support) |
| `frontend/src/pages/files/FilesPage.tsx` | 1186 | `UploadZone` JSX wrapper in FilesPage |
| `frontend/src/components/shared/AppDropZone.tsx` | — | Global file drop zone (already implemented) |
| `frontend/src/components/shared/DropIndicator.tsx` | — | Reusable drop zone visual indicator (already implemented) |
| `frontend/src/pages/tickets/TicketKanbanBoard.tsx` | — | Kanban board with drag-and-drop (already implemented) |
| `frontend/src/pages/broadcast/ProductShelfManager.tsx` | 3 | `@dnd-kit/sortable` import for shelf reorder |
| `app/routers/broadcast.py` | 1845 | `BroadcastShelfReorderIn` model (item_order validation) |
| `app/routers/broadcast.py` | 1945 | `PATCH /sessions/{id}/products/reorder` route |
| `app/routers/broadcast.py` | 1953 | Creator-only auth check for reorder |
| `app/services/broadcast_product_shelf.py` | 188 | `reorder_shelf()` (updates display_order, publishes SSE) |
| `app/services/tickets.py` | 15 | `_TICKET_STATUSES` = ("open", "in_progress", "waiting_on_user", "done") |
| `app/services/tickets.py` | 16-21 | `_STATUS_TRANSITIONS` (valid status transition map) |
| `app/services/filemanager.py` | 3474 | `move_node()` (file/folder move) |
| `app/services/filemanager.py` | 3412 | `move_node_dispatched()` (dispatched variant) |
