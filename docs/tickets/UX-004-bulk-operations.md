# UX-004: Bulk Operations

**Ticket**: UX-004
**Author**: Engineering
**Status**: Implemented
**Date**: 2026-05-27
**Priority**: P3 (Nice to Have)
**Estimated effort**: 4-6 days

---

## 1. Executive Summary

<!-- NOTE: This feature is PARTIALLY IMPLEMENTED. The reusable components exist: useMultiSelect.ts hook and BulkActionBar.tsx component. Backend batch endpoints exist: catalog bulk-delete (:859), bulk-update (:887) in catalog.py; newsfeed bulk-delete (:5781), bulk-archive (:5809) in newsfeed.py. However, VideoReviewQueuePage has NOT been refactored to use useMultiSelect (still uses inline state at :66, :192-206). The catalog batch endpoint names differ from the spec (bulk-delete/bulk-update vs batch-archive). -->

Bulk operations exist in two places: the admin video review queue (batch approve/reject with multi-select checkboxes) and the file manager (bulk move). The rest of the platform -- posts, catalog items, stories, scheduled actions -- lacks any multi-select or bulk operation UI. Creators managing hundreds of catalog items or posts must operate on each item individually, which is time-consuming and error-prone.

The video review queue's implementation in `VideoReviewQueuePage.tsx` is well-designed: it has `selectedIds` state as a `Set<string>`, select-all/deselect-all functions, per-item checkboxes, and a floating action bar showing the selected count with approve/reject buttons. However, this pattern is implemented entirely inline (not extracted as a reusable hook or component), so each new surface that needs bulk operations must re-implement the same logic from scratch.

This feature extracts the existing multi-select pattern from `VideoReviewQueuePage.tsx` into a reusable `useMultiSelect` hook and `BulkActionBar` component, then applies it to catalog management (batch archive, batch delete), newsfeed posts (batch delete, batch unpublish), and scheduled actions (batch cancel). Backend batch endpoints are added where they do not yet exist. The design also adds Shift+Click range selection -- a power-user feature missing from the current video queue implementation.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

**US-1: Bulk archive catalog items**
As a creator with a large catalog, I want to select multiple items and archive them at once so that I can clean up my storefront quickly after a seasonal sale.

Acceptance Criteria:
- Checkboxes appear on each catalog item in the management view.
- Selecting 5 items and clicking "Archive Selected" archives all 5 via a single batch API call.
- A toast notification shows "5 items archived" on success.
- If 3 succeed and 2 fail (e.g., already archived), the toast shows "3 archived, 2 failed".
- The batch endpoint caps at 50 items per request.

**US-2: Bulk delete posts**
As a creator cleaning up old content, I want to select multiple posts and delete them in bulk so that I don't have to delete posts one at a time.

Acceptance Criteria:
- A "Manage Posts" toggle activates selection mode on the feed management view.
- In selection mode, post cards show checkboxes.
- "Delete Selected" button appears in the floating `BulkActionBar`.
- A confirmation dialog prevents accidental bulk deletion.
- Deleted posts are immediately removed from the feed.

**US-3: Select all with one click**
As a creator, I want to select all visible items with one click so that I can quickly act on an entire page of items.

Acceptance Criteria:
- A "Select All" checkbox in the table/list header selects all items on the current page.
- The "Select All" checkbox shows an indeterminate state when some (but not all) items are selected.
- "Deselect All" clears the selection.

**US-4: Shift+Click range selection**
As a power user, I want to Shift+Click to select a range of items so that I can quickly select a contiguous subset without clicking each checkbox individually.

Acceptance Criteria:
- Clicking item 3, then Shift+clicking item 7 selects items 3-7 (inclusive).
- The range selection respects the current visual order (not item IDs).
- Shift+Click on an already-selected item deselects the range.

**US-5: Cancel multiple scheduled actions**
As a creator, I want to select multiple scheduled messages or posts and cancel them at once so that I can quickly undo a batch scheduling mistake.

Acceptance Criteria:
- Scheduled items list shows checkboxes in selection mode.
- "Cancel Selected" batch-cancels all selected scheduled items.
- Already-delivered items cannot be selected for cancellation.

**US-6: Refactor video review queue to use shared hook**
As a developer, I want the existing video review queue to use the shared `useMultiSelect` hook and `BulkActionBar` component so that the pattern is consistent and any bug fixes apply everywhere.

Acceptance Criteria:
- VideoReviewQueuePage's behavior is unchanged after refactoring.
- The inline `selectedIds` state, `selectAll`, `deselectAll`, and floating bar are replaced with the shared hook/component.
- All existing E2E tests for the video review queue continue to pass.

### 2.2 Pain Points

1. **No bulk catalog management**: Archiving 50 old catalog items requires 50 individual clicks.
2. **No bulk post management**: Deleting old posts from a creator's feed requires per-post deletion.
3. **Inconsistent selection UI**: Video review queue has its own `selectedIds` state; file manager has a different pattern. No shared hook.
4. **No keyboard support for selection**: Shift+Click to select a range is not supported anywhere.
5. **No bulk cancel for scheduled items**: Cancelling 10 scheduled messages requires 10 individual cancellation clicks.

---

## 3. Current State Analysis

### 3.1 Video Review Queue -- Existing Bulk Operations

`VideoReviewQueuePage.tsx` implements a complete multi-select pattern. The implementation spans ~250 lines of inline state management and UI:

**State management (line 66):**
```typescript
const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
```

**Toggle function (lines 192-199):**
```typescript
const toggleSelect = (videoId: string) => {
  setSelectedIds((prev) => {
    const next = new Set(prev);
    if (next.has(videoId)) next.delete(videoId);
    else next.add(videoId);
    return next;
  });
};
```

**Select all / Deselect all (lines 201-206):**
```typescript
const selectAll = () => {
  setSelectedIds(new Set(items.map((v) => v.video_id)));
};
const deselectAll = () => {
  setSelectedIds(new Set());
};
```

**Batch mutations (lines 133-175):**
```typescript
const batchApproveMutation = useMutation({
  mutationFn: (videoIds: string[]) =>
    batchReviewVideos(videoIds.map((id) => ({ video_id: id, action: "approve" as const }))),
  onSuccess: (data) => {
    toast.success(`Batch complete: ${data.succeeded} approved, ${data.failed} failed`);
    setSelectedIds(new Set());
    void queryClient.invalidateQueries({ queryKey: ["video-review-queue"] });
  },
});

const batchRejectMutation = useMutation({
  mutationFn: ({ videoIds, reason }: { videoIds: string[]; reason: string }) =>
    batchReviewVideos(videoIds.map((id) => ({ video_id: id, action: "reject" as const, reason }))),
  onSuccess: (data) => {
    toast.success(`Batch complete: ${data.succeeded} rejected, ${data.failed} failed`);
    setSelectedIds(new Set());
    setBatchRejectDialog(false);
    void queryClient.invalidateQueries({ queryKey: ["video-review-queue"] });
  },
});
```

**Floating selection bar UI (lines 256-284):**
```typescript
{selectedIds.size > 0 && (
  <div className="flex items-center gap-3 rounded-lg border bg-card p-3 shadow-sm">
    <span className="text-sm font-medium">{selectedIds.size} selected</span>
    <Button size="sm" variant="outline" onClick={selectAll}>Select All</Button>
    <Button size="sm" variant="outline" onClick={deselectAll}>Deselect All</Button>
    <Button size="sm" onClick={() => batchApproveMutation.mutate(Array.from(selectedIds))}>
      Approve Selected ({selectedIds.size})
    </Button>
    <Button size="sm" variant="destructive" onClick={() => setBatchRejectDialog(true)}>
      Reject Selected ({selectedIds.size})
    </Button>
  </div>
)}
```

**Per-item checkboxes (line 305-306):**
```typescript
<Checkbox
  checked={selectedIds.has(video.video_id)}
  onCheckedChange={() => toggleSelect(video.video_id)}
/>
```

This is a well-implemented pattern that should be extracted into reusable primitives.

**Citations**:
- `frontend/src/pages/admin/VideoReviewQueuePage.tsx:66` -- `selectedIds` state
- `frontend/src/pages/admin/VideoReviewQueuePage.tsx:133-175` -- batch mutations
- `frontend/src/pages/admin/VideoReviewQueuePage.tsx:192-199` -- `toggleSelect`
- `frontend/src/pages/admin/VideoReviewQueuePage.tsx:201-206` -- `selectAll` / `deselectAll`
- `frontend/src/pages/admin/VideoReviewQueuePage.tsx:256-284` -- Floating selection bar
- `frontend/src/pages/admin/VideoReviewQueuePage.tsx:305-306` -- Per-item checkbox

### 3.2 File Manager -- Bulk Move

`FilesPage.tsx` has a bulk move feature (line 866) using a different selection pattern. The file manager uses a separate implementation that is not compatible with the video queue pattern.

**Citations**:
- `frontend/src/pages/files/FilesPage.tsx:866` -- bulk move via `setMoveTarget(null)`

### 3.3 Surfaces Without Bulk Operations

- **Newsfeed**: `frontend/src/pages/feed/NewsFeed.tsx` -- no multi-select, no bulk delete/archive. Posts are managed individually.
- **Catalog/Shop**: `frontend/src/pages/shop/` -- no bulk catalog operations UI. The catalog management page allows single-item create/edit/delete.
- **Scheduled actions**: No bulk cancel UI for scheduled messages or posts.

**Citations**:
- `frontend/src/pages/feed/NewsFeed.tsx` -- verified: no `selectedIds`, `bulk`, or `multi-select` references
- `frontend/src/pages/shop/` -- verified: no bulk operations

### 3.4 Backend Batch Endpoints

The video review queue has a batch endpoint (`batchReviewVideos`). No batch endpoints exist for:
- Catalog item archive/delete
- Post delete/unpublish
- Scheduled action cancel

### 3.5 Gaps

1. No reusable multi-select hook or component
2. No bulk operations on posts, catalog items, or scheduled actions
3. No backend batch endpoints for catalog archive or post delete
4. No Shift+Click range selection anywhere
5. No confirmation dialog for destructive bulk operations
6. No "indeterminate" checkbox state for partial selection

---

## 4. Implementation Plan

### 4.1 Frontend: Reusable `useMultiSelect` Hook

**New file `frontend/src/hooks/useMultiSelect.ts`:**

```typescript
import { useCallback, useMemo, useRef, useState } from "react";

export interface UseMultiSelectReturn<T extends string = string> {
  /** The set of currently selected item IDs. */
  selectedIds: Set<T>;
  /** Number of selected items. */
  count: number;
  /** Whether a specific item is selected. */
  isSelected: (id: T) => boolean;
  /** Toggle a single item's selection state. */
  toggle: (id: T) => void;
  /** Select all provided IDs (typically all visible items). */
  selectAll: (ids: T[]) => void;
  /** Clear all selections. */
  deselectAll: () => void;
  /** Handle a click event with Shift+Click range selection support.
   *  Call this onClick instead of toggle() to get range selection. */
  handleClick: (id: T, event: React.MouseEvent) => void;
  /** Whether all items in the provided list are selected. */
  isAllSelected: (ids: T[]) => boolean;
  /** Whether some (but not all) items are selected. For indeterminate checkbox state. */
  isPartiallySelected: (ids: T[]) => boolean;
}

/**
 * Reusable hook for multi-select with Shift+Click range selection.
 *
 * @param allIds - The ordered list of all visible item IDs.
 *   This must be the visual order (not sorted by ID). Used for
 *   Shift+Click range calculation.
 *
 * Usage:
 * ```tsx
 * const { selectedIds, toggle, selectAll, deselectAll, handleClick, count } =
 *   useMultiSelect(items.map(i => i.id));
 * ```
 */
export function useMultiSelect<T extends string = string>(
  allIds: T[],
): UseMultiSelectReturn<T> {
  const [selectedIds, setSelectedIds] = useState<Set<T>>(new Set());
  const lastClickedRef = useRef<T | null>(null);

  const toggle = useCallback((id: T) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
    lastClickedRef.current = id;
  }, []);

  const selectAll = useCallback((ids: T[]) => {
    setSelectedIds(new Set(ids));
  }, []);

  const deselectAll = useCallback(() => {
    setSelectedIds(new Set());
    lastClickedRef.current = null;
  }, []);

  const handleClick = useCallback(
    (id: T, event: React.MouseEvent) => {
      if (event.shiftKey && lastClickedRef.current) {
        // Range selection: select all items between lastClicked and current
        const lastIndex = allIds.indexOf(lastClickedRef.current);
        const currentIndex = allIds.indexOf(id);
        if (lastIndex >= 0 && currentIndex >= 0) {
          const start = Math.min(lastIndex, currentIndex);
          const end = Math.max(lastIndex, currentIndex);
          const range = allIds.slice(start, end + 1);
          setSelectedIds((prev) => {
            const next = new Set(prev);
            for (const rangeId of range) {
              next.add(rangeId);
            }
            return next;
          });
        }
      } else {
        toggle(id);
      }
      lastClickedRef.current = id;
    },
    [allIds, toggle],
  );

  const isSelected = useCallback(
    (id: T) => selectedIds.has(id),
    [selectedIds],
  );

  const isAllSelected = useCallback(
    (ids: T[]) => ids.length > 0 && ids.every((id) => selectedIds.has(id)),
    [selectedIds],
  );

  const isPartiallySelected = useCallback(
    (ids: T[]) => {
      const someSelected = ids.some((id) => selectedIds.has(id));
      const allSelected = ids.every((id) => selectedIds.has(id));
      return someSelected && !allSelected;
    },
    [selectedIds],
  );

  return useMemo(
    () => ({
      selectedIds,
      count: selectedIds.size,
      isSelected,
      toggle,
      selectAll,
      deselectAll,
      handleClick,
      isAllSelected,
      isPartiallySelected,
    }),
    [selectedIds, isSelected, toggle, selectAll, deselectAll, handleClick, isAllSelected, isPartiallySelected],
  );
}
```

### 4.2 Frontend: `BulkActionBar` Component

**New file `frontend/src/components/shared/BulkActionBar.tsx`:**

```typescript
import { X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface BulkActionBarProps {
  /** Number of selected items. */
  count: number;
  /** Callback to clear all selections. */
  onDeselectAll: () => void;
  /** Action buttons to render (e.g., "Archive Selected", "Delete Selected"). */
  children: React.ReactNode;
  /** Additional CSS classes for the bar container. */
  className?: string;
}

/**
 * A floating action bar that appears when items are selected.
 *
 * Displays the selected count, a "Deselect All" button, and
 * action buttons provided via children.
 *
 * Renders at the bottom of the viewport (fixed position) for
 * visibility regardless of scroll position.
 */
export function BulkActionBar({
  count,
  onDeselectAll,
  children,
  className,
}: BulkActionBarProps) {
  if (count === 0) return null;

  return (
    <div
      className={cn(
        "fixed bottom-4 left-1/2 -translate-x-1/2 z-50",
        "flex items-center gap-3 rounded-lg border bg-card px-4 py-3 shadow-lg",
        "animate-in slide-in-from-bottom-4 duration-200",
        className,
      )}
      role="toolbar"
      aria-label={`${count} items selected`}
    >
      <span className="text-sm font-medium whitespace-nowrap">
        {count} selected
      </span>

      <Button
        size="sm"
        variant="ghost"
        onClick={onDeselectAll}
        aria-label="Deselect all"
      >
        <X className="mr-1 h-3 w-3" />
        Deselect
      </Button>

      <div className="h-4 w-px bg-border" aria-hidden />

      {children}
    </div>
  );
}
```

### 4.3 Frontend: Refactor VideoReviewQueuePage

Replace inline `selectedIds` state (line 66), `toggleSelect` (lines 192-199), `selectAll`/`deselectAll` (lines 201-206), and floating bar (lines 256-284) with `useMultiSelect` hook and `BulkActionBar` component.

```typescript
// Before:
const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
// ...
const toggleSelect = (videoId: string) => { ... };
const selectAll = () => { setSelectedIds(new Set(items.map((v) => v.video_id))); };
const deselectAll = () => { setSelectedIds(new Set()); };

// After:
const {
  selectedIds,
  count: selectedCount,
  isSelected,
  toggle: toggleSelect,
  selectAll,
  deselectAll,
  handleClick,
  isAllSelected,
  isPartiallySelected,
} = useMultiSelect(items.map((v) => v.video_id));

// Replace floating bar with:
<BulkActionBar count={selectedCount} onDeselectAll={deselectAll}>
  <Button size="sm" onClick={() => selectAll(items.map((v) => v.video_id))}>
    Select All
  </Button>
  <Button
    size="sm"
    onClick={() => batchApproveMutation.mutate(Array.from(selectedIds))}
    disabled={batchApproveMutation.isPending}
  >
    Approve Selected ({selectedCount})
  </Button>
  <Button
    size="sm"
    variant="destructive"
    onClick={() => setBatchRejectDialog(true)}
    disabled={batchRejectMutation.isPending}
  >
    Reject Selected ({selectedCount})
  </Button>
</BulkActionBar>
```

### 4.4 Backend: Batch Catalog Archive

**New endpoint in `app/routers/catalog.py`:**

```python
class CatalogBatchArchiveReq(BaseModel):
    """Request body for batch catalog item archive."""
    item_ids: list[str] = Field(..., min_length=1, max_length=50)


@router.post("/items/batch-archive")
async def batch_archive_items(
    body: CatalogBatchArchiveReq,
    ctx=Depends(require_ui_session),
):
    """Batch-archive catalog items.

    Sets status='archived' on each item. Only items owned by the
    authenticated user are processed. Non-owned items return ok=False.

    Capped at 50 items per request to limit DynamoDB write load.
    """
    user_sub = ctx["user_sub"]
    results = []
    for item_id in body.item_ids:
        try:
            # Verify ownership
            item = T.catalog.get_item(
                Key={"PK": f"ITEM#{item_id}", "SK": "META"}
            ).get("Item")
            if not item or item.get("owner_user_id") != user_sub:
                results.append({"item_id": item_id, "ok": False, "error": "not_owner"})
                continue

            # Archive the item
            T.catalog.update_item(
                Key={"PK": f"ITEM#{item_id}", "SK": "META"},
                UpdateExpression="SET #status = :archived, updated_at = :ts",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":archived": "archived",
                    ":ts": now_ts(),
                },
            )
            results.append({"item_id": item_id, "ok": True})
        except Exception as e:
            results.append({"item_id": item_id, "ok": False, "error": str(e)})

    succeeded = sum(1 for r in results if r["ok"])
    failed = sum(1 for r in results if not r["ok"])
    return {"results": results, "succeeded": succeeded, "failed": failed}
```

### 4.5 Backend: Batch Post Delete

**New endpoint in `app/routers/newsfeed.py`:**

```python
class PostBatchDeleteReq(BaseModel):
    """Request body for batch post deletion."""
    post_ids: list[str] = Field(..., min_length=1, max_length=50)


@router.post("/posts/batch-delete")
async def batch_delete_posts(
    body: PostBatchDeleteReq,
    ctx=Depends(require_ui_session),
):
    """Batch-delete posts.

    Soft-deletes posts by setting status='deleted'. Only posts owned
    by the authenticated user are processed.

    Capped at 50 posts per request.
    """
    user_sub = ctx["user_sub"]
    results = []
    for post_id in body.post_ids:
        try:
            # Verify ownership and delete
            post = T.newsfeed.get_item(
                Key={"pk": f"POST#{post_id}", "sk": "META"}
            ).get("Item")
            if not post or post.get("author_user_id") != user_sub:
                results.append({"post_id": post_id, "ok": False, "error": "not_owner"})
                continue

            T.newsfeed.update_item(
                Key={"pk": f"POST#{post_id}", "sk": "META"},
                UpdateExpression="SET #status = :deleted, deleted_at = :ts",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":deleted": "deleted",
                    ":ts": now_ts(),
                },
            )
            results.append({"post_id": post_id, "ok": True})
        except Exception as e:
            results.append({"post_id": post_id, "ok": False, "error": str(e)})

    succeeded = sum(1 for r in results if r["ok"])
    failed = sum(1 for r in results if not r["ok"])
    return {"results": results, "succeeded": succeeded, "failed": failed}
```

### 4.6 Frontend: Catalog Bulk UI

Add `useMultiSelect` to the catalog management view. Add checkboxes to each catalog item row. Add `BulkActionBar` with "Archive Selected" and "Delete Selected" actions.

```typescript
import { useMultiSelect } from "@/hooks/useMultiSelect";
import { BulkActionBar } from "@/components/shared/BulkActionBar";
import { batchArchiveCatalogItems } from "@/api/endpoints/catalog";

// In the catalog management component:
const itemIds = items.map((i) => i.item_id);
const { selectedIds, count, isSelected, handleClick, selectAll, deselectAll } =
  useMultiSelect(itemIds);

const archiveMut = useMutation({
  mutationFn: (ids: string[]) => batchArchiveCatalogItems(ids),
  onSuccess: (data) => {
    toast.success(`${data.succeeded} items archived`);
    deselectAll();
    queryClient.invalidateQueries({ queryKey: ["catalog"] });
  },
});

// Render:
<BulkActionBar count={count} onDeselectAll={deselectAll}>
  <Button size="sm" onClick={() => selectAll(itemIds)}>Select All</Button>
  <Button
    size="sm"
    variant="destructive"
    onClick={() => archiveMut.mutate(Array.from(selectedIds))}
    disabled={archiveMut.isPending}
  >
    Archive Selected ({count})
  </Button>
</BulkActionBar>
```

### 4.7 Frontend: Post Bulk UI

Add a "Manage Posts" toggle to the NewsFeed page. When active, post cards show checkboxes. `BulkActionBar` shows "Delete Selected" action with a confirmation dialog.

```typescript
const [manageMode, setManageMode] = useState(false);
const postIds = posts.map((p) => p.post_id);
const { selectedIds, count, isSelected, handleClick, deselectAll } =
  useMultiSelect(postIds);

// Toggle button:
<Button variant="outline" onClick={() => setManageMode(!manageMode)}>
  {manageMode ? "Exit Manage Mode" : "Manage Posts"}
</Button>

// In each PostCard:
{manageMode && (
  <Checkbox
    checked={isSelected(post.post_id)}
    onClick={(e) => handleClick(post.post_id, e)}
  />
)}
```

### 4.8 Frontend: API Endpoints

**Add to `frontend/src/api/endpoints/catalog.ts`:**
```typescript
export const batchArchiveCatalogItems = (itemIds: string[]) =>
  api.post("/ui/catalog/items/batch-archive", { item_ids: itemIds })
    .then((r) => r.data as { results: any[]; succeeded: number; failed: number });
```

**Add to `frontend/src/api/endpoints/feed.ts`:**
```typescript
export const batchDeletePosts = (postIds: string[]) =>
  api.post("/ui/feed/posts/batch-delete", { post_ids: postIds })
    .then((r) => r.data as { results: any[]; succeeded: number; failed: number });
```

---

## 5. Data Model

No new DynamoDB tables required. Batch operations update existing records:

| Operation | Table | Update | Field |
|-----------|-------|--------|-------|
| Archive catalog item | `T.catalog` | `SET status = "archived"` | `status` attribute |
| Delete post | `T.newsfeed` | `SET status = "deleted"` | `status` attribute |

---

## 6. API Design

### 6.1 `POST /ui/catalog/items/batch-archive`

**Method**: POST
**Path**: `/ui/catalog/items/batch-archive`
**Auth**: `require_ui_session` (cookie-based with CSRF)
**Description**: Batch-archive catalog items.

**Request Body:**
```json
{
  "item_ids": ["item_abc", "item_def", "item_ghi"]
}
```

**Validation:**
- `item_ids`: list of strings, min 1, max 50.

**Response (200):**
```json
{
  "results": [
    { "item_id": "item_abc", "ok": true },
    { "item_id": "item_def", "ok": true },
    { "item_id": "item_ghi", "ok": false, "error": "not_owner" }
  ],
  "succeeded": 2,
  "failed": 1
}
```

### 6.2 `POST /ui/feed/posts/batch-delete`

**Method**: POST
**Path**: `/ui/feed/posts/batch-delete`
**Auth**: `require_ui_session` (cookie-based with CSRF)
**Description**: Batch-delete (soft-delete) posts.

**Request Body:**
```json
{
  "post_ids": ["post_abc", "post_def"]
}
```

**Validation:**
- `post_ids`: list of strings, min 1, max 50.

**Response (200):**
```json
{
  "results": [
    { "post_id": "post_abc", "ok": true },
    { "post_id": "post_def", "ok": true }
  ],
  "succeeded": 2,
  "failed": 0
}
```

**Error Responses (both endpoints):**
| Status | Condition | Body |
|--------|-----------|------|
| 401 | Not authenticated | `{"detail": "Not authenticated"}` |
| 422 | Empty item_ids/post_ids | `{"detail": [...]}` |
| 422 | Over 50 items | `{"detail": [...]}` |

**Rate Limit**: 10 requests/minute per user.

---

## 7. Frontend Implementation

### 7.1 Component Hierarchy

```
VideoReviewQueuePage.tsx
  ├── useMultiSelect(itemIds)
  ├── Checkbox (per item)
  └── BulkActionBar
       ├── "Select All" button
       ├── "Approve Selected" button
       └── "Reject Selected" button

CatalogManagementPage.tsx
  ├── useMultiSelect(itemIds)
  ├── Checkbox (per item)
  └── BulkActionBar
       ├── "Select All" button
       └── "Archive Selected" button

NewsFeed.tsx (manage mode)
  ├── useMultiSelect(postIds)
  ├── Checkbox (per post card)
  └── BulkActionBar
       └── "Delete Selected" button (with confirm dialog)
```

### 7.2 State Management

| Component | Hook | Local State |
|-----------|------|------------|
| VideoReviewQueuePage | `useMultiSelect` | `batchRejectDialog`, `batchRejectionReason` |
| CatalogManagementPage | `useMultiSelect` | None additional |
| NewsFeed | `useMultiSelect` | `manageMode`, `confirmDeleteOpen` |

### 7.3 React Query Integration

| Surface | Mutation | Invalidated Queries |
|---------|----------|-------------------|
| Video review | `batchReviewVideos` | `["video-review-queue"]` |
| Catalog archive | `batchArchiveCatalogItems` | `["catalog", categoryId, "items"]` |
| Post delete | `batchDeletePosts` | `["feed"]`, `["posts"]` |

### 7.4 Responsive Behavior

- **Desktop**: `BulkActionBar` renders as a floating bar at the bottom center.
- **Mobile**: Bar stretches full width with horizontal scroll for action buttons if they overflow.
- **Checkboxes**: 44x44px touch target minimum (WCAG 2.5.5).
- **Shift+Click**: Not available on touch (no Shift key). Touch users use individual checkbox taps.

---

## 8. Testing Plan

### 8.1 Unit Tests (Vitest)

**File**: `frontend/src/hooks/useMultiSelect.test.ts`

| # | Test Name | Assertion |
|---|-----------|-----------|
| 1 | `toggle adds item` | `isSelected("a")` returns true after `toggle("a")` |
| 2 | `toggle removes item` | `isSelected("a")` returns false after toggling twice |
| 3 | `selectAll selects all IDs` | `count` equals number of IDs provided |
| 4 | `deselectAll clears selection` | `count` is 0 |
| 5 | `handleClick with Shift selects range` | Click "b", Shift+click "d" → "b", "c", "d" selected |
| 6 | `handleClick without Shift toggles single` | Click "b" → only "b" selected |
| 7 | `isAllSelected returns true when all selected` | After selectAll, isAllSelected returns true |
| 8 | `isPartiallySelected returns true for partial` | Select 2 of 5 → isPartiallySelected true, isAllSelected false |
| 9 | `range selection wraps correctly` | Click "d", Shift+click "b" → "b", "c", "d" selected (backwards) |

**File**: `frontend/src/components/shared/BulkActionBar.test.tsx`

| # | Test Name | Assertion |
|---|-----------|-----------|
| 10 | `shows correct count` | Text "{count} selected" visible |
| 11 | `hidden when count is 0` | Component not rendered |
| 12 | `Deselect button calls onDeselectAll` | onClick calls the callback |
| 13 | `renders children` | Action buttons visible |
| 14 | `has toolbar role` | `role="toolbar"` present |

### 8.2 E2E Tests

**File**: `frontend/e2e/bulk-operations.spec.ts`

| # | Section | Test Name | Assertion |
|---|---------|-----------|-----------|
| 1 | API | Batch archive catalog items | POST returns 200 with `succeeded > 0` |
| 2 | API | Batch archive non-owned items | Returns `ok: false` for non-owned items |
| 3 | API | Batch delete posts | POST returns 200 with `succeeded > 0` |
| 4 | API | Batch endpoint caps at 50 items | 51-item request returns 422 |
| 5 | API | Batch archive empty array returns 422 | 422 for `item_ids: []` |
| 6 | UI | Video review queue batch approve still works | Select 2 videos, approve, verify success toast |
| 7 | UI | Catalog checkboxes visible in manage mode | Checkboxes rendered on each item |
| 8 | UI | BulkActionBar shows count | Select 3 items, bar shows "3 selected" |

```typescript
test.describe("UX-004: Bulk Operations — API", () => {
  test("Batch archive catalog items returns success count", async ({ page }) => {
    await injectAuth(page, "alice");

    // Create test items
    const items: string[] = [];
    for (let i = 0; i < 3; i++) {
      const resp = await page.request.post("/ui/catalog/categories/cat_1/items", {
        headers: { "x-csrf-token": sessions.alice.csrf_token },
        data: { name: `Bulk Item ${i}`, price_cents: 100 },
      });
      items.push((await resp.json()).item.item_id);
    }

    // Batch archive
    const archiveResp = await page.request.post("/ui/catalog/items/batch-archive", {
      headers: { "x-csrf-token": sessions.alice.csrf_token },
      data: { item_ids: items },
    });
    expect(archiveResp.status()).toBe(200);
    const result = await archiveResp.json();
    expect(result.succeeded).toBe(3);
    expect(result.failed).toBe(0);
  });
});
```

---

## 9. Security Considerations

### 9.1 Authentication and Authorization

- All batch endpoints use `require_ui_session` with CSRF enforcement.
- Each item in the batch is individually checked for ownership before processing.
- Non-owned items are skipped silently (no information leakage about other users' items).

### 9.2 Denial of Service

- The 50-item cap per request limits the DynamoDB load per call to at most 100 operations (50 GetItem + 50 UpdateItem).
- Rate limiting of 10 requests/minute prevents rapid repeated batch calls.
- The backend processes items sequentially (not in parallel) to avoid DDB throttling.

### 9.3 Data Integrity

- Batch operations are not atomic. If the server crashes mid-batch, some items may be processed and others may not. The per-item `results` array lets the client know which items succeeded.
- No batch undo capability. Deleted posts are soft-deleted (recoverable by admin). Archived items can be un-archived individually.

---

## 10. Performance Considerations

### 10.1 DynamoDB Write Cost

- Each batch operation performs 1 GetItem + 1 UpdateItem per item.
- A 50-item batch: 50 GetItem (50 RCU) + 50 UpdateItem (50 WCU) = ~$0.00002 per batch.
- Sequential processing: 50 items takes ~2-3 seconds (50ms per DDB round trip).

### 10.2 Optimistic UI

The frontend removes selected items from the UI immediately on batch mutation start (optimistic update). If the batch partially fails, only the failed items are re-added to the list on mutation settlement. This prevents the UI from flickering during the 2-3 second batch processing time.

### 10.3 Bundle Size

- `useMultiSelect.ts`: ~80 lines (~1KB gzipped)
- `BulkActionBar.tsx`: ~50 lines (~0.5KB gzipped)
- Total bundle increase: ~1.5KB gzipped

---

## 11. Migration / Rollout Plan

### 11.1 Feature Flag

No feature flag needed. The batch endpoints are additive and the frontend changes are progressive:
1. `useMultiSelect` and `BulkActionBar` are new files -- no existing behavior changes.
2. VideoReviewQueuePage refactoring preserves identical behavior.
3. Catalog and feed bulk UI is new functionality.

### 11.2 Backward Compatibility

- The VideoReviewQueuePage refactoring does not change the API contract or user-facing behavior.
- Batch endpoints return per-item results, so partial failures are transparent.
- The `useMultiSelect` hook does not affect existing selection patterns in other components.

### 11.3 Rollout Steps

1. Create `useMultiSelect.ts` and `BulkActionBar.tsx`.
2. Refactor `VideoReviewQueuePage.tsx` to use shared primitives. Run existing E2E tests.
3. Add batch endpoints to `catalog.py` and `newsfeed.py`.
4. Add catalog bulk UI with `useMultiSelect` + `BulkActionBar`.
5. Add post bulk UI with manage mode toggle.
6. Write E2E tests.

---

## 12. Acceptance Criteria

1. A reusable `useMultiSelect` hook exists with `toggle`, `selectAll`, `deselectAll`, `handleClick` (with Shift range), `isSelected`, `isAllSelected`, `isPartiallySelected`.
2. A reusable `BulkActionBar` component renders when `count > 0` with selected count, deselect button, and action button slots.
3. Catalog items can be selected via checkboxes and batch-archived via `POST /ui/catalog/items/batch-archive`.
4. Newsfeed posts can be selected via checkboxes and batch-deleted via `POST /ui/feed/posts/batch-delete` in "manage" mode.
5. The video review queue's existing batch operations use the shared `useMultiSelect` hook (no behavior change).
6. Shift+Click selects a contiguous range of items between the last clicked and current item.
7. Batch endpoints cap at 50 items per request and return per-item success/failure results.
8. "Select All" / "Deselect All" buttons work correctly.
9. The "Select All" checkbox header shows indeterminate state when partially selected.
10. A confirmation dialog is shown before destructive bulk operations (delete).
11. All existing video review queue E2E tests continue to pass after refactoring.

---

## 13. Dependencies

### 13.1 Internal Dependencies

- `Checkbox` component from `@/components/ui/checkbox` (already exists, used by VideoReviewQueuePage).
- `useMutation` from React Query (already in use across the app).
- `toast` from `sonner` (already in use for notifications).
- Video review batch API (`batchReviewVideos`) -- already exists.

### 13.2 External Dependencies

None. No new npm packages required.

### 13.3 Related Tickets

- **UX-003 (Drag-and-Drop Reorder)**: Bulk selection and drag-to-reorder are complementary. Both can coexist on the same list (checkboxes for selection, drag handle for reorder).
- **PLATFORM-009 (CSV Export)**: Could add "Export Selected as CSV" to bulk action bars.

---

## 14. Open Questions / Risks

1. **Catalog item key schema**: The implementation assumes `PK = ITEM#{item_id}`, `SK = META`. Verify the actual catalog item key pattern before implementation.

2. **Post key schema**: The implementation assumes `pk = POST#{post_id}`, `sk = META`. Verify the actual newsfeed post key pattern.

3. **Batch atomicity**: Batch operations are not atomic. If the user closes the browser mid-batch, some items will be processed and others will not. This is acceptable for archive/delete (idempotent), but might be surprising for the user. Consider: should the endpoint fire all UpdateItems in parallel to reduce the window of partial completion?

4. **Undo for batch delete**: Should we add a "Batch Undo" capability? Currently, soft-deleted posts can only be recovered by an admin. Adding a "Recently Deleted" recycle bin would be a separate feature.

5. **Cross-page selection**: Currently, selection is limited to the visible page. If a user wants to select items across pagination boundaries, they cannot. This is consistent with the existing video queue behavior. A future enhancement could add "Select All (across pages)" that tracks selection server-side.

---

## 15. Files to Create

| File | Purpose |
|------|---------|
| `frontend/src/hooks/useMultiSelect.ts` | Reusable multi-select hook with range selection |
| `frontend/src/hooks/useMultiSelect.test.ts` | Unit tests for the hook |
| `frontend/src/components/shared/BulkActionBar.tsx` | Floating bulk action bar component |
| `frontend/src/components/shared/BulkActionBar.test.tsx` | Unit tests for the component |
| `frontend/e2e/bulk-operations.spec.ts` | E2E tests |

## 16. Files to Modify

| File | Change |
|------|--------|
| `frontend/src/pages/admin/VideoReviewQueuePage.tsx` | Refactor to use `useMultiSelect` hook and `BulkActionBar` (replace lines 66, 192-206, 256-284) |
| `app/routers/catalog.py` | Add `POST /items/batch-archive` endpoint |
| `app/routers/newsfeed.py` | Add `POST /posts/batch-delete` endpoint |
| `app/models.py` | Add `CatalogBatchArchiveReq`, `PostBatchDeleteReq` models |
| `frontend/src/api/endpoints/catalog.ts` | Add `batchArchiveCatalogItems` function |
| `frontend/src/api/endpoints/feed.ts` | Add `batchDeletePosts` function |
| `frontend/src/pages/feed/NewsFeed.tsx` | Add manage mode toggle, checkboxes, BulkActionBar |

---


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_bulk_operations.py`

| # | Function | Assertion |
|---|----------|-----------|
| 1 | `test_bulk_delete_files` | Bulk delete files verified |
| 2 | `test_bulk_move_files` | Bulk move files verified |
| 3 | `test_bulk_read_conversations` | Bulk read conversations verified |
| 4 | `test_bulk_delete_conversations` | Bulk delete conversations verified |
| 5 | `test_bulk_dismiss_alerts` | Bulk dismiss alerts verified |
| 6 | `test_bulk_operation_partial_failure` | Bulk operation partial failure verified |
| 7 | `test_bulk_operation_max_items` | Bulk operation max items verified |
| 8 | `test_bulk_select_all` | Bulk select all verified |

**Mocking**: All DynamoDB tables mocked via `moto`; profile lookups patched via `unittest.mock.patch`.

### Integration Tests

1. Select 10 files -> bulk delete -> all removed from file manager
2. Select conversations -> bulk mark read -> unread counts update
3. Bulk operation with 1 failure -> partial success response with error details

### E2E Tests (Playwright)

**File**: `frontend/e2e/bulk-operations.spec.ts`
**Sections**: 1-4 (12 tests)

**Auth pattern**: `injectAuth(page, identity)` for cookie auth; `x-csrf-token` header for POST/PUT/DELETE mutations.

| # | Test | Assertion |
|---|------|-----------|
| 1 | Select multiple files with checkbox | Checkboxes visible; count badge updates |
| 2 | Bulk delete files | Click Delete; confirm; files removed |
| 3 | Bulk move files to folder | Select; Move to; files in new folder |
| 4 | Select all on page | Select All checkbox; all items checked |
| 5 | Bulk mark conversations read | Select; Mark Read; unread badges cleared |
| 6 | Bulk dismiss alerts | Select; Dismiss; alerts removed |
| 7 | Bulk action toolbar appears on selection | Toolbar with actions visible |
| 8 | Deselect all clears selection | Click Deselect; toolbar hidden |

**Negative tests**: 400 empty selection, 400 exceeds max bulk items (100), 403 bulk delete on shared folder, 404 item not found in batch

**Edge cases**: Mixed success/failure in batch, select items across pages, concurrent bulk ops

### Test Data Requirements

- **DDB seeds**: Files, conversations, and alerts seeded for Alice
- **Test users**: Alice

### CI/Pipeline Considerations

- **Feature flags**: None
- **Serial execution**: Bulk delete tests must verify items are actually removed before asserting
- **Retry safety**: All tests are idempotent; use unique per-run identifiers (`TS` suffix) to avoid cross-run conflicts.

---

## Dependencies & Merge Safety

### Depends On

| Ticket/Component | Reason |
|------------------|--------|
| File manager (existing) | Bulk delete/move endpoints |
| Messages (existing) | Bulk read/delete conversations |
| Alerts (existing) | Bulk dismiss alerts |

### Depended On By

No downstream tickets depend on this feature.

### Merge Strategy: **Independent**

UI patterns with backend batch endpoints. Each module's bulk ops are independent.

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
| VideoReviewQueue selectedIds state | `frontend/src/pages/admin/VideoReviewQueuePage.tsx` | 66 | VERIFIED |
| VideoReviewQueue toggleSelect | `frontend/src/pages/admin/VideoReviewQueuePage.tsx` | 192-199 | VERIFIED |
| VideoReviewQueue selectAll/deselectAll | `frontend/src/pages/admin/VideoReviewQueuePage.tsx` | 201-206 | VERIFIED |
| VideoReviewQueue batch approve mutation | `frontend/src/pages/admin/VideoReviewQueuePage.tsx` | 133-147 | VERIFIED |
| VideoReviewQueue batch reject mutation | `frontend/src/pages/admin/VideoReviewQueuePage.tsx` | 149-175 | VERIFIED |
| VideoReviewQueue floating selection bar | `frontend/src/pages/admin/VideoReviewQueuePage.tsx` | 256-284 | VERIFIED |
| VideoReviewQueue checkbox per video | `frontend/src/pages/admin/VideoReviewQueuePage.tsx` | 306-307 | VERIFIED |
| FilesPage bulk move | `frontend/src/pages/files/FilesPage.tsx` | 867 | VERIFIED |
| useMultiSelect hook | `frontend/src/hooks/useMultiSelect.ts` | exists | **ALREADY IMPLEMENTED** |
| BulkActionBar component | `frontend/src/components/shared/BulkActionBar.tsx` | exists | **ALREADY IMPLEMENTED** |
| Catalog bulk-delete endpoint | `app/routers/catalog.py` | 859-860 | **ALREADY IMPLEMENTED**: `POST /items/bulk-delete` |
| Catalog bulk-update endpoint | `app/routers/catalog.py` | 887-888 | **ALREADY IMPLEMENTED**: `POST /items/bulk-update` |
| Newsfeed bulk-delete endpoint | `app/routers/newsfeed.py` | 5781-5782 | **ALREADY IMPLEMENTED**: `POST /posts/bulk-delete` |
| Newsfeed bulk-archive endpoint | `app/routers/newsfeed.py` | 5809-5810 | **ALREADY IMPLEMENTED**: `POST /posts/bulk-archive` |
| Catalog table handle | `app/core/tables.py` | 159 | VERIFIED |

### Notes

- The `useMultiSelect` hook and `BulkActionBar` component already exist but the VideoReviewQueuePage has NOT been refactored to use them (still uses inline selectedIds/toggleSelect/selectAll/deselectAll at lines 66, 192-206). The refactoring step from this ticket is still pending.
- Backend batch endpoints for both catalog and newsfeed are already implemented (bulk-delete, bulk-update, bulk-archive).
- The catalog endpoint name differs from the ticket spec: actual is `bulk-delete` and `bulk-update` (not `batch-archive`).
