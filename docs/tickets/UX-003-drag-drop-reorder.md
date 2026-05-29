# UX-003: Drag-and-Drop Reorder

**Ticket**: UX-003
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: P3 (Nice to Have)
**Estimated effort**: 4-6 days

---

## 1. Executive Summary

<!-- NOTE: This feature is ALREADY FULLY IMPLEMENTED. @dnd-kit/core (^6.3.1), @dnd-kit/sortable (^10.0.0), @dnd-kit/utilities (^3.2.2), @dnd-kit/modifiers (^9.0.0) are installed at package.json:17-20. SortableList.tsx and SortableItem.tsx exist at frontend/src/components/shared/. QuestionnaireBuilderPage.tsx already uses SortableList (line 27, 453). The catalog reorder endpoint exists at catalog.py with position sorting at :392-393, _catalog_item_out at :108,125 includes position field. ProductShelfManager.tsx still uses arrow buttons alongside drag support. -->

Sortable lists across the platform use either native HTML5 `draggable` (questionnaire sections) or arrow buttons (broadcast product shelf). There is no DnD library installed, and the native drag implementation is limited -- it lacks visual feedback, drop targets, accessibility support, and touch device compatibility.

The native HTML5 drag API is notoriously difficult to work with: drag previews are browser-rendered screenshots with no customization, there are no built-in drop indicators, touch devices require entirely separate gesture handling, and keyboard accessibility requires manual implementation from scratch. The questionnaire builder's current drag implementation (`QuestionnaireBuilderPage.tsx`, line 485) demonstrates these limitations -- a user can drag sections but receives no visual cue about where the section will land, the drag does not work on tablets, and keyboard users have no drag equivalent.

This feature introduces `@dnd-kit/core` and `@dnd-kit/sortable` as the standard drag-and-drop library, replaces the existing native drag in QuestionnaireBuilderPage, and extends drag-and-drop reorder to broadcast product shelves, catalog item arrangement, and video gallery playlists. `@dnd-kit` was chosen for its accessibility-first design (keyboard + screen reader support via `KeyboardSensor` and ARIA live regions), lightweight bundle size (~10KB gzipped), native React integration (hooks-based API), and active maintenance. It is the successor to `react-beautiful-dnd` (which is unmaintained as of 2024).

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

**US-1: Questionnaire section reorder with visual feedback**
As a creator building a questionnaire, I want to drag sections to reorder them with a visible ghost overlay showing where the section will land, so that I can intuitively restructure my questionnaire.

Acceptance Criteria:
- Dragging a section shows a semi-transparent ghost overlay of the section being moved.
- A visual drop indicator (colored line or gap) appears between sections to show the target position.
- Dropping the section at the new position triggers the existing reorder API call.
- The drag can be cancelled by pressing Escape or releasing outside the list.
- The existing up/down arrow buttons remain as secondary controls.

**US-2: Broadcast product shelf drag reorder**
As a creator managing a live broadcast product shelf, I want to drag shelf products to set their display order rather than using repetitive up/down arrow clicks.

Acceptance Criteria:
- Product shelf items have a drag handle (grip icon) alongside the existing arrow buttons.
- Dragging a product shows a ghost overlay and drop indicator.
- Dropping the product calls the existing `reorderShelf` mutation.
- Arrow buttons remain functional as a secondary control for accessibility.
- The maximum shelf size constraint (existing `MAX_SHELF` constant) is not affected.

**US-3: Catalog item position management**
As a creator managing my storefront catalog, I want to drag catalog items to set their display order so that I can showcase featured items at the top.

Acceptance Criteria:
- Catalog items in the management view have drag handles.
- Reordering via drag persists the new order to the backend.
- A new `position` field on catalog items controls display order.
- Items without a `position` value are sorted after positioned items.

**US-4: Touch device compatibility**
As a user on a phone or tablet, I want drag-and-drop to work with touch gestures so that I can reorder items without a mouse.

Acceptance Criteria:
- Touch drag activates after a 250ms long-press (to distinguish from scroll).
- During drag, the page does not scroll (scroll lock).
- The ghost overlay follows the user's finger.
- A 5px tolerance prevents accidental activation during normal taps.

**US-5: Keyboard accessibility for drag**
As a keyboard-only user, I want to reorder items using keyboard shortcuts so that drag-and-drop functionality is accessible without a mouse.

Acceptance Criteria:
- Focusing a drag handle and pressing Space activates drag mode.
- Arrow keys move the item up/down within the list.
- Space confirms the new position; Escape cancels.
- Screen readers announce "Item X picked up, position Y of Z" on activation.
- Screen readers announce "Item X dropped, new position Y of Z" on drop.

**US-6: Reusable sortable list component**
As a developer, I want a reusable `SortableList` component so that future sortable surfaces can be implemented consistently without duplicating DnD boilerplate.

Acceptance Criteria:
- `SortableList` accepts generic item types via TypeScript generics.
- `SortableList` handles DndContext, sensors, SortableContext, and DragOverlay internally.
- The consuming component only provides `items`, `getItemId`, `renderItem`, and `onReorder`.
- The component supports a `disabled` prop to prevent drag.

### 2.2 Pain Points

1. **Poor drag UX in questionnaires**: Native HTML5 `draggable` has no ghost preview customization, no drop indicators, no accessibility, and breaks on touch devices.
2. **Arrow buttons are tedious**: The broadcast product shelf requires many clicks to move an item from position 10 to position 1 (9 clicks vs. 1 drag).
3. **No reorder for catalog/gallery**: Catalog items and gallery videos have no position control at all -- items display in creation order.
4. **Inconsistent patterns**: Each sortable list implements its own reorder logic from scratch, leading to different UX patterns and duplicated code.

---

## 3. Current State Analysis

### 3.1 Questionnaire Builder -- Native Drag

`QuestionnaireBuilderPage.tsx` uses native HTML5 `draggable` on section containers (line 485). A `draggingSectionId` state (line 66) tracks the source section. On `onDrop`, sections are reordered by swapping indices and calling the `reorder` function which triggers the `reorderQuestionnaireSections` API endpoint.

The implementation (lines 485-496) is inline JSX with no component extraction:

```typescript
// Line 66: state
const [draggingSectionId, setDraggingSectionId] = React.useState<string | null>(null);

// Lines 485-496: drag handlers on each section div
<div
  key={section.section_id}
  className="rounded-md border p-3 space-y-3 bg-background"
  draggable
  onDragStart={() => setDraggingSectionId(section.section_id)}
  onDragOver={(e) => e.preventDefault()}
  onDrop={async () => {
    if (!draggingSectionId || draggingSectionId === section.section_id) return;
    const from = sections.findIndex((s) => s.section_id === draggingSectionId);
    const to = sections.findIndex((s) => s.section_id === section.section_id);
    if (from < 0 || to < 0) return;
    const ordered = [...sections];
    const [item] = ordered.splice(from, 1);
    if (!item) return;
    ordered.splice(to, 0, item);
    await reorder(ordered);
    setDraggingSectionId(null);
  }}
>
```

The section containers also have a `GripVertical` icon (line 498) for visual affordance and `moveSection` arrow buttons (lines 500-501) for up/down reorder. The `GripVertical` icon is currently decorative -- it is not a drag handle (the entire `div` is draggable).

**Issues with current implementation:**
- No visual ghost preview (browser renders default screenshot)
- No drop indicator between sections
- No keyboard drag support
- No touch support (HTML5 drag does not work on mobile Safari or most mobile browsers)
- The entire section div is draggable, not just the grip handle
- No `aria-roledescription` or ARIA live region announcements

**Citations**:
- `frontend/src/pages/questionnaires/QuestionnaireBuilderPage.tsx:27` -- `import SortableList from "@/components/shared/SortableList"` (native drag already replaced)
- `frontend/src/pages/questionnaires/QuestionnaireBuilderPage.tsx:453` -- `<SortableList` usage
- `frontend/src/pages/questionnaires/QuestionnaireBuilderPage.tsx:465` -- `<GripVertical>` (now a drag handle via SortableList)
- `frontend/src/pages/questionnaires/QuestionnaireBuilderPage.tsx:468-469` -- Arrow buttons for `moveSection(index, -1)` and `moveSection(index, 1)`

### 3.2 Broadcast Product Shelf -- Arrow Buttons

`ProductShelfManager.tsx` uses `handleMoveUp` (line 115) and `handleMoveDown` (line 124) functions that swap adjacent items in the array and call `reorderMut.mutate(newOrder)`. There is no drag support.

```typescript
// Lines 115-131: Arrow button handlers
const handleMoveUp = (index: number) => {
  if (index <= 0) return;
  const newOrder = items.map((i) => i.item_id);
  const tmp = newOrder[index - 1]!;
  newOrder[index - 1] = newOrder[index]!;
  newOrder[index] = tmp;
  reorderMut.mutate(newOrder);
};

const handleMoveDown = (index: number) => {
  if (index >= items.length - 1) return;
  const newOrder = items.map((i) => i.item_id);
  const tmp = newOrder[index]!;
  newOrder[index] = newOrder[index + 1]!;
  newOrder[index + 1] = tmp;
  reorderMut.mutate(newOrder);
};
```

The `reorderMut` mutation (line 92) calls `reorderShelf(sessionId, order)` which POSTs the new order array to the backend. The arrow buttons (lines 218-229) are disabled at the top/bottom of the list and during pending mutations.

**Citations**:
- `frontend/src/pages/broadcast/ProductShelfManager.tsx:95-96` -- `reorderMut` mutation calling `reorderShelf`
- `frontend/src/pages/broadcast/ProductShelfManager.tsx:118-133` -- `handleMoveUp` (:118) / `handleMoveDown` (:127) with array swap
- `frontend/src/pages/broadcast/ProductShelfManager.tsx:239-250` -- Arrow button rendering with disabled states

### 3.3 No DnD Library Installed

The `package.json` does not include `react-dnd`, `@dnd-kit/core`, `react-beautiful-dnd`, or any drag-and-drop library.

**Citations**:
- `frontend/package.json:17-20` -- **OUTDATED**: @dnd-kit IS now installed (`@dnd-kit/core` ^6.3.1, `@dnd-kit/sortable` ^10.0.0, `@dnd-kit/utilities` ^3.2.2, `@dnd-kit/modifiers` ^9.0.0)

### 3.4 Catalog Items -- No Position Control

Catalog items are stored in DynamoDB with `PK` (category) and `SK` (item ID). The `catalog` table (`T.catalog`, tables.py:133) has no `position` or `display_order` attribute. Items are returned from `catalog.py` queries in DynamoDB's default sort order (SK ascending), which is essentially creation order. There is no reorder endpoint.

The catalog router (`app/routers/catalog.py`, line 37) provides CRUD operations but no position management:
- `POST /ui/catalog/categories/{id}/items` -- create item
- `PATCH /ui/catalog/items/{id}` -- update item fields
- `DELETE /ui/catalog/items/{id}` -- delete item
- No `PATCH /ui/catalog/items/reorder` endpoint

**Citations**:
- `app/core/tables.py:159` -- `catalog=ddb.Table(S.catalog_table_name)`
- `app/routers/catalog.py:41` -- Router prefix `/ui/catalog`
- `app/routers/catalog.py:106` -- `_catalog_item_out` function (**now includes position** at :108,:125)
- `app/routers/catalog.py:392-393` -- Position sort already implemented
- `app/routers/catalog.py:404+` -- Reorder endpoint already implemented

### 3.5 Gaps

<!-- NOTE: Items 1, 2, 4, 6 are now RESOLVED. -->

1. ~~No DnD library in the project~~ **RESOLVED**: `@dnd-kit` installed at package.json:17-20
2. ~~Native drag in questionnaires lacks accessibility, visual feedback, and touch support~~ **RESOLVED**: QuestionnaireBuilderPage uses SortableList (:27, :453)
3. Product shelf uses arrow buttons only (no drag) -- may still need drag handles added
4. ~~Catalog items have no `position`/`display_order` field or reorder endpoint~~ **RESOLVED**: position field at catalog.py:108,125; reorder endpoint at :404+; sort at :392-393
5. Gallery playlists have no reorder support
6. ~~No reusable sortable list component~~ **RESOLVED**: SortableList.tsx and SortableItem.tsx exist
7. No ARIA live region announcements for screen readers during drag operations -- may be handled by @dnd-kit

---

## 4. Implementation Plan

### 4.1 Install `@dnd-kit`

```bash
cd frontend && npm install @dnd-kit/core @dnd-kit/sortable @dnd-kit/utilities @dnd-kit/modifiers
```

Packages and their roles:
- `@dnd-kit/core` (~5KB gzipped) -- DndContext, sensors (PointerSensor, KeyboardSensor, TouchSensor), collision detection
- `@dnd-kit/sortable` (~3KB gzipped) -- `useSortable`, `SortableContext`, sort strategies (`verticalListSortingStrategy`)
- `@dnd-kit/utilities` (~1KB gzipped) -- CSS transform utilities (`CSS.Transform.toString`)
- `@dnd-kit/modifiers` (~1KB gzipped) -- `restrictToVerticalAxis`, `restrictToParentElement`

### 4.2 Frontend: Reusable SortableList Component

**New file `frontend/src/components/shared/SortableList.tsx`:**

A generic sortable list wrapper that encapsulates all DnD boilerplate:

```typescript
import React, { useState } from "react";
import {
  DndContext,
  closestCenter,
  KeyboardSensor,
  PointerSensor,
  TouchSensor,
  useSensor,
  useSensors,
  type DragEndEvent,
  type DragStartEvent,
  DragOverlay,
} from "@dnd-kit/core";
import {
  SortableContext,
  sortableKeyboardCoordinates,
  verticalListSortingStrategy,
  arrayMove,
} from "@dnd-kit/sortable";
import { restrictToVerticalAxis } from "@dnd-kit/modifiers";
import SortableItem from "./SortableItem";

export interface SortableListProps<T> {
  /** The items to render in sortable order. */
  items: T[];
  /** Extract a unique string ID from an item. */
  getItemId: (item: T) => string;
  /** Render function for each item. Receives the item, its index, and
   * a dragHandleProps object to spread onto the drag handle element. */
  renderItem: (
    item: T,
    index: number,
    dragHandleProps: Record<string, unknown>,
  ) => React.ReactNode;
  /** Called when an item is dropped at a new position. */
  onReorder: (oldIndex: number, newIndex: number) => void;
  /** If true, drag is disabled and handles are hidden. */
  disabled?: boolean;
  /** Optional: render function for the drag overlay (ghost preview).
   * If not provided, a default semi-transparent clone is shown. */
  renderOverlay?: (item: T) => React.ReactNode;
  /** CSS class for the list container. */
  className?: string;
}

export default function SortableList<T>({
  items,
  getItemId,
  renderItem,
  onReorder,
  disabled = false,
  renderOverlay,
  className,
}: SortableListProps<T>) {
  const [activeId, setActiveId] = useState<string | null>(null);

  const sensors = useSensors(
    useSensor(PointerSensor, {
      activationConstraint: { distance: 8 },
    }),
    useSensor(TouchSensor, {
      activationConstraint: { delay: 250, tolerance: 5 },
    }),
    useSensor(KeyboardSensor, {
      coordinateGetter: sortableKeyboardCoordinates,
    }),
  );

  const handleDragStart = (event: DragStartEvent) => {
    setActiveId(event.active.id as string);
  };

  const handleDragEnd = (event: DragEndEvent) => {
    const { active, over } = event;
    setActiveId(null);

    if (over && active.id !== over.id) {
      const oldIndex = items.findIndex((i) => getItemId(i) === active.id);
      const newIndex = items.findIndex((i) => getItemId(i) === over.id);
      if (oldIndex >= 0 && newIndex >= 0) {
        onReorder(oldIndex, newIndex);
      }
    }
  };

  const activeItem = activeId
    ? items.find((i) => getItemId(i) === activeId)
    : null;

  const itemIds = items.map(getItemId);

  return (
    <DndContext
      sensors={sensors}
      collisionDetection={closestCenter}
      onDragStart={handleDragStart}
      onDragEnd={handleDragEnd}
      modifiers={[restrictToVerticalAxis]}
    >
      <SortableContext items={itemIds} strategy={verticalListSortingStrategy}>
        <div className={className} role="list" aria-label="Sortable list">
          {items.map((item, index) => (
            <SortableItem
              key={getItemId(item)}
              id={getItemId(item)}
              disabled={disabled}
            >
              {(dragHandleProps) => renderItem(item, index, dragHandleProps)}
            </SortableItem>
          ))}
        </div>
      </SortableContext>

      <DragOverlay>
        {activeItem && renderOverlay ? (
          renderOverlay(activeItem)
        ) : activeItem ? (
          <div className="rounded-md border bg-card p-3 opacity-80 shadow-lg">
            {renderItem(
              activeItem,
              items.indexOf(activeItem),
              {},
            )}
          </div>
        ) : null}
      </DragOverlay>
    </DndContext>
  );
}
```

**New file `frontend/src/components/shared/SortableItem.tsx`:**

```typescript
import React from "react";
import { useSortable } from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import { GripVertical } from "lucide-react";

interface SortableItemProps {
  id: string;
  disabled?: boolean;
  children: (dragHandleProps: Record<string, unknown>) => React.ReactNode;
}

export default function SortableItem({
  id,
  disabled = false,
  children,
}: SortableItemProps) {
  const {
    attributes,
    listeners,
    setNodeRef,
    setActivatorNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({ id, disabled });

  const style: React.CSSProperties = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.4 : 1,
    position: "relative" as const,
    zIndex: isDragging ? 50 : "auto",
  };

  const dragHandleProps = disabled
    ? {}
    : {
        ref: setActivatorNodeRef,
        ...listeners,
        ...attributes,
        "aria-roledescription": "sortable",
        role: "button",
        tabIndex: 0,
        style: { cursor: "grab", touchAction: "none" } as React.CSSProperties,
      };

  return (
    <div ref={setNodeRef} style={style} role="listitem">
      {children(dragHandleProps)}
    </div>
  );
}
```

### 4.3 Frontend: Replace Questionnaire Native Drag

Replace the native `draggable` / `onDragStart` / `onDrop` pattern in `QuestionnaireBuilderPage.tsx:485-496` with `SortableList`.

**Changes to `QuestionnaireBuilderPage.tsx`:**

1. Remove `draggingSectionId` state (line 66).
2. Remove `draggable`, `onDragStart`, `onDragOver`, `onDrop` props from the section div (lines 485-496).
3. Wrap the sections list with `SortableList`.
4. Pass the `GripVertical` icon as the drag handle target.
5. The `onReorder` callback calls the existing `reorder` function.

```typescript
// Before (lines 484-496):
{sections.map((section, index) => (
  <div key={section.section_id} className="..." draggable onDragStart={...} onDragOver={...} onDrop={...}>
    <GripVertical className="h-4 w-4 text-muted-foreground" />
    ...
  </div>
))}

// After:
<SortableList
  items={sections}
  getItemId={(s) => s.section_id}
  onReorder={async (oldIndex, newIndex) => {
    const ordered = arrayMove(sections, oldIndex, newIndex);
    await reorder(ordered);
  }}
  renderItem={(section, index, dragHandleProps) => (
    <div className="rounded-md border p-3 space-y-3 bg-background">
      <div className="flex items-center gap-2">
        <span {...dragHandleProps}>
          <GripVertical className="h-4 w-4 text-muted-foreground" />
        </span>
        <Input ... />
        <Button ... onClick={() => moveSection(index, -1)}>↑</Button>
        <Button ... onClick={() => moveSection(index, 1)}>↓</Button>
        ...
      </div>
    </div>
  )}
/>
```

### 4.4 Frontend: Replace Product Shelf Arrow Buttons

Replace `handleMoveUp` / `handleMoveDown` in `ProductShelfManager.tsx:115-131` with `SortableList`. Keep arrow buttons as a secondary control for accessibility, but add drag handles as the primary reorder method.

```typescript
<SortableList
  items={items}
  getItemId={(i) => i.item_id}
  onReorder={(oldIndex, newIndex) => {
    const newOrder = arrayMove(
      items.map((i) => i.item_id),
      oldIndex,
      newIndex,
    );
    reorderMut.mutate(newOrder);
  }}
  disabled={reorderMut.isPending}
  renderItem={(item, idx, dragHandleProps) => (
    <div className="flex items-center gap-2 border rounded p-2">
      <span {...dragHandleProps}>
        <GripVertical className="h-4 w-4 text-muted-foreground" />
      </span>
      {/* existing item content */}
      <Button onClick={() => handleMoveUp(idx)} disabled={idx === 0}>↑</Button>
      <Button onClick={() => handleMoveDown(idx)} disabled={idx === items.length - 1}>↓</Button>
    </div>
  )}
/>
```

### 4.5 Backend: Catalog Item Position

Add a `position` field (integer) to catalog items. The field is stored as a numeric attribute on the catalog DynamoDB record. Items are sorted by `position` (ascending) when retrieved, with unpositioned items (position=null) sorted to the end.

**Model change in `app/models.py`:**

```python
class CatalogReorderReq(BaseModel):
    """Request body for catalog item reorder."""
    item_ids: list[str] = Field(..., min_length=1, max_length=100)
```

**New endpoint in `app/routers/catalog.py`:**

```python
@router.patch("/items/reorder")
async def reorder_catalog_items(
    body: CatalogReorderReq,
    ctx=Depends(require_ui_session),
):
    """Set display order for catalog items.

    Accepts an ordered list of item IDs. Each item's `position` field
    is set to its index in the list (0-based). Items not in the list
    retain their current position.

    Only items owned by the authenticated user are updated.
    Non-owned items are silently skipped.
    """
    user_sub = ctx["user_sub"]
    results = []
    for idx, item_id in enumerate(body.item_ids):
        try:
            # Verify ownership before updating
            item = T.catalog.get_item(
                Key={"PK": f"ITEM#{item_id}", "SK": "META"}
            ).get("Item")
            if not item or item.get("owner_user_id") != user_sub:
                results.append({"item_id": item_id, "ok": False, "error": "not_owner"})
                continue

            T.catalog.update_item(
                Key={"PK": f"ITEM#{item_id}", "SK": "META"},
                UpdateExpression="SET #pos = :pos",
                ExpressionAttributeNames={"#pos": "position"},
                ExpressionAttributeValues={":pos": idx},
            )
            results.append({"item_id": item_id, "ok": True})
        except Exception as e:
            results.append({"item_id": item_id, "ok": False, "error": str(e)})

    return {"ok": True, "results": results}
```

**Modify `_catalog_item_out` to include position (catalog.py:89):**

```python
def _catalog_item_out(item: dict) -> CatalogItemOut:
    return CatalogItemOut(
        # ... existing fields ...
        position=item.get("position"),
    )
```

**Modify catalog list queries to sort by position:**

```python
# After fetching items from DynamoDB, sort by position:
items.sort(key=lambda x: (x.get("position") is None, x.get("position", 0)))
```

### 4.6 Backend: Gallery Playlist Position

If the video gallery hub (VOD-017) has playlist support, add a `PATCH /ui/videos/playlists/{id}/reorder` endpoint. If playlists are not yet implemented, defer this to the playlist feature. The `SortableList` component is ready for use when playlists are built.

### 4.7 Frontend: API Client for Catalog Reorder

**Add to `frontend/src/api/endpoints/catalog.ts`:**

```typescript
export const reorderCatalogItems = (itemIds: string[]): Promise<{ ok: boolean }> =>
  api.patch("/ui/catalog/items/reorder", { item_ids: itemIds }).then((r) => r.data);
```

### 4.8 Touch Support Configuration

`@dnd-kit` supports touch via `TouchSensor` with configurable `activationConstraint`. The `SortableList` component registers both `PointerSensor` (for mouse) and `TouchSensor` (for touch) in the DndContext:

```typescript
const sensors = useSensors(
  useSensor(PointerSensor, {
    activationConstraint: { distance: 8 },  // 8px move threshold
  }),
  useSensor(TouchSensor, {
    activationConstraint: {
      delay: 250,     // 250ms long-press to activate
      tolerance: 5,   // 5px tolerance during delay
    },
  }),
  useSensor(KeyboardSensor, {
    coordinateGetter: sortableKeyboardCoordinates,
  }),
);
```

**Touch UX details:**
- Long-press (250ms) activates drag mode. This prevents accidental drag during scroll.
- During drag, `touch-action: none` on the drag handle prevents the page from scrolling.
- The `restrictToVerticalAxis` modifier ensures the ghost only moves vertically.
- Releasing the finger drops the item at the current position.

### 4.9 Keyboard Accessibility

The `KeyboardSensor` from `@dnd-kit` provides full keyboard support:
- **Focus drag handle** (Tab): Focus ring appears on the handle.
- **Space/Enter**: Picks up the item. Screen reader announces "Picked up item, position X of Y."
- **Arrow Up/Down**: Moves the item in the list. Screen reader announces "Item moved to position X of Y."
- **Space/Enter again**: Drops the item. Screen reader announces "Dropped item, final position X of Y."
- **Escape**: Cancels the drag and returns the item to its original position.

The `useSortable` hook automatically manages `aria-roledescription`, `aria-describedby`, and ARIA live region announcements.

---

## 5. Data Model

### 5.1 Catalog Item Position (New Field)

| Attribute | Type | Description |
|-----------|------|-------------|
| `position` | N (optional) | Display order index (0-based). Items with position are sorted ascending; items without position appear at the end. |

**Example item before:**
```json
{
  "PK": "CAT#cat_abc123",
  "SK": "ITEM#item_xyz",
  "name": "Widget Pro",
  "price_cents": 999,
  "status": "active"
}
```

**Example item after:**
```json
{
  "PK": "CAT#cat_abc123",
  "SK": "ITEM#item_xyz",
  "name": "Widget Pro",
  "price_cents": 999,
  "status": "active",
  "position": 0
}
```

### 5.2 No New Tables

No new DynamoDB tables are required. The `position` field is added to existing catalog item records.

---

## 6. API Design

### 6.1 `PATCH /ui/catalog/items/reorder`

**Method**: PATCH
**Path**: `/ui/catalog/items/reorder`
**Auth**: `require_ui_session` (cookie-based with CSRF)
**Description**: Set display order for catalog items by providing an ordered list of item IDs.

**Request Body:**
```json
{
  "item_ids": ["item_xyz", "item_abc", "item_def"]
}
```

**Validation:**
- `item_ids` must contain at least 1 and at most 100 items.
- Each item_id must be a non-empty string.
- Duplicate item_ids are allowed (last occurrence wins).
- Item IDs not owned by the user are silently skipped.

**Response (200):**
```json
{
  "ok": true,
  "results": [
    { "item_id": "item_xyz", "ok": true },
    { "item_id": "item_abc", "ok": true },
    { "item_id": "item_def", "ok": false, "error": "not_owner" }
  ]
}
```

**Error Responses:**
| Status | Condition | Body |
|--------|-----------|------|
| 401 | Not authenticated | `{"detail": "Not authenticated"}` |
| 422 | Empty item_ids | `{"detail": [{"loc": ["body", "item_ids"], ...}]}` |
| 422 | item_ids exceeds 100 | `{"detail": [{"loc": ["body", "item_ids"], ...}]}` |

**Rate Limit**: 10 requests/minute per user

---

## 7. Frontend Implementation

### 7.1 Component Hierarchy

```
QuestionnaireBuilderPage.tsx
  └── SortableList<QuestionnaireSection>
       ├── SortableItem (section 1)
       │   └── renderItem() → section card with GripVertical handle
       ├── SortableItem (section 2)
       └── DragOverlay → ghost preview

ProductShelfManager.tsx
  └── SortableList<ShelfItem>
       ├── SortableItem (item 1)
       │   └── renderItem() → item card with GripVertical handle + arrow buttons
       └── DragOverlay → ghost preview

CatalogManagementPage.tsx (future)
  └── SortableList<CatalogItem>
       └── ...
```

### 7.2 State Management

No new Zustand stores. The drag state is managed internally by `@dnd-kit`:
- `activeId` (local state in SortableList) -- the currently dragged item ID
- Sensors manage pointer/touch/keyboard state internally
- `DragOverlay` renders the ghost preview based on `activeId`

### 7.3 React Query Integration

| Surface | Query Key | Mutation | Invalidation |
|---------|-----------|----------|-------------|
| Questionnaire sections | `["questionnaire", id, "sections"]` | `reorderQuestionnaireSections` | On success |
| Product shelf | `["broadcast-shelf", sessionId]` | `reorderShelf` | On success |
| Catalog items | `["catalog", categoryId, "items"]` | `reorderCatalogItems` (new) | On success |

### 7.4 Optimistic Updates

For smooth UX, the sortable list should apply the reorder optimistically:

```typescript
onReorder={(oldIndex, newIndex) => {
  // Optimistic: update local state immediately
  const newSections = arrayMove(sections, oldIndex, newIndex);
  setSections(newSections);

  // Persist to backend (revert on error)
  reorderMut.mutate(newSections, {
    onError: () => {
      setSections(sections);  // Revert
      toast.error("Failed to reorder");
    },
  });
}}
```

### 7.5 Responsive Behavior

- **Desktop**: Pointer drag with 8px move threshold. Ghost overlay follows cursor.
- **Tablet**: Touch drag with 250ms long-press. Haptic feedback (if browser supports `navigator.vibrate`).
- **Mobile**: Same as tablet. The drag handle is large enough (44px touch target) per WCAG 2.5.5.

---

## 8. Testing Plan

### 8.1 Unit Tests (Vitest)

**File**: `frontend/src/components/shared/SortableList.test.tsx`

| # | Test Name | Description | Assertion |
|---|-----------|-------------|-----------|
| 1 | `renders all items` | Pass 3 items to SortableList | All 3 items visible in DOM |
| 2 | `calls onReorder on drag-end` | Simulate drag-end event | `onReorder(0, 2)` called |
| 3 | `disabled prop prevents drag` | Set `disabled=true` | Drag handle has no listeners |
| 4 | `keyboard Space activates drag` | Focus handle, press Space | Item enters "dragging" state |
| 5 | `Escape cancels drag` | Start drag, press Escape | Item returns to original position |
| 6 | `renders drag overlay during drag` | Start drag | DragOverlay content visible |
| 7 | `drag handle has correct ARIA attrs` | Render SortableList | Handle has `aria-roledescription="sortable"` |

### 8.2 E2E Tests

**File**: `frontend/e2e/drag-drop-reorder.spec.ts`

| # | Section | Test Name | Assertion |
|---|---------|-----------|-----------|
| 1 | API | Catalog reorder API persists order | PATCH `/ui/catalog/items/reorder`, GET items, verify new order |
| 2 | API | Catalog reorder with invalid item returns partial success | Non-owned item returns `ok: false` |
| 3 | API | Catalog reorder with empty array returns 422 | 422 status code |
| 4 | API | Catalog reorder caps at 100 items | 101-item request rejected with 422 |
| 5 | UI | Questionnaire sections have drag handles | Drag handle element visible on each section |
| 6 | UI | Product shelf has drag handles alongside arrows | GripVertical icon visible on shelf items |
| 7 | UI | Questionnaire section reorder via keyboard | Tab to handle, Space, ArrowDown, Space | Section moves down |

```typescript
// Example E2E test for reorder API
test("Catalog reorder API persists order", async ({ page }) => {
  await injectAuth(page, "alice");

  // Create 3 catalog items
  const items = [];
  for (let i = 0; i < 3; i++) {
    const resp = await page.request.post("/ui/catalog/categories/cat_1/items", {
      headers: { "x-csrf-token": sessions.alice.csrf_token },
      data: { name: `Item ${i}`, price_cents: 100 * (i + 1) },
    });
    items.push((await resp.json()).item.item_id);
  }

  // Reorder: reverse the list
  const reversed = [...items].reverse();
  const reorderResp = await page.request.patch("/ui/catalog/items/reorder", {
    headers: { "x-csrf-token": sessions.alice.csrf_token },
    data: { item_ids: reversed },
  });
  expect(reorderResp.status()).toBe(200);

  // Verify order persisted
  const listResp = await page.request.get("/ui/catalog/categories/cat_1/items");
  const listed = (await listResp.json()).items;
  expect(listed[0].item_id).toBe(reversed[0]);
  expect(listed[2].item_id).toBe(reversed[2]);
});
```

---

## 9. Security Considerations

### 9.1 Authentication

The catalog reorder endpoint uses `require_ui_session` with CSRF enforcement. Only authenticated users can reorder items. Item ownership is verified before each position update.

### 9.2 Input Validation

- `item_ids` is validated by Pydantic: must be a list of strings, min 1, max 100.
- Each item_id is looked up in DynamoDB and ownership is verified.
- Non-owned items are skipped silently (not exposed in error messages to prevent enumeration).

### 9.3 Denial of Service

The 100-item cap on `item_ids` prevents large payloads. Each item update is a separate DynamoDB UpdateItem call. At 100 items, the endpoint performs at most 200 DynamoDB operations (100 GetItem + 100 UpdateItem), completing in ~500ms.

---

## 10. Performance Considerations

### 10.1 Bundle Size Impact

| Package | Size (gzipped) |
|---------|---------------|
| `@dnd-kit/core` | ~5KB |
| `@dnd-kit/sortable` | ~3KB |
| `@dnd-kit/utilities` | ~1KB |
| `@dnd-kit/modifiers` | ~1KB |
| **Total** | **~10KB** |

This is a one-time addition. The packages are tree-shakeable, so only imported modules are bundled.

### 10.2 Render Performance

- `DragOverlay` uses `position: fixed` and CSS transforms for smooth 60fps drag. No React re-renders during drag motion.
- `SortableItem` uses `transform` and `transition` styles (hardware-accelerated) for list reflow.
- Large lists (50+ items) may benefit from virtualization (`react-virtual`), but the current sortable surfaces have at most ~20 items. No virtualization needed initially.

### 10.3 DynamoDB Write Cost

Catalog reorder: 1 WCU per item update. A 20-item reorder costs 20 WCU. With on-demand billing, this is negligible (~$0.000025 per reorder).

---

## 11. Migration / Rollout Plan

### 11.1 Feature Flag

No feature flag needed. The changes are additive:
- `SortableList` is a new component that does not affect existing behavior until it is used.
- The questionnaire and product shelf changes are direct replacements of existing UX (native drag / arrow buttons).
- The catalog reorder endpoint is new and does not affect existing catalog CRUD.

### 11.2 Backward Compatibility

- Questionnaire section reorder uses the same backend API (`reorderQuestionnaireSections`).
- Product shelf reorder uses the same backend API (`reorderShelf`).
- Arrow buttons are retained alongside drag handles for backward compatibility.
- Catalog items without a `position` attribute are sorted after positioned items.

### 11.3 Rollout Steps

1. Install `@dnd-kit` packages.
2. Create `SortableList.tsx` and `SortableItem.tsx`.
3. Replace questionnaire native drag with `SortableList`.
4. Add drag handles to product shelf alongside arrow buttons.
5. Add catalog reorder endpoint and frontend integration.
6. Write E2E tests.

---

## 12. Acceptance Criteria

1. `@dnd-kit/core` and `@dnd-kit/sortable` are installed and used for all sortable lists.
2. Questionnaire sections are reorderable via drag with a visible ghost overlay (replacing native `draggable`).
3. A drop indicator (colored line or gap) shows the target position during drag.
4. Broadcast product shelf items are reorderable via drag (arrow buttons retained as secondary).
5. Catalog items have a `position` field and are reorderable via drag in the catalog management UI.
6. `PATCH /ui/catalog/items/reorder` accepts an ordered list of item IDs and sets positions.
7. Drag works on touch devices with long-press activation (250ms delay, 5px tolerance).
8. Keyboard reorder (Space to pick up, Arrow keys to move, Space to drop, Escape to cancel) works for all sortable lists.
9. Screen readers announce drag state changes via ARIA live regions.
10. A reusable `SortableList` component is available for future sortable surfaces.
11. All existing questionnaire and product shelf E2E tests continue to pass.

---

## 13. Dependencies

### 13.1 External Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `@dnd-kit/core` | `^6.1.0` | DnD context, sensors, collision detection |
| `@dnd-kit/sortable` | `^8.0.0` | Sortable-specific hooks and strategies |
| `@dnd-kit/utilities` | `^3.2.0` | CSS transform utilities |
| `@dnd-kit/modifiers` | `^7.0.0` | Axis restriction modifiers |

### 13.2 Internal Dependencies

- Questionnaire reorder API (`reorderQuestionnaireSections`) -- already exists.
- Product shelf reorder API (`reorderShelf`) -- already exists.
- Catalog table (`T.catalog`) -- already exists.

### 13.3 Related Tickets

- **VOD-017 (Video Gallery Hub)**: Gallery playlists will use `SortableList` when implemented.
- **UX-004 (Bulk Operations)**: Bulk selection and drag-to-reorder are complementary but independent.

---

## 14. Open Questions / Risks

1. **Catalog item ownership model**: The current catalog PK pattern uses `CAT#{category_id}` as PK and `ITEM#{item_id}` as SK. The reorder endpoint needs to verify ownership. If the catalog item does not store `owner_user_id`, ownership verification requires a category-level lookup. Verify the catalog item schema before implementation.

2. **Gallery playlist reorder**: VOD-017 may not have playlist support yet. Defer gallery reorder to when playlists are built. The `SortableList` component is ready for use.

3. **Large list performance**: If a catalog category has 100+ items, the reorder endpoint performs 100+ sequential DynamoDB UpdateItem calls. Consider `BatchWriteItem` for performance (but BatchWriteItem does not support UpdateItem -- only PutItem and DeleteItem). Alternative: store position in a separate "positions" record as a map or list.

4. **Concurrent reorder conflict**: If two users reorder the same list simultaneously, the last write wins. For questionnaires and product shelves (single-owner), this is not an issue. For shared catalogs (if ever supported), consider optimistic locking with a version counter.

---

## 15. Files to Create

| File | Purpose |
|------|---------|
| `frontend/src/components/shared/SortableList.tsx` | Generic sortable list wrapper with DndContext, sensors, DragOverlay |
| `frontend/src/components/shared/SortableItem.tsx` | Individual sortable item with useSortable hook |
| `frontend/src/components/shared/SortableList.test.tsx` | Unit tests for SortableList |
| `frontend/e2e/drag-drop-reorder.spec.ts` | E2E tests |

## 16. Files to Modify

| File | Change |
|------|--------|
| `frontend/package.json` | Add `@dnd-kit/core`, `@dnd-kit/sortable`, `@dnd-kit/utilities`, `@dnd-kit/modifiers` |
| `frontend/src/pages/questionnaires/QuestionnaireBuilderPage.tsx` | Replace native `draggable` (lines 66, 485-496) with `SortableList`; remove `draggingSectionId` state |
| `frontend/src/pages/broadcast/ProductShelfManager.tsx` | Add `SortableList` wrapper; keep arrow buttons alongside drag handles |
| `app/routers/catalog.py` | Add `PATCH /items/reorder` endpoint; modify item listing to sort by `position` |
| `app/models.py` | Add `CatalogReorderReq` model |
| `frontend/src/api/endpoints/catalog.ts` | Add `reorderCatalogItems` function |

---


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_drag_drop_reorder.py`

| # | Function | Assertion |
|---|----------|-----------|
| 1 | `test_reorder_files_updates_sort_order` | Reorder files updates sort order verified |
| 2 | `test_reorder_sidebar_items_persists` | Reorder sidebar items persists verified |
| 3 | `test_drag_between_folders` | Drag between folders verified |
| 4 | `test_reorder_with_invalid_index` | Reorder with invalid index verified |
| 5 | `test_concurrent_reorder_conflict` | Concurrent reorder conflict verified |
| 6 | `test_reorder_preserves_other_metadata` | Reorder preserves other metadata verified |

**Mocking**: All DynamoDB tables mocked via `moto`; profile lookups patched via `unittest.mock.patch`.

### Integration Tests

1. Drag file to new position -> PATCH order -> GET returns new order
2. Drag sidebar item -> order saved to profile preferences -> reload preserves order
3. Drag file between folders -> parent_id updated + sort_order set

### E2E Tests (Playwright)

**File**: `frontend/e2e/drag-drop-reorder.spec.ts`
**Sections**: 1-3 (10 tests)

**Auth pattern**: `injectAuth(page, identity)` for cookie auth; `x-csrf-token` header for POST/PUT/DELETE mutations.

| # | Test | Assertion |
|---|------|-----------|
| 1 | Drag file to reorder | Drag handle; drop at new position; order persisted |
| 2 | Drag sidebar item | Drag nav item; new position saved |
| 3 | Drag between folders | File moved to target folder |
| 4 | Undo reorder | Ctrl+Z reverts to previous order |
| 5 | Keyboard reorder | Alt+Arrow keys move selected item |
| 6 | Reorder persists on reload | Reload page; order unchanged |

**Negative tests**: 400 invalid target index, 404 item not found, 403 reorder in read-only folder

**Edge cases**: Drag to same position (no-op), rapid successive drags, drag during upload

### Test Data Requirements

- **DDB seeds**: Files in file manager with sort_order; sidebar preferences
- **Test users**: Alice

### CI/Pipeline Considerations

- **Feature flags**: None
- **Serial execution**: Drag tests use Playwright mouse events which are order-sensitive
- **Retry safety**: All tests are idempotent; use unique per-run identifiers (`TS` suffix) to avoid cross-run conflicts.

---

## Dependencies & Merge Safety

### Depends On

| Ticket/Component | Reason |
|------------------|--------|
| File manager (existing) | Node ordering in filemanager.py |
| Sidebar (existing) | Navigation item ordering |

### Depended On By

No downstream tickets depend on this feature.

### Merge Strategy: **Independent**

UI enhancement with backend order persistence. No schema migration.

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
| Native draggable on questionnaire sections | `frontend/src/pages/questionnaires/QuestionnaireBuilderPage.tsx` | -- | **OUTDATED**: Native drag replaced by SortableList (imported at :27, used at :453) |
| GripVertical icon | `frontend/src/pages/questionnaires/QuestionnaireBuilderPage.tsx` | 465 | VERIFIED (now a drag handle, not decorative) |
| Arrow buttons on sections | `frontend/src/pages/questionnaires/QuestionnaireBuilderPage.tsx` | 468-469 | VERIFIED: `moveSection(index, -1)` and `moveSection(index, 1)` |
| Arrow buttons on product shelf | `frontend/src/pages/broadcast/ProductShelfManager.tsx` | 118-133 | VERIFIED: `handleMoveUp` at :118, `handleMoveDown` at :127 |
| reorderMut in ProductShelfManager | `frontend/src/pages/broadcast/ProductShelfManager.tsx` | 95-96 | VERIFIED |
| Arrow button disabled states | `frontend/src/pages/broadcast/ProductShelfManager.tsx` | 239-250 | VERIFIED |
| @dnd-kit installed | `frontend/package.json` | 17-20 | **ALREADY IMPLEMENTED**: `@dnd-kit/core` ^6.3.1, `@dnd-kit/sortable` ^10.0.0, `@dnd-kit/utilities` ^3.2.2, `@dnd-kit/modifiers` ^9.0.0 |
| SortableList component | `frontend/src/components/shared/SortableList.tsx` | exists | **ALREADY IMPLEMENTED** |
| SortableItem component | `frontend/src/components/shared/SortableItem.tsx` | exists | **ALREADY IMPLEMENTED** |
| Catalog table handle | `app/core/tables.py` | 159 | VERIFIED: `catalog=ddb.Table(S.catalog_table_name)` |
| Catalog router prefix | `app/routers/catalog.py` | 41 | VERIFIED: `prefix="/ui/catalog"` |
| _catalog_item_out function | `app/routers/catalog.py` | 106 | **ALREADY INCLUDES position**: position at :108,125 |
| Catalog position sort | `app/routers/catalog.py` | 392-393 | **ALREADY IMPLEMENTED**: items sorted by position |
| Catalog reorder endpoint | `app/routers/catalog.py` | 404+ | **ALREADY IMPLEMENTED**: PATCH items/reorder |
