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
