import React from "react";
import { useSortable } from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";

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
