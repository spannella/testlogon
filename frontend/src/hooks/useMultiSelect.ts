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
