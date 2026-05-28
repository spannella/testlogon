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
 * Displays the selected count, a "Deselect" button, and
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
