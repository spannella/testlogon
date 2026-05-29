import { AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { ContentCalendarConflict, ContentCalendarItem, ContentItemType } from "@/api/types";

interface Props {
  conflicts: ContentCalendarConflict[];
  items: ContentCalendarItem[];
  onResolve: (itemId: string, itemType: ContentItemType, newTs: number) => void;
}

export function ConflictBanner({ conflicts, items, onResolve }: Props) {
  if (conflicts.length === 0) return null;

  function findItem(id: string, type: string) {
    return items.find((i) => i.id === id && i.type === type);
  }

  function formatTime(ts: number) {
    return new Date(ts * 1000).toLocaleTimeString(undefined, {
      hour: "numeric",
      minute: "2-digit",
    });
  }

  return (
    <div className="rounded-lg border border-amber-300 bg-amber-50 p-4 text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200">
      <div className="flex items-center gap-2 font-semibold mb-2">
        <AlertTriangle className="h-4 w-4" />
        <span>Scheduling Conflicts ({conflicts.length})</span>
      </div>
      <div className="space-y-2">
        {conflicts.slice(0, 3).map((c, idx) => {
          const a = findItem(c.item_a_id, c.item_a_type);
          const b = findItem(c.item_b_id, c.item_b_type);
          if (!a || !b) return null;
          return (
            <div key={idx} className="flex items-center justify-between gap-2 text-sm">
              <span>
                <strong>{a.title}</strong> ({formatTime(a.scheduled_at)}) and{" "}
                <strong>{b.title}</strong> ({formatTime(b.scheduled_at)}) are only{" "}
                {c.gap_minutes} min apart
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  // Push later item 30 min after earlier item
                  const newTs = a.scheduled_at + 30 * 60;
                  onResolve(b.id, b.type as ContentItemType, newTs);
                }}
              >
                Space 30 min apart
              </Button>
            </div>
          );
        })}
        {conflicts.length > 3 && (
          <p className="text-xs">
            + {conflicts.length - 3} more conflicts
          </p>
        )}
      </div>
    </div>
  );
}
