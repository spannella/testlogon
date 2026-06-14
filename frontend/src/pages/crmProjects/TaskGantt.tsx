import { useMemo } from "react";
import { Flag } from "lucide-react";

import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import type { CrmProjectTaskModel } from "@/api/endpoints/crmProjects";
import { fmtDate } from "./projectHelpers";

const DAY = 86400;

/**
 * Lightweight gantt-style visualization: each task occupies a horizontal bar
 * positioned relative to the project's overall date window. Tasks without
 * dates are listed but not bar-positioned.
 */
export function TaskGantt({ tasks }: { tasks: CrmProjectTaskModel[] }) {
  const { minTs, span, dated } = useMemo(() => {
    const withDates = tasks.filter((t) => t.start_date != null);
    const starts = withDates.map((t) => t.start_date as number);
    const ends = withDates.map(
      (t) => t.end_date ?? (t.start_date as number) + t.duration_days * DAY,
    );
    const lo = starts.length ? Math.min(...starts) : 0;
    const hi = ends.length ? Math.max(...ends) : lo + DAY;
    return {
      minTs: lo,
      span: Math.max(hi - lo, DAY),
      dated: withDates.length > 0,
    };
  }, [tasks]);

  if (tasks.length === 0) {
    return (
      <p className="py-8 text-center text-sm text-muted-foreground">
        No tasks to chart yet.
      </p>
    );
  }

  return (
    <div className="space-y-2">
      {tasks.map((t) => {
        const start = t.start_date ?? null;
        const end = t.end_date ?? (start != null ? start + t.duration_days * DAY : null);
        const hasBar = dated && start != null && end != null;
        const left = hasBar ? ((start! - minTs) / span) * 100 : 0;
        const width = hasBar ? Math.max(((end! - start!) / span) * 100, 2) : 0;

        return (
          <div
            key={t.id}
            className="grid grid-cols-[minmax(0,1fr)_2fr] items-center gap-3 rounded-md border p-2"
          >
            <div className="min-w-0">
              <div className="flex items-center gap-1.5">
                {t.is_milestone && <Flag className="h-3.5 w-3.5 text-amber-500" />}
                <span className="truncate text-sm font-medium">{t.name}</span>
              </div>
              <p className="text-xs text-muted-foreground">
                {fmtDate(t.start_date)} – {fmtDate(t.end_date)} · {t.duration_days}d
              </p>
            </div>
            <div className="relative h-6 rounded bg-muted/40">
              {hasBar ? (
                <div
                  className="absolute top-0 flex h-6 items-center justify-end rounded bg-primary/70 px-1.5"
                  style={{ left: `${left}%`, width: `${width}%` }}
                  title={`${t.percent_complete}% complete`}
                >
                  <span className="text-[10px] font-medium text-primary-foreground">
                    {t.percent_complete}%
                  </span>
                </div>
              ) : (
                <div className="absolute inset-0 flex items-center px-2">
                  <Badge variant="outline" className="text-[10px]">
                    no schedule
                  </Badge>
                  <div className="ml-2 flex-1">
                    <Progress value={t.percent_complete} className="h-1.5" />
                  </div>
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
