import { useMemo } from "react";
import { cn } from "@/lib/utils";
import type { ContentCalendarItem } from "@/api/types";

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

function getMonthDays(year: number, month: number): Date[] {
  const first = new Date(year, month, 1);
  const startDay = first.getDay();
  const days: Date[] = [];
  // Fill in days from previous month
  for (let i = startDay - 1; i >= 0; i--) {
    const d = new Date(year, month, -i);
    days.push(d);
  }
  // Fill in days of current month
  const lastDay = new Date(year, month + 1, 0).getDate();
  for (let i = 1; i <= lastDay; i++) {
    days.push(new Date(year, month, i));
  }
  // Fill in remaining days to complete the grid (6 rows x 7 days)
  while (days.length < 42) {
    const d = new Date(year, month + 1, days.length - startDay - lastDay + 1);
    days.push(d);
  }
  return days;
}

function isSameDay(a: Date, b: Date): boolean {
  return (
    a.getFullYear() === b.getFullYear() &&
    a.getMonth() === b.getMonth() &&
    a.getDate() === b.getDate()
  );
}

const TYPE_COLORS: Record<string, string> = {
  post: "bg-blue-500",
  broadcast: "bg-red-500",
  vod: "bg-violet-500",
};

interface Props {
  anchorDate: Date;
  items: ContentCalendarItem[];
  onDayClick: (date: Date) => void;
  onItemClick: (item: ContentCalendarItem) => void;
}

export function ContentCalendarMonth({ anchorDate, items, onDayClick, onItemClick }: Props) {
  const year = anchorDate.getFullYear();
  const month = anchorDate.getMonth();
  const days = useMemo(() => getMonthDays(year, month), [year, month]);
  const today = new Date();

  function itemsForDay(day: Date): ContentCalendarItem[] {
    return items.filter((item) => {
      const d = new Date(item.scheduled_at * 1000);
      return isSameDay(d, day);
    });
  }

  return (
    <div>
      {/* Day headers */}
      <div className="grid grid-cols-7 border-b">
        {DAYS.map((d) => (
          <div key={d} className="border-r p-2 text-center text-xs font-medium text-muted-foreground">
            {d}
          </div>
        ))}
      </div>

      {/* Day grid */}
      <div className="grid grid-cols-7">
        {days.map((day, idx) => {
          const isCurrentMonth = day.getMonth() === month;
          const isToday = isSameDay(day, today);
          const dayItems = itemsForDay(day);
          return (
            <div
              key={idx}
              className={cn(
                "border-r border-b p-1 min-h-[80px] cursor-pointer hover:bg-muted/30 transition-colors",
                !isCurrentMonth && "text-muted-foreground/40 bg-muted/10",
                isToday && "bg-primary/5",
              )}
              onClick={() => onDayClick(day)}
              data-content-count={dayItems.length}
            >
              <div className={cn(
                "text-xs font-medium mb-1",
                isToday && "rounded-full bg-primary text-primary-foreground w-6 h-6 flex items-center justify-center",
              )}>
                {day.getDate()}
              </div>
              {/* Content dots */}
              <div className="flex flex-wrap gap-0.5">
                {dayItems.slice(0, 4).map((item) => (
                  <div
                    key={`${item.type}-${item.id}`}
                    className={cn("w-2 h-2 rounded-full", TYPE_COLORS[item.type])}
                    title={`${item.title} (${item.type})`}
                    onClick={(e) => {
                      e.stopPropagation();
                      onItemClick(item);
                    }}
                  />
                ))}
                {dayItems.length > 4 && (
                  <span className="text-[9px] text-muted-foreground">+{dayItems.length - 4}</span>
                )}
              </div>
              {/* Show up to 2 item titles */}
              {dayItems.slice(0, 2).map((item) => (
                <div
                  key={`title-${item.type}-${item.id}`}
                  className="text-[9px] truncate mt-0.5"
                  onClick={(e) => {
                    e.stopPropagation();
                    onItemClick(item);
                  }}
                >
                  {item.title}
                </div>
              ))}
            </div>
          );
        })}
      </div>
    </div>
  );
}
