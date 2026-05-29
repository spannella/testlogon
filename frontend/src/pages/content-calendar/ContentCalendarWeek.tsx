import { useMemo, createElement } from "react";
import { cn } from "@/lib/utils";
import { FileText, Radio, Video } from "lucide-react";
import type { ContentCalendarItem, ContentItemType } from "@/api/types";

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const HOURS = Array.from({ length: 24 }, (_, i) => i);

function formatHour(h: number): string {
  if (h === 0) return "12 AM";
  if (h < 12) return `${h} AM`;
  if (h === 12) return "12 PM";
  return `${h - 12} PM`;
}

function getWeekDays(date: Date): Date[] {
  const day = date.getDay();
  const start = new Date(date);
  start.setDate(start.getDate() - day);
  start.setHours(0, 0, 0, 0);
  return Array.from({ length: 7 }, (_, i) => {
    const d = new Date(start);
    d.setDate(d.getDate() + i);
    return d;
  });
}

function isSameDay(a: Date, b: Date): boolean {
  return (
    a.getFullYear() === b.getFullYear() &&
    a.getMonth() === b.getMonth() &&
    a.getDate() === b.getDate()
  );
}

const CONTENT_COLORS: Record<ContentItemType, string> = {
  post: "bg-blue-100 border-blue-400 text-blue-700 dark:bg-blue-950 dark:border-blue-600 dark:text-blue-300",
  broadcast: "bg-red-100 border-red-400 text-red-700 dark:bg-red-950 dark:border-red-600 dark:text-red-300",
  vod: "bg-violet-100 border-violet-400 text-violet-700 dark:bg-violet-950 dark:border-violet-600 dark:text-violet-300",
};

const CONTENT_ICONS: Record<ContentItemType, typeof FileText> = {
  post: FileText,
  broadcast: Radio,
  vod: Video,
};

interface Props {
  anchorDate: Date;
  items: ContentCalendarItem[];
  onDrop: (item: ContentCalendarItem, newTs: number) => void;
  onSlotClick: (ts: number) => void;
  onItemClick: (item: ContentCalendarItem) => void;
}

export function ContentCalendarWeek({
  anchorDate,
  items,
  onDrop,
  onSlotClick,
  onItemClick,
}: Props) {
  const weekDays = useMemo(() => getWeekDays(anchorDate), [anchorDate]);
  const today = new Date();

  function itemsForDayHour(day: Date, hour: number): ContentCalendarItem[] {
    return items.filter((item) => {
      const d = new Date(item.scheduled_at * 1000);
      return isSameDay(d, day) && d.getHours() === hour;
    });
  }

  return (
    <div className="overflow-x-auto">
      {/* Day headers */}
      <div className="grid grid-cols-[60px_repeat(7,1fr)] border-b">
        <div className="border-r p-2" />
        {weekDays.map((day, i) => (
          <div
            key={i}
            className={cn(
              "border-r p-2 text-center text-xs font-medium",
              isSameDay(day, today) && "bg-primary/5 font-bold",
            )}
          >
            <div>{DAYS[i]}</div>
            <div className={cn(
              "text-lg",
              isSameDay(day, today) && "rounded-full bg-primary text-primary-foreground w-8 h-8 flex items-center justify-center mx-auto",
            )}>
              {day.getDate()}
            </div>
          </div>
        ))}
      </div>

      {/* Hour rows */}
      <div className="max-h-[600px] overflow-y-auto">
        {HOURS.map((hour) => (
          <div key={hour} className="grid grid-cols-[60px_repeat(7,1fr)] min-h-[48px]">
            <div className="border-r border-b p-1 text-right text-[10px] text-muted-foreground">
              {formatHour(hour)}
            </div>
            {weekDays.map((day, dayIdx) => {
              const slotItems = itemsForDayHour(day, hour);
              const slotTs = Math.floor(
                new Date(day.getFullYear(), day.getMonth(), day.getDate(), hour).getTime() / 1000,
              );
              return (
                <div
                  key={dayIdx}
                  className={cn(
                    "border-r border-b p-0.5 cursor-pointer hover:bg-muted/30 transition-colors",
                    isSameDay(day, today) && "bg-primary/5",
                  )}
                  onClick={() => {
                    if (slotItems.length === 0) onSlotClick(slotTs);
                  }}
                  onDragOver={(e) => {
                    e.preventDefault();
                    e.dataTransfer.dropEffect = "move";
                  }}
                  onDrop={(e) => {
                    e.preventDefault();
                    try {
                      const item: ContentCalendarItem = JSON.parse(
                        e.dataTransfer.getData("application/json"),
                      );
                      onDrop(item, slotTs);
                    } catch {
                      // ignore malformed drag data
                    }
                  }}
                >
                  {slotItems.map((item) => {
                    const Icon = CONTENT_ICONS[item.type];
                    return (
                      <div
                        key={`${item.type}-${item.id}`}
                        draggable
                        onDragStart={(e) => {
                          e.dataTransfer.setData(
                            "application/json",
                            JSON.stringify(item),
                          );
                          e.dataTransfer.effectAllowed = "move";
                        }}
                        onClick={(e) => {
                          e.stopPropagation();
                          onItemClick(item);
                        }}
                        className={cn(
                          "cursor-grab rounded border-l-4 px-1.5 py-0.5 text-[11px] mb-0.5",
                          "hover:shadow-sm transition-shadow",
                          CONTENT_COLORS[item.type],
                          item.status === "overdue" && "opacity-75 ring-1 ring-amber-400",
                        )}
                        title={`${item.title} (${item.type})`}
                      >
                        <div className="flex items-center gap-1">
                          {createElement(Icon, { className: "h-3 w-3 flex-shrink-0" })}
                          <span className="truncate font-medium">{item.title}</span>
                        </div>
                        {item.status === "overdue" && (
                          <span className="text-amber-600 text-[9px]">Overdue</span>
                        )}
                      </div>
                    );
                  })}
                </div>
              );
            })}
          </div>
        ))}
      </div>
    </div>
  );
}
