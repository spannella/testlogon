import { createElement } from "react";
import { FileText, Radio, Video, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import type { ContentCalendarItem, ContentItemType } from "@/api/types";

const CONTENT_ICONS: Record<ContentItemType, typeof FileText> = {
  post: FileText,
  broadcast: Radio,
  vod: Video,
};

const TYPE_LABELS: Record<ContentItemType, string> = {
  post: "Post",
  broadcast: "Broadcast",
  vod: "Video",
};

interface Props {
  items: ContentCalendarItem[];
  onItemClick: (item: ContentCalendarItem) => void;
  onCancel: (item: ContentCalendarItem) => void;
}

export function ContentCalendarMobileList({ items, onItemClick, onCancel }: Props) {
  if (items.length === 0) {
    return (
      <div className="p-8 text-center text-muted-foreground">
        <p className="text-sm">No upcoming content scheduled</p>
        <p className="text-xs mt-1">Create a post, broadcast, or video to get started</p>
      </div>
    );
  }

  // Group by date
  const grouped = items.reduce<Record<string, ContentCalendarItem[]>>((acc, item) => {
    const dateStr = new Date(item.scheduled_at * 1000).toLocaleDateString(undefined, {
      weekday: "long",
      month: "short",
      day: "numeric",
    });
    if (!acc[dateStr]) acc[dateStr] = [];
    acc[dateStr].push(item);
    return acc;
  }, {});

  return (
    <div className="divide-y">
      {Object.entries(grouped).map(([dateStr, dayItems]) => (
        <div key={dateStr}>
          <div className="bg-muted/50 px-4 py-2 text-xs font-semibold text-muted-foreground">
            {dateStr}
          </div>
          {dayItems.map((item) => {
            const Icon = CONTENT_ICONS[item.type];
            const time = new Date(item.scheduled_at * 1000).toLocaleTimeString(undefined, {
              hour: "numeric",
              minute: "2-digit",
            });
            return (
              <div
                key={`${item.type}-${item.id}`}
                className="flex items-center gap-3 px-4 py-3 hover:bg-muted/30 cursor-pointer"
                onClick={() => onItemClick(item)}
              >
                <div
                  className="flex h-8 w-8 items-center justify-center rounded-full"
                  style={{ backgroundColor: item.color + "20", color: item.color }}
                >
                  {createElement(Icon, { className: "h-4 w-4" })}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">{item.title}</p>
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <span>{time}</span>
                    <Badge variant="outline" className="text-[10px] px-1 py-0">
                      {TYPE_LABELS[item.type]}
                    </Badge>
                    {item.status === "overdue" && (
                      <Badge variant="destructive" className="text-[10px] px-1 py-0 bg-amber-500">
                        Overdue
                      </Badge>
                    )}
                  </div>
                </div>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8 text-muted-foreground hover:text-destructive"
                  onClick={(e) => {
                    e.stopPropagation();
                    onCancel(item);
                  }}
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              </div>
            );
          })}
        </div>
      ))}
    </div>
  );
}
