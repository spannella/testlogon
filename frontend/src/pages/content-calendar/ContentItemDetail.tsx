import { createElement } from "react";
import { FileText, Radio, Video, Clock, Trash2 } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import type { ContentCalendarItem, ContentItemType } from "@/api/types";

const CONTENT_ICONS: Record<ContentItemType, typeof FileText> = {
  post: FileText,
  broadcast: Radio,
  vod: Video,
};

const TYPE_LABELS: Record<ContentItemType, string> = {
  post: "Scheduled Post",
  broadcast: "Scheduled Broadcast",
  vod: "Scheduled Video Release",
};

interface Props {
  item: ContentCalendarItem;
  open: boolean;
  onClose: () => void;
  onCancel: () => void;
  onReschedule: (newTs: number) => void;
}

export function ContentItemDetail({ item, open, onClose, onCancel, onReschedule: _onReschedule }: Props) {
  const Icon = CONTENT_ICONS[item.type];
  const scheduledDate = new Date(item.scheduled_at * 1000);

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            {createElement(Icon, { className: "h-5 w-5", style: { color: item.color } })}
            {TYPE_LABELS[item.type]}
          </DialogTitle>
          <DialogDescription>
            View and manage this scheduled item
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {/* Title */}
          <div>
            <p className="text-sm font-medium text-muted-foreground">Title</p>
            <p className="text-sm">{item.title}</p>
          </div>

          {/* Scheduled Time */}
          <div>
            <p className="text-sm font-medium text-muted-foreground">Scheduled For</p>
            <div className="flex items-center gap-2">
              <Clock className="h-4 w-4 text-muted-foreground" />
              <p className="text-sm">
                {scheduledDate.toLocaleString(undefined, {
                  weekday: "long",
                  year: "numeric",
                  month: "long",
                  day: "numeric",
                  hour: "numeric",
                  minute: "2-digit",
                })}
              </p>
            </div>
            {item.timezone && (
              <p className="text-xs text-muted-foreground mt-1">Timezone: {item.timezone}</p>
            )}
          </div>

          {/* Status */}
          <div>
            <p className="text-sm font-medium text-muted-foreground">Status</p>
            <Badge
              variant={item.status === "overdue" ? "destructive" : "outline"}
              className={item.status === "overdue" ? "bg-amber-500" : ""}
            >
              {item.status}
            </Badge>
          </div>

          {/* Type-specific details */}
          {item.type === "post" && (
            <div className="space-y-1">
              {item.has_images && (
                <p className="text-xs text-muted-foreground">Contains images</p>
              )}
              {item.has_video && (
                <p className="text-xs text-muted-foreground">Contains video</p>
              )}
              {item.locked && (
                <p className="text-xs text-muted-foreground">
                  Locked (${((item.unlock_price_cents ?? 0) / 100).toFixed(2)})
                </p>
              )}
            </div>
          )}

          {item.type === "broadcast" && item.description && (
            <div>
              <p className="text-sm font-medium text-muted-foreground">Description</p>
              <p className="text-sm">{item.description}</p>
            </div>
          )}

          {item.type === "vod" && item.duration_seconds != null && (
            <div>
              <p className="text-sm font-medium text-muted-foreground">Duration</p>
              <p className="text-sm">
                {Math.floor(item.duration_seconds / 60)}:{String(Math.floor(item.duration_seconds % 60)).padStart(2, "0")}
              </p>
            </div>
          )}
        </div>

        <DialogFooter className="flex gap-2 sm:justify-between">
          <Button
            variant="destructive"
            size="sm"
            onClick={onCancel}
            className="gap-1"
          >
            <Trash2 className="h-3.5 w-3.5" />
            Cancel Item
          </Button>
          <Button variant="outline" size="sm" onClick={onClose}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
