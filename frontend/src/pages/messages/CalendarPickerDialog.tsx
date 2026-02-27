import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { CalendarDays } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { cn } from "@/lib/utils";
import { getCalendars } from "@/api/endpoints/calendar";
import type { SendCalendarShareReq } from "@/api/types";

interface CalendarPickerDialogProps {
  open: boolean;
  onClose: () => void;
  onSelect: (params: SendCalendarShareReq) => void;
}

export function CalendarPickerDialog({ open, onClose, onSelect }: CalendarPickerDialogProps) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [permission, setPermission] = useState<"read" | "write">("read");
  const [includeBookingLink, setIncludeBookingLink] = useState(true);

  const { data: calendars = [], isLoading } = useQuery({
    queryKey: ["calendars"],
    queryFn: () => getCalendars(),
    enabled: open,
  });

  function handleShare() {
    if (!selectedId) return;
    onSelect({ calendar_id: selectedId, permission, include_booking_link: includeBookingLink });
    onClose();
  }

  function handleOpenChange(isOpen: boolean) {
    if (!isOpen) onClose();
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Share a calendar</DialogTitle>
        </DialogHeader>

        <div className="space-y-3 py-2">
          {isLoading && (
            <p className="text-sm text-muted-foreground">Loading calendars…</p>
          )}
          {!isLoading && calendars.length === 0 && (
            <p className="text-sm text-muted-foreground">No calendars found.</p>
          )}
          <div className="max-h-52 overflow-y-auto space-y-1">
            {calendars.map((cal) => (
              <button
                key={cal.calendar_id}
                type="button"
                onClick={() => setSelectedId(cal.calendar_id)}
                className={cn(
                  "w-full flex items-center gap-2 rounded-md px-3 py-2 text-sm text-left transition-colors",
                  selectedId === cal.calendar_id
                    ? "bg-primary text-primary-foreground"
                    : "hover:bg-muted",
                )}
              >
                <CalendarDays className="h-4 w-4 shrink-0" />
                <span className="truncate">{cal.name}</span>
              </button>
            ))}
          </div>

          {/* Permission toggle */}
          <div className="flex gap-2 pt-1">
            <Button
              variant={permission === "read" ? "default" : "outline"}
              size="sm"
              onClick={() => setPermission("read")}
            >
              View only
            </Button>
            <Button
              variant={permission === "write" ? "default" : "outline"}
              size="sm"
              onClick={() => setPermission("write")}
            >
              View + Edit
            </Button>
          </div>

          {/* Booking link checkbox */}
          <label className="flex items-start gap-2 cursor-pointer">
            <input
              type="checkbox"
              className="mt-0.5"
              checked={includeBookingLink}
              onChange={(e) => setIncludeBookingLink(e.target.checked)}
            />
            <span className="text-sm">
              Include booking link — let recipients schedule time with you
            </span>
          </label>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button disabled={!selectedId} onClick={handleShare}>Share</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
