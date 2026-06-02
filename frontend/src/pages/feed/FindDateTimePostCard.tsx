import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CalendarSearch } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { AvailabilityGrid } from "@/components/shared/AvailabilityGrid";
import {
  getPostFindDateTime,
  submitPostAvailability,
  closePostFindDateTime,
} from "@/api/endpoints/newsfeed";
import type { FeedPost } from "@/api/types";

/**
 * FEED-003: Find-a-DateTime newsfeed post card.
 *
 * Reuses the shared AvailabilityGrid (MSG-009) for both submission and the
 * results heat map, and the post-linked FADT endpoints backed by the
 * messaging_find_datetime overlap-computation service.
 */
interface FindDateTimePostCardProps {
  post: FeedPost;
  isOwn: boolean;
}

function fmtDateRange(from: string, to: string): string {
  const f = new Date(`${from}T00:00:00`);
  const t = new Date(`${to}T00:00:00`);
  const opts: Intl.DateTimeFormatOptions = { month: "short", day: "numeric" };
  return `${f.toLocaleDateString(undefined, opts)} – ${t.toLocaleDateString(undefined, opts)}`;
}

function fmtWindow(start: string, end: string): string {
  const s = new Date(start);
  const e = new Date(end);
  const date = s.toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" });
  const st = s.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  const et = e.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  return `${date} ${st}–${et}`;
}

export function FindDateTimePostCard({ post, isOwn }: FindDateTimePostCardProps) {
  const queryClient = useQueryClient();
  const pollId = post.find_datetime_id ?? "";
  const [gridOpen, setGridOpen] = useState(false);
  const [selected, setSelected] = useState<string[]>([]);

  const { data } = useQuery({
    queryKey: ["post-find-datetime", pollId],
    queryFn: () => getPostFindDateTime(pollId),
    enabled: !!pollId,
    refetchInterval: (q) => (q.state.data?.status === "open" ? 30000 : false),
  });

  const status = data?.status ?? post.find_datetime_status ?? "open";
  const isClosed = status === "closed";
  const fromDate = data?.from_date ?? post.find_datetime_from_date ?? "";
  const toDate = data?.to_date ?? post.find_datetime_to_date ?? "";
  const startHour = data?.start_hour ?? post.find_datetime_start_hour ?? 0;
  const endHour = data?.end_hour ?? post.find_datetime_end_hour ?? 24;
  const slotDuration = data?.slot_duration_minutes ?? post.find_datetime_slot_duration_minutes ?? 30;
  const title = data?.title ?? post.find_datetime_title ?? "Find a Time";

  const heatMap = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const av of data?.availabilities ?? []) {
      for (const slot of av.slots) {
        counts[slot] = (counts[slot] ?? 0) + 1;
      }
    }
    return counts;
  }, [data?.availabilities]);

  const submitMut = useMutation({
    mutationFn: (slots: string[]) => submitPostAvailability(pollId, slots),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["post-find-datetime", pollId] });
      setGridOpen(false);
      toast.success("Availability submitted");
    },
    onError: () => toast.error("Failed to submit availability"),
  });

  const closeMut = useMutation({
    mutationFn: () => closePostFindDateTime(pollId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["post-find-datetime", pollId] });
      toast.success("Poll closed");
    },
    onError: () => toast.error("Failed to close poll"),
  });

  function openGrid() {
    const mine = data?.availabilities.find((a) => a.user_sub === post.author_id && isOwn);
    setSelected(mine?.slots ?? []);
    setGridOpen(true);
  }

  if (!pollId) return null;
  const windows = data?.best_windows ?? [];

  return (
    <div
      className="mt-3 space-y-2 rounded-lg border bg-muted/40 p-3"
      data-testid="fadt-post-card"
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <CalendarSearch className="h-5 w-5 shrink-0 text-primary/70" />
          <div>
            <p className="text-sm font-medium" data-testid="fadt-post-title">
              {title}
            </p>
            <p className="text-xs text-muted-foreground">
              {fmtDateRange(fromDate, toDate)} · {startHour}:00–{endHour}:00
            </p>
          </div>
        </div>
        <span
          className={
            isClosed
              ? "rounded-full bg-muted px-2 py-0.5 text-xs"
              : "rounded-full bg-blue-100 px-2 py-0.5 text-xs text-blue-700"
          }
          data-testid="fadt-post-status"
        >
          {isClosed ? "Closed" : "Open"}
        </span>
      </div>

      {data && (
        <p className="text-xs text-muted-foreground" data-testid="fadt-post-participants">
          {data.participant_count}{" "}
          {data.participant_count === 1 ? "participant responded" : "participants responded"}
        </p>
      )}

      {!isClosed && (
        <div className="flex flex-wrap gap-2">
          <Button size="sm" variant="outline" onClick={openGrid} data-testid="fadt-post-submit-btn">
            Submit Availability
          </Button>
          {isOwn && (
            <Button
              size="sm"
              variant="secondary"
              onClick={() => closeMut.mutate()}
              disabled={closeMut.isPending}
              data-testid="fadt-post-close-btn"
            >
              Close &amp; Compute
            </Button>
          )}
        </div>
      )}

      {isClosed && data && (
        <div className="space-y-3" data-testid="fadt-post-result">
          <div className="space-y-1">
            <p className="text-xs font-semibold text-muted-foreground">Best windows</p>
            {windows.length === 0 ? (
              <p className="text-xs text-muted-foreground">No overlapping availability found.</p>
            ) : (
              <ol className="space-y-1">
                {windows.slice(0, 3).map((w, i) => (
                  <li
                    key={`${w.start}-${i}`}
                    className="flex items-center justify-between rounded-md border px-2 py-1 text-xs"
                    data-testid="fadt-post-best-window"
                  >
                    <span className="font-medium">
                      #{i + 1} {fmtWindow(w.start, w.end)}
                    </span>
                    <Badge variant="secondary">
                      {w.count} {w.count === 1 ? "person" : "people"}
                    </Badge>
                  </li>
                ))}
              </ol>
            )}
          </div>
          <div>
            <p className="mb-1 text-xs font-semibold text-muted-foreground">Heat map</p>
            <AvailabilityGrid
              fromDate={fromDate}
              toDate={toDate}
              startHour={startHour}
              endHour={endHour}
              slotDurationMinutes={slotDuration}
              selectedSlots={[]}
              readOnly
              heatMap={heatMap}
              maxParticipants={data.participant_count}
            />
          </div>
        </div>
      )}

      <Dialog open={gridOpen} onOpenChange={setGridOpen}>
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>Mark your availability</DialogTitle>
          </DialogHeader>
          <AvailabilityGrid
            fromDate={fromDate}
            toDate={toDate}
            startHour={startHour}
            endHour={endHour}
            slotDurationMinutes={slotDuration}
            selectedSlots={selected}
            onSlotsChange={setSelected}
          />
          <p className="text-xs text-muted-foreground">{selected.length} slots selected</p>
          <DialogFooter>
            <Button variant="outline" onClick={() => setGridOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={selected.length === 0 || submitMut.isPending}
              onClick={() => submitMut.mutate(selected)}
            >
              Submit
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default FindDateTimePostCard;
