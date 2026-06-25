import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CalendarClock } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { AvailabilityGrid } from "@/components/shared/AvailabilityGrid";
import { FindDateTimeResult } from "@/pages/messages/FindDateTimeResult";
import {
  getFindDateTime,
  submitFindDateTimeAvailability,
  closeFindDateTime,
} from "@/api/endpoints/messaging";
import type { FindDateTimeAttachment } from "@/api/types";

interface FindDateTimeCardProps {
  stub: FindDateTimeAttachment;
  isOwn: boolean;
}

function fmtDateRange(from: string, to: string): string {
  const f = new Date(`${from}T00:00:00`);
  const t = new Date(`${to}T00:00:00`);
  const opts: Intl.DateTimeFormatOptions = { month: "short", day: "numeric" };
  return `${f.toLocaleDateString(undefined, opts)} – ${t.toLocaleDateString(undefined, opts)}`;
}

export function FindDateTimeCard({ stub, isOwn }: FindDateTimeCardProps) {
  const queryClient = useQueryClient();
  const [gridOpen, setGridOpen] = useState(false);
  const [selected, setSelected] = useState<string[]>([]);

  const { data } = useQuery({
    queryKey: ["find-datetime", stub.poll_id],
    queryFn: () => getFindDateTime(stub.poll_id),
    refetchInterval: stub.status === "open" ? 30000 : false,
  });

  const status = data?.meta.status ?? stub.status;
  const isClosed = status === "closed";

  const submitMut = useMutation({
    mutationFn: (slots: string[]) => submitFindDateTimeAvailability(stub.poll_id, slots),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["find-datetime", stub.poll_id] });
      setGridOpen(false);
      toast.success("Availability submitted");
    },
    onError: () => toast.error("Failed to submit availability"),
  });

  const closeMut = useMutation({
    mutationFn: () => closeFindDateTime(stub.poll_id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["find-datetime", stub.poll_id] });
      toast.success("Poll closed");
    },
    onError: () => toast.error("Failed to close poll"),
  });

  function openGrid() {
    const mine = data?.availabilities.find((a) => a.user_sub === data.meta.creator_sub && isOwn);
    setSelected(mine?.slots ?? []);
    setGridOpen(true);
  }

  return (
    <div className="mt-1 max-w-md space-y-2 rounded-lg border bg-background text-foreground p-3" data-testid="fadt-card">
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <CalendarClock className="h-5 w-5 shrink-0 text-primary/70" />
          <div>
            <p className="text-sm font-medium" data-testid="fadt-title">
              {data?.meta.title ?? stub.title}
            </p>
            <p className="text-xs text-muted-foreground">
              {fmtDateRange(stub.from_date, stub.to_date)} · {stub.start_hour}:00–{stub.end_hour}:00
            </p>
          </div>
        </div>
        <span
          className={
            isClosed
              ? "rounded-full bg-muted px-2 py-0.5 text-xs"
              : "rounded-full bg-blue-100 px-2 py-0.5 text-xs text-blue-700"
          }
        >
          {isClosed ? "Closed" : "Open"}
        </span>
      </div>

      {data && (
        <p className="text-xs text-muted-foreground">
          {data.meta.participant_count}{" "}
          {data.meta.participant_count === 1 ? "participant responded" : "participants responded"}
        </p>
      )}

      {!isClosed && (
        <div className="flex flex-wrap gap-2">
          <Button size="sm" variant="outline" onClick={openGrid}>
            Submit Availability
          </Button>
          {isOwn && (
            <Button
              size="sm"
              variant="secondary"
              onClick={() => closeMut.mutate()}
              disabled={closeMut.isPending}
            >
              Close &amp; Compute
            </Button>
          )}
        </div>
      )}

      {isClosed && data && <FindDateTimeResult data={data} />}

      <Dialog open={gridOpen} onOpenChange={setGridOpen}>
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>Mark your availability</DialogTitle>
          </DialogHeader>
          <AvailabilityGrid
            fromDate={stub.from_date}
            toDate={stub.to_date}
            startHour={stub.start_hour}
            endHour={stub.end_hour}
            slotDurationMinutes={stub.slot_duration_minutes}
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

export default FindDateTimeCard;
