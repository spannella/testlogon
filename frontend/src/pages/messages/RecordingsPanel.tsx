import { useQuery } from "@tanstack/react-query";
import { Download, Video } from "lucide-react";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { getConversationRecordings } from "@/api/endpoints/messaging";
import type { RecordingMetadataOut } from "@/api/endpoints/messaging";
import { isCallRecordingEnabled } from "@/lib/featureFlags";

interface RecordingsPanelProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  conversationId: string;
}

function formatTs(ts: number): string {
  return new Date(ts * 1000).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZoneName: "short",
  });
}

function formatDuration(seconds: number | null): string {
  if (seconds == null) return "—";
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}m ${s}s`;
}

function formatSize(bytes: number | null): string {
  if (bytes == null) return "";
  return ` · ${(bytes / 1_048_576).toFixed(1)} MB`;
}

function RecordingRow({ rec }: { rec: RecordingMetadataOut }) {
  const ready = rec.status === "ready" && !!rec.download_url;
  return (
    <div
      data-testid="recording-item"
      className="flex items-center justify-between gap-3 rounded-lg border border-border bg-card p-3"
    >
      <div className="min-w-0">
        <p className="truncate text-sm font-medium">{formatTs(rec.created_at)}</p>
        <p className="text-xs text-muted-foreground">
          {formatDuration(rec.duration_seconds)}
          {formatSize(rec.file_size_bytes)}
        </p>
        <p className="text-xs capitalize text-muted-foreground">{rec.status}</p>
      </div>
      {ready && (
        <Button size="sm" variant="outline" asChild className="shrink-0">
          <a href={rec.download_url ?? "#"} download aria-label="Download recording">
            <Download className="h-3.5 w-3.5" />
          </a>
        </Button>
      )}
    </div>
  );
}

export function RecordingsPanel({ open, onOpenChange, conversationId }: RecordingsPanelProps) {
  const query = useQuery({
    queryKey: ["recordings", conversationId],
    queryFn: () => getConversationRecordings(conversationId),
    enabled: open && isCallRecordingEnabled(),
    staleTime: 10_000,
  });

  const items = query.data?.items ?? [];

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-96 sm:w-[34rem]">
        <SheetHeader>
          <SheetTitle className="flex items-center gap-2">
            <Video className="h-4 w-4" />
            Call recordings
          </SheetTitle>
          <SheetDescription>
            Recordings of calls in this conversation that you participated in.
          </SheetDescription>
        </SheetHeader>

        <div className="mt-4 space-y-3 overflow-y-auto">
          {query.isLoading ? (
            Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-20 w-full rounded-lg" />)
          ) : items.length === 0 ? (
            <p data-testid="recordings-empty" className="py-8 text-center text-sm text-muted-foreground">
              No recordings for this conversation.
            </p>
          ) : (
            items.map((rec) => <RecordingRow key={rec.recording_id} rec={rec} />)
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}
