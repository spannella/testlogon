import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Clock, Trash2, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { getScheduledMessages, cancelScheduledMessage } from "@/api/endpoints/messaging";
import type { Message } from "@/api/types";

interface ScheduledMessagesProps {
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

function messagePreview(msg: Message): string {
  if (msg.kind === "image") return "[Image]";
  if (msg.kind === "file") return "[File]";
  if (msg.kind === "video") return "[Video]";
  if (msg.kind === "audio") return "[Audio]";
  if (msg.is_encrypted) return "[Encrypted message]";
  return (msg.text ?? "").slice(0, 80) || "[Message]";
}

function ScheduledMessageRow({
  message,
  conversationId,
}: {
  message: Message;
  conversationId: string;
}) {
  const queryClient = useQueryClient();
  const cancelMut = useMutation({
    mutationFn: () => cancelScheduledMessage(conversationId, message.message_id),
    onSuccess: () => {
      toast.success("Scheduled message cancelled");
      void queryClient.invalidateQueries({ queryKey: ["scheduled-messages", conversationId] });
    },
    onError: () => toast.error("Failed to cancel scheduled message"),
  });

  // deliver_at is the scheduled send time; fall back to created_at
  const sendAt = message.deliver_at ?? message.created_at;

  return (
    <div className="flex items-start gap-3 rounded-lg border border-border bg-card p-3">
      <Clock className="mt-0.5 h-4 w-4 shrink-0 text-blue-500" />
      <div className="min-w-0 flex-1">
        <p className="truncate text-sm">{messagePreview(message)}</p>
        <p className="mt-0.5 text-xs text-muted-foreground">Sends: {formatTs(sendAt)}</p>
      </div>
      <Button
        variant="ghost"
        size="icon"
        className="h-7 w-7 shrink-0 text-destructive hover:text-destructive"
        onClick={() => cancelMut.mutate()}
        disabled={cancelMut.isPending}
        aria-label="Cancel scheduled message"
      >
        {cancelMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
      </Button>
    </div>
  );
}

export function ScheduledMessages({ open, onOpenChange, conversationId }: ScheduledMessagesProps) {
  const { data, isLoading } = useQuery({
    queryKey: ["scheduled-messages", conversationId],
    queryFn: () => getScheduledMessages(conversationId),
    enabled: open,
    staleTime: 10_000,
  });

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-80 sm:w-96">
        <SheetHeader>
          <SheetTitle className="flex items-center gap-2">
            <Clock className="h-4 w-4" />
            Scheduled Messages
          </SheetTitle>
        </SheetHeader>

        <div className="mt-4 space-y-3">
          {isLoading ? (
            Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-16 w-full rounded-lg" />)
          ) : !data || data.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">
              No scheduled messages.
            </p>
          ) : (
            data.map((msg) => (
              <ScheduledMessageRow key={msg.message_id} message={msg} conversationId={conversationId} />
            ))
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}
