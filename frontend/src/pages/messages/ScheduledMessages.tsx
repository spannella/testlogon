import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Clock, Trash2, Loader2, Pencil, Check, X } from "lucide-react";
import { toast } from "sonner";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { getScheduledMessages, cancelScheduledMessage, editScheduledMessage } from "@/api/endpoints/messaging";
import type { Message } from "@/api/types";

// Format an epoch-seconds ts as the value a <input type="datetime-local"> expects
// (local "YYYY-MM-DDTHH:mm"), accounting for the local tz offset.
function toDatetimeLocalValue(ts: number): string {
  const d = new Date(ts * 1000);
  const off = d.getTimezoneOffset() * 60000;
  return new Date(d.getTime() - off).toISOString().slice(0, 16);
}

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
  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["scheduled-messages", conversationId] });

  // deliver_at is the scheduled send time; fall back to created_at
  const sendAt = message.deliver_at ?? message.created_at;

  const [editing, setEditing] = useState(false);
  // Only text-bearing kinds can have their text edited; all can be rescheduled.
  const textEditable =
    message.kind === "text" ||
    message.kind === "image" ||
    message.kind === "gallery" ||
    message.kind === "file" ||
    message.kind === "audio" ||
    message.kind === "video" ||
    message.kind === "file_share" ||
    message.kind === "video_share";
  const [editText, setEditText] = useState(message.text ?? "");
  const [editWhen, setEditWhen] = useState(toDatetimeLocalValue(sendAt));

  const cancelMut = useMutation({
    mutationFn: () => cancelScheduledMessage(conversationId, message.message_id),
    onSuccess: () => {
      toast.success("Scheduled message cancelled");
      void invalidate();
    },
    onError: () => toast.error("Failed to cancel scheduled message"),
  });

  const editMut = useMutation({
    mutationFn: () => {
      const whenMs = new Date(editWhen).getTime();
      return editScheduledMessage(conversationId, message.message_id, {
        text: textEditable && !message.is_encrypted ? editText : undefined,
        send_at: isNaN(whenMs) ? undefined : Math.floor(whenMs / 1000),
        send_at_tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
      });
    },
    onSuccess: () => {
      toast.success("Scheduled message updated");
      setEditing(false);
      void invalidate();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to update scheduled message"),
  });

  if (editing) {
    return (
      <div className="space-y-2 rounded-lg border border-border bg-card p-3">
        {textEditable && !message.is_encrypted && (
          <textarea
            className="w-full rounded border border-input bg-background p-2 text-sm"
            rows={2}
            value={editText}
            onChange={(e) => setEditText(e.target.value)}
            placeholder="Message text"
          />
        )}
        <div className="flex flex-col gap-1">
          <label className="text-xs text-muted-foreground">Sends at</label>
          <input
            type="datetime-local"
            className="rounded border border-input bg-background px-2 py-1 text-sm"
            value={editWhen}
            onChange={(e) => setEditWhen(e.target.value)}
          />
        </div>
        <div className="flex justify-end gap-2">
          <Button variant="ghost" size="sm" onClick={() => setEditing(false)} disabled={editMut.isPending}>
            <X className="mr-1 h-3.5 w-3.5" /> Cancel
          </Button>
          <Button size="sm" onClick={() => editMut.mutate()} disabled={editMut.isPending}>
            {editMut.isPending ? <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" /> : <Check className="mr-1 h-3.5 w-3.5" />}
            Save
          </Button>
        </div>
      </div>
    );
  }

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
        className="h-7 w-7 shrink-0"
        onClick={() => {
          setEditText(message.text ?? "");
          setEditWhen(toDatetimeLocalValue(sendAt));
          setEditing(true);
        }}
        aria-label="Edit scheduled message"
      >
        <Pencil className="h-3.5 w-3.5" />
      </Button>
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
    // Keep the list fresh so a message that gets delivered drops off promptly
    // (the SSE thread stream also invalidates this key from ConversationView).
    refetchInterval: open ? 15_000 : false,
  });

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-80 sm:w-96" onInteractOutside={(e) => e.preventDefault()}>
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
