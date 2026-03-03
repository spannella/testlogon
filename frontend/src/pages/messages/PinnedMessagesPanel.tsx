import { useMemo } from "react";
import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Loader2, Pin } from "lucide-react";
import { toast } from "sonner";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { getPinnedMessages, unpinMessage } from "@/api/endpoints/messaging";
import type { ConversationPin, Message, Participant } from "@/api/types";

interface PinnedMessagesPanelProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  conversationId: string;
  participants: Participant[];
  messageById: Map<string, Message>;
  onJumpToMessage: (messageId: string) => void;
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

function previewText(msg?: Message): string {
  if (!msg) return "Message unavailable in current timeline";
  if (msg.kind === "image") return "[Image]";
  if (msg.kind === "file") return "[File]";
  if (msg.kind === "video") return "[Video]";
  if (msg.kind === "audio") return "[Audio]";
  if (msg.is_encrypted) return "[Encrypted message]";
  return (msg.text ?? "").slice(0, 120) || "[Message]";
}

function displayName(userId: string, participants: Participant[]): string {
  const found = participants.find((p) => p.user_id === userId);
  return found?.display_name ?? userId;
}

function PinRow({
  pin,
  participants,
  message,
  conversationId,
  onJumpToMessage,
}: {
  pin: ConversationPin;
  participants: Participant[];
  message?: Message;
  conversationId: string;
  onJumpToMessage: (messageId: string) => void;
}) {
  const queryClient = useQueryClient();

  const unpinMut = useMutation({
    mutationFn: () => unpinMessage(conversationId, pin.message_id),
    onSuccess: () => {
      toast.success("Message unpinned");
      void queryClient.invalidateQueries({ queryKey: ["pinned-messages", conversationId] });
      void queryClient.invalidateQueries({ queryKey: ["conversations"] });
    },
    onError: () => toast.error("Failed to unpin message"),
  });

  return (
    <div className="rounded-lg border border-border bg-card p-3">
      <p className="text-sm">{previewText(message)}</p>
      <p className="mt-1 text-xs text-muted-foreground">Author: {message ? displayName(message.sender_id, participants) : "Unknown"}</p>
      <p className="text-xs text-muted-foreground">Pinned by: {displayName(pin.pinned_by_user_id, participants)}</p>
      <p className="text-xs text-muted-foreground">Pinned at: {formatTs(pin.pinned_at)}</p>
      <div className="mt-3 flex items-center gap-2">
        <Button variant="outline" size="sm" onClick={() => onJumpToMessage(pin.message_id)}>
          Jump to message
        </Button>
        <Button
          variant="ghost"
          size="sm"
          className="text-blue-600 hover:text-blue-700"
          disabled={unpinMut.isPending}
          onClick={() => unpinMut.mutate()}
        >
          {unpinMut.isPending ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : null}
          Unpin
        </Button>
      </div>
    </div>
  );
}

export function PinnedMessagesPanel({
  open,
  onOpenChange,
  conversationId,
  participants,
  messageById,
  onJumpToMessage,
}: PinnedMessagesPanelProps) {
  const query = useInfiniteQuery({
    queryKey: ["pinned-messages", conversationId],
    queryFn: ({ pageParam }) => getPinnedMessages(conversationId, pageParam, 50),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
    enabled: open,
    staleTime: 10_000,
  });

  const allItems = useMemo(() => {
    const merged = query.data?.pages.flatMap((page) => page.items ?? []) ?? [];
    return merged.filter((item) => item.is_active);
  }, [query.data]);

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-96 sm:w-[34rem]">
        <SheetHeader>
          <SheetTitle className="flex items-center gap-2">
            <Pin className="h-4 w-4" />
            Pinned messages
          </SheetTitle>
          <SheetDescription>
            Review active pins in this conversation, then jump to a message or unpin it.
          </SheetDescription>
        </SheetHeader>

        <div className="mt-4 space-y-3 overflow-y-auto">
          {query.isLoading ? (
            Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-28 w-full rounded-lg" />)
          ) : allItems.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">No pinned messages.</p>
          ) : (
            allItems.map((pin) => (
              <PinRow
                key={`${pin.conversation_id}:${pin.message_id}`}
                pin={pin}
                participants={participants}
                message={messageById.get(pin.message_id)}
                conversationId={conversationId}
                onJumpToMessage={onJumpToMessage}
              />
            ))
          )}

          {query.hasNextPage && (
            <div className="pt-2">
              <Button
                variant="ghost"
                size="sm"
                className="w-full"
                onClick={() => query.fetchNextPage()}
                disabled={query.isFetchingNextPage}
              >
                {query.isFetchingNextPage ? "Loading…" : "Load more"}
              </Button>
            </div>
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}
