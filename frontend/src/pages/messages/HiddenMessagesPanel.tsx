import { useMemo } from "react";
import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { EyeOff, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { getHiddenMessages, unhideMessage } from "@/api/endpoints/messaging";
import type { Message } from "@/api/types";

interface HiddenMessagesPanelProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  conversationId: string;
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

function messagePreview(msg: Message): string {
  if (msg.kind === "image") return "[Image]";
  if (msg.kind === "file") return "[File]";
  if (msg.kind === "video") return "[Video]";
  if (msg.kind === "audio") return "[Audio]";
  if (msg.is_encrypted) return "[Encrypted message]";
  return (msg.text ?? "").slice(0, 120) || "[Message]";
}

function HiddenMessageRow({
  message,
  conversationId,
  onJumpToMessage,
}: {
  message: Message;
  conversationId: string;
  onJumpToMessage: (messageId: string) => void;
}) {
  const queryClient = useQueryClient();

  const unhideMut = useMutation({
    mutationFn: () => unhideMessage(conversationId, message.message_id),
    onSuccess: () => {
      toast.success("Message unhidden");
      void queryClient.invalidateQueries({ queryKey: ["hidden-messages", conversationId] });
      void queryClient.invalidateQueries({ queryKey: ["messages", conversationId] });
    },
    onError: () => toast.error("Failed to unhide message"),
  });

  return (
    <div className="rounded-lg border border-border bg-card p-3">
      <p className="text-sm">{messagePreview(message)}</p>
      <p className="mt-1 text-xs text-muted-foreground">Sent: {formatTs(message.created_at)}</p>
      <div className="mt-3 flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={() => onJumpToMessage(message.message_id)}
        >
          Jump to original position
        </Button>
        <Button
          variant="ghost"
          size="sm"
          className="text-blue-600 hover:text-blue-700"
          disabled={unhideMut.isPending}
          onClick={() => unhideMut.mutate()}
        >
          {unhideMut.isPending ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : null}
          Unhide
        </Button>
      </div>
    </div>
  );
}

export function HiddenMessagesPanel({
  open,
  onOpenChange,
  conversationId,
  onJumpToMessage,
}: HiddenMessagesPanelProps) {
  const query = useInfiniteQuery({
    queryKey: ["hidden-messages", conversationId],
    queryFn: ({ pageParam }) => getHiddenMessages(conversationId, pageParam, 50),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
    enabled: open,
    staleTime: 10_000,
  });

  const allItems = useMemo(() => {
    const merged = query.data?.pages.flatMap((page) => page.items ?? []) ?? [];
    return merged.slice().sort((a, b) => a.created_at - b.created_at);
  }, [query.data]);

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-96 sm:w-[34rem]">
        <SheetHeader>
          <SheetTitle className="flex items-center gap-2">
            <EyeOff className="h-4 w-4" />
            Hidden Messages
          </SheetTitle>
          <SheetDescription>
            Review messages hidden only for your account, then unhide or jump to their original position.
          </SheetDescription>
        </SheetHeader>

        <div className="mt-4 space-y-3 overflow-y-auto">
          {query.isLoading ? (
            Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-24 w-full rounded-lg" />)
          ) : allItems.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">No hidden messages.</p>
          ) : (
            allItems.map((msg) => (
              <HiddenMessageRow
                key={msg.message_id}
                message={msg}
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
