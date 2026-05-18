import { useMemo, useState } from "react";
import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { MessageSquareText, Send } from "lucide-react";
import { toast } from "sonner";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import { getThreadMessages, sendTextMessage } from "@/api/endpoints/messaging";
import type { Message } from "@/api/types";
import { MessageBubble } from "./MessageBubble";

interface ThreadPanelProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  conversationId: string;
  anchorMessage: Message | null;
  currentUserId?: string;
}

export function ThreadPanel({
  open,
  onOpenChange,
  conversationId,
  anchorMessage,
  currentUserId,
}: ThreadPanelProps) {
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState("");

  const threadId = anchorMessage?.thread_id;
  const threadRootId = anchorMessage?.thread_root_message_id ?? anchorMessage?.message_id;

  const threadQuery = useInfiniteQuery({
    queryKey: ["thread-messages", threadId],
    queryFn: ({ pageParam }) => {
      if (!threadId) return Promise.resolve({ items: [], next_cursor: null });
      return getThreadMessages(threadId, pageParam, 50);
    },
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
    enabled: open && !!threadId,
    staleTime: 10_000,
  });

  const threadMessages = useMemo(() => {
    const merged = threadQuery.data?.pages.flatMap((p) => p.items ?? []) ?? [];
    return merged.slice().sort((a, b) => a.created_at - b.created_at);
  }, [threadQuery.data]);

  const participantIds = useMemo(
    () => Array.from(new Set(threadMessages.map((m) => m.sender_id).filter(Boolean))),
    [threadMessages],
  );
  const unreadCount = threadQuery.data?.pages?.[0]?.unread_count ?? 0;

  const fallbackReplyTarget = threadMessages[threadMessages.length - 1]?.message_id ?? threadRootId;
  const fallbackThreadRootId = threadMessages[0]?.thread_root_message_id ?? threadRootId;

  const sendReplyMut = useMutation({
    mutationFn: async () => {
      const text = draft.trim();
      if (!text) throw new Error("Type a reply before sending.");
      if (!fallbackReplyTarget) throw new Error("Thread context is unavailable.");
      return sendTextMessage(conversationId, {
        text,
        reply_to_message_id: fallbackReplyTarget,
        parent_message_id: fallbackReplyTarget,
        ...(threadId ? { thread_id: threadId } : {}),
        ...(fallbackThreadRootId ? { thread_root_message_id: fallbackThreadRootId } : {}),
      });
    },
    onSuccess: () => {
      setDraft("");
      toast.success("Reply sent to thread");
      void queryClient.invalidateQueries({ queryKey: ["thread-messages", threadId] });
      void queryClient.invalidateQueries({ queryKey: ["messages", conversationId] });
      void queryClient.invalidateQueries({ queryKey: ["conversations"] });
    },
    onError: (err: Error) => {
      toast.error(err.message || "Failed to send thread reply");
    },
  });

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:w-[40rem] p-0 flex flex-col">
        <SheetHeader className="px-5 pt-5 pb-3 border-b">
          <SheetTitle className="flex items-center gap-2">
            <MessageSquareText className="h-4 w-4" />
            Thread
          </SheetTitle>
          <SheetDescription>
            {anchorMessage?.thread_reply_count
              ? `${anchorMessage.thread_reply_count} replies in this thread`
              : "View and reply in thread context."}
          </SheetDescription>
          {unreadCount > 0 && (
            <p className="text-xs text-muted-foreground">{unreadCount} unread in thread</p>
          )}
          {participantIds.length > 0 && (
            <div className="flex flex-wrap gap-1 pt-1">
              {participantIds.map((userId) => (
                <span key={userId} className="rounded-full border px-2 py-0.5 text-xs text-muted-foreground">
                  {userId}
                </span>
              ))}
            </div>
          )}
        </SheetHeader>

        <div className="flex-1 overflow-y-auto px-4 py-4 space-y-3">
          {threadQuery.isLoading ? (
            Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-24 w-full rounded-xl" />)
          ) : threadMessages.length === 0 ? (
            <p className="py-10 text-center text-sm text-muted-foreground">No messages loaded for this thread.</p>
          ) : (
            threadMessages.map((msg) => (
              <MessageBubble
                key={msg.message_id}
                message={msg}
                isOwn={msg.sender_id === currentUserId}
                conversationId={conversationId}
                replyToMessage={msg.reply_to_message_id ? threadMessages.find((t) => t.message_id === msg.reply_to_message_id) : undefined}
              />
            ))
          )}

          {threadQuery.hasNextPage && (
            <Button
              variant="ghost"
              size="sm"
              className="w-full"
              onClick={() => threadQuery.fetchNextPage()}
              disabled={threadQuery.isFetchingNextPage}
            >
              {threadQuery.isFetchingNextPage ? "Loading…" : "Load older thread messages"}
            </Button>
          )}
        </div>

        <div className="border-t px-4 py-3 space-y-2">
          <Textarea
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="Reply in thread…"
            rows={3}
          />
          <div className="flex justify-end">
            <Button
              type="button"
              onClick={() => sendReplyMut.mutate()}
              disabled={sendReplyMut.isPending || !draft.trim() || !fallbackReplyTarget}
            >
              <Send className="mr-2 h-4 w-4" />
              Send reply
            </Button>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  );
}
