import * as React from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Users } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import {
  getMessages,
  sendTextMessage,
  sendImageMessage,
  markRead,
} from "@/api/endpoints/messaging";
import { useAuthStore } from "@/stores/authStore";
import type { Conversation, Message } from "@/api/types";
import { MessageBubble } from "./MessageBubble";
import { ComposeBar } from "./ComposeBar";
import { PresenceDot } from "./PresenceDot";
import { TypingIndicator, useTypingSignal } from "./TypingIndicator";

interface ConversationViewProps {
  conversation: Conversation;
  onBack?: () => void;
}

export function ConversationView({ conversation, onBack }: ConversationViewProps) {
  const userId = useAuthStore((s) => s.userId);
  const queryClient = useQueryClient();
  const scrollRef = React.useRef<HTMLDivElement>(null);
  const [hasAutoScrolled, setHasAutoScrolled] = React.useState(false);

  const convoId = conversation.conversation_id;
  const isGroup = conversation.type === "group";

  // ── Messages query ──────────────────────────────────────────────

  const { data, isLoading, fetchNextPage, hasNextPage, isFetchingNextPage } =
    useMessagesQuery(convoId);

  const allMessages = React.useMemo(() => {
    if (!data?.pages) return [];
    // Pages come newest-first from the API; reverse to display oldest at top
    const msgs: Message[] = [];
    for (let i = data.pages.length - 1; i >= 0; i--) {
      const page = data.pages[i];
      if (page) msgs.push(...(page.messages ?? []));
    }
    return msgs;
  }, [data]);

  // ── Auto-scroll to bottom on new messages ───────────────────────

  React.useEffect(() => {
    if (allMessages.length > 0 && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
      setHasAutoScrolled(true);
    }
  }, [allMessages.length, hasAutoScrolled]);

  // ── Mark read ──────────────────────────────────────────────────

  React.useEffect(() => {
    const lastMsg = allMessages[allMessages.length - 1];
    if (lastMsg && (conversation.unread_count ?? 0) > 0) {
      markRead(convoId, lastMsg.message_id).catch(() => {});
    }
  }, [convoId, allMessages, conversation.unread_count]);

  // ── Send mutations ─────────────────────────────────────────────

  const sendText = useMutation({
    mutationFn: (body: string) => sendTextMessage(convoId, { body }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["messages", convoId] });
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
    },
  });

  const sendImage = useMutation({
    mutationFn: (file: File) => {
      const fd = new FormData();
      fd.append("file", file);
      return sendImageMessage(convoId, fd);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["messages", convoId] });
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
    },
  });

  // ── Conversation title / header ────────────────────────────────

  const title = conversation.title
    ?? (conversation.participants
        .filter((p) => p.user_id !== userId)
        .map((p) => p.display_name ?? p.user_id)
        .join(", ") || "Conversation");

  const participantCount = conversation.participants.length;

  // DM partner for presence dot
  const dmPartner = !isGroup
    ? conversation.participants.find((p) => p.user_id !== userId)
    : undefined;

  // Typing signal
  const onKeystroke = useTypingSignal(convoId);

  // ── Render ──────────────────────────────────────────────────────

  return (
    <div className="flex h-full flex-col">
      {/* Header */}
      <div className="flex items-center gap-3 border-b border-border px-4 py-3">
        {onBack && (
          <Button variant="ghost" size="icon" className="md:hidden h-8 w-8" onClick={onBack}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
        )}
        <div className="relative">
          <Avatar className="h-9 w-9">
            <AvatarFallback className="text-xs">
              {title.slice(0, 2).toUpperCase()}
            </AvatarFallback>
          </Avatar>
          {dmPartner && <PresenceDot userId={dmPartner.user_id} />}
        </div>
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-semibold">{title}</p>
          {isGroup && (
            <p className="flex items-center gap-1 text-xs text-muted-foreground">
              <Users className="h-3 w-3" />
              {participantCount} participant{participantCount !== 1 && "s"}
            </p>
          )}
        </div>
      </div>

      {/* Messages */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto px-4 py-4 space-y-3">
        {/* Load older */}
        {hasNextPage && (
          <div className="flex justify-center pb-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => fetchNextPage()}
              disabled={isFetchingNextPage}
            >
              {isFetchingNextPage ? "Loading..." : "Load older messages"}
            </Button>
          </div>
        )}

        {isLoading ? (
          <div className="space-y-4">
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className={cn("flex", i % 2 ? "justify-end" : "justify-start")}>
                <Skeleton className={cn("h-12 rounded-2xl", i % 2 ? "w-48" : "w-56")} />
              </div>
            ))}
          </div>
        ) : allMessages.length === 0 ? (
          <p className="py-12 text-center text-sm text-muted-foreground">
            No messages yet. Say hello!
          </p>
        ) : (
          allMessages.map((msg) => (
            <MessageBubble
              key={msg.message_id}
              message={msg}
              isOwn={msg.sender_id === userId}
              showSender={isGroup}
            />
          ))
        )}
      </div>

      {/* Typing indicator */}
      <TypingIndicator conversationId={convoId} />

      {/* Compose */}
      <ComposeBar
        onSendText={(text) => sendText.mutate(text)}
        onSendImage={(file) => sendImage.mutate(file)}
        sending={sendText.isPending || sendImage.isPending}
        onKeystroke={onKeystroke}
      />
    </div>
  );
}

// ─── Messages infinite query hook ───────────────────────────────

import { useInfiniteQuery } from "@tanstack/react-query";

function useMessagesQuery(conversationId: string) {
  return useInfiniteQuery({
    queryKey: ["messages", conversationId],
    queryFn: ({ pageParam }) => getMessages(conversationId, pageParam),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
  });
}
