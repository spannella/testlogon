import * as React from "react";
import { useMutation, useQueryClient, type InfiniteData } from "@tanstack/react-query";
import { ArrowLeft, Images, Users, Clock } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import {
  getMessages,
  sendTextMessage,
  sendImageMessage,
  markRead,
} from "@/api/endpoints/messaging";
import { useAuthStore } from "@/stores/authStore";
import type { Conversation, Message, SendTextMessageReq } from "@/api/types";
import { MessageBubble } from "./MessageBubble";
import { ComposeBar } from "./ComposeBar";
import { PresenceDot } from "./PresenceDot";
import { TypingIndicator, useTypingSignal } from "./TypingIndicator";
import { ParticipantsPanel } from "./ParticipantsPanel";
import { isMessagingGalleryEnabled } from "@/lib/featureFlags";
import { ConversationGallery } from "./ConversationGallery";
import { ScheduledMessages } from "./ScheduledMessages";

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
  const [participantsOpen, setParticipantsOpen] = React.useState(false);
  const [galleryOpen, setGalleryOpen] = React.useState(false);
  const [scheduledOpen, setScheduledOpen] = React.useState(false);
  const galleryEnabled = isMessagingGalleryEnabled();
  const [jumpTargetMessageId, setJumpTargetMessageId] = React.useState<string | null>(null);
  const [highlightMessageId, setHighlightMessageId] = React.useState<string | null>(null);
  const [replyingTo, setReplyingTo] = React.useState<Message | null>(null);
  const [viewedOnceIds, setViewedOnceIds] = React.useState<Set<string>>(new Set());
  const handleViewOnce = React.useCallback((id: string) => {
    setViewedOnceIds((prev) => new Set([...prev, id]));
  }, []);

  // ── Messages query ──────────────────────────────────────────────

  const { data, isLoading, fetchNextPage, hasNextPage, isFetchingNextPage } =
    useMessagesQuery(convoId);

  const allMessages = React.useMemo(() => {
    if (!data?.pages) return [];
    // Pages come newest-first from the API (each page itself is also newest-first).
    // Iterate pages oldest→newest, and reverse each page's messages so the final
    // array is chronological oldest→newest for top-to-bottom display.
    const msgs: Message[] = [];
    for (let i = data.pages.length - 1; i >= 0; i--) {
      const page = data.pages[i];
      if (page) msgs.push(...(page.messages ?? []).slice().reverse());
    }
    return msgs;
  }, [data]);

  // ── Message lookup map for reply previews ──────────────────────

  const messageById = React.useMemo(() => {
    const map = new Map<string, Message>();
    for (const msg of allMessages) map.set(msg.message_id, msg);
    return map;
  }, [allMessages]);

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
      markRead(convoId, lastMsg.created_at).catch(() => {});
    }
  }, [convoId, allMessages, conversation.unread_count]);

  // ── Reconcile stale local state across reconnect/focus ─────────

  React.useEffect(() => {
    const refresh = () => {
      void queryClient.invalidateQueries({ queryKey: ["messages", convoId] });
      void queryClient.invalidateQueries({ queryKey: ["conversations"] });
    };

    const onVisibility = () => {
      if (document.visibilityState === "visible") {
        refresh();
      }
    };

    window.addEventListener("online", refresh);
    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      window.removeEventListener("online", refresh);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [convoId, queryClient]);

  // ── Send mutations ─────────────────────────────────────────────

  type MessagesPage = { messages: Message[]; next_cursor?: string };

  const sendText = useMutation({
    mutationFn: (payload: SendTextMessageReq) => sendTextMessage(convoId, payload),
    onMutate: async (payload) => {
      // Skip optimistic update for scheduled messages - they won't appear until send_at
      if (payload.send_at) return { snapshot: undefined, isScheduled: true };

      await queryClient.cancelQueries({ queryKey: ["messages", convoId] });
      const snapshot = queryClient.getQueryData(["messages", convoId]);

      const optimistic: Message = {
        message_id: `optimistic-${Date.now()}`,
        conversation_id: convoId,
        sender_id: userId ?? "",
        kind: "text",
        text: payload.encryption ? "" : (payload.text ?? ""),
        is_encrypted: !!payload.encryption,
        encryption: payload.encryption,
        created_at: Date.now() / 1000,
        reactions_counts: {},
        reply_to_message_id: payload.reply_to_message_id,
      };

      queryClient.setQueryData<InfiniteData<MessagesPage>>(
        ["messages", convoId],
        (old) => {
          if (!old?.pages.length) return old;
          // pages[0] is the newest page and its messages are newest-first.
          // Prepend the optimistic message so that after allMessages reversal
          // it appears at the bottom (newest position) rather than the top.
          const pages = old.pages.map((p, i) =>
            i === 0 ? { ...p, messages: [optimistic, ...(p.messages ?? [])] } : p,
          );
          return { ...old, pages };
        },
      );

      return { snapshot, isScheduled: false };
    },
    onSuccess: (_data, payload, context) => {
      if (context?.isScheduled) {
        // Show toast for scheduled messages instead of adding to chat
        const scheduledDate = new Date((payload.send_at ?? 0) * 1000);
        toast.success(
          `Message scheduled for ${scheduledDate.toLocaleString(undefined, {
            month: "short",
            day: "numeric",
            hour: "numeric",
            minute: "2-digit",
            timeZoneName: "short",
          })}`,
        );
        return;
      }
      queryClient.invalidateQueries({ queryKey: ["messages", convoId] });
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
    },
    onError: (err: Error, _payload, context) => {
      if (context?.snapshot) {
        queryClient.setQueryData(["messages", convoId], context.snapshot);
      }
      toast.error(err.message || "Failed to send message");
    },
  });

  const sendImage = useMutation({
    mutationFn: (args: {
      file: File;
      consumptionPolicy?: "none" | "view_once";
      caption?: string;
      expires_in_seconds?: number;
      lock_price_cents?: number;
      lock_description?: string;
      tip_amount_cents?: number;
      tip_payment_method_id?: string;
      send_at?: number;
    }) => {
      const fd = new FormData();
      fd.append("file", args.file);
      return sendImageMessage(convoId, fd, {
        consumption_policy: args.consumptionPolicy ?? "none",
        caption: args.caption,
        expires_in_seconds: args.expires_in_seconds,
        lock_price_cents: args.lock_price_cents,
        lock_description: args.lock_description,
        tip_amount_cents: args.tip_amount_cents,
        tip_payment_method_id: args.tip_payment_method_id,
        send_at: args.send_at,
      });
    },
    onMutate: async (args) => {
      // Skip optimistic update for scheduled image messages
      if (args.send_at) return { snapshot: undefined, optimisticUrl: undefined, isScheduled: true };

      await queryClient.cancelQueries({ queryKey: ["messages", convoId] });
      const snapshot = queryClient.getQueryData(["messages", convoId]);

      // Optimistic placeholder so the user sees immediate feedback during upload
      const optimistic: Message = {
        message_id: `optimistic-img-${Date.now()}`,
        conversation_id: convoId,
        sender_id: userId ?? "",
        kind: args.file.type === "application/pdf" ? "file" : "image",
        text: args.caption,
        created_at: Date.now() / 1000,
        reactions_counts: {},
        // Show a local object URL as preview (will be replaced by the real URL after success)
        image: args.file.type.startsWith("image/")
          ? { url: URL.createObjectURL(args.file) }
          : undefined,
        file: args.file.type === "application/pdf"
          ? { name: args.file.name, size: args.file.size, content_type: args.file.type }
          : undefined,
      };

      queryClient.setQueryData<InfiniteData<MessagesPage>>(
        ["messages", convoId],
        (old) => {
          if (!old?.pages.length) return old;
          const pages = old.pages.map((p, i) =>
            i === 0 ? { ...p, messages: [optimistic, ...(p.messages ?? [])] } : p,
          );
          return { ...old, pages };
        },
      );

      return { snapshot, optimisticUrl: optimistic.image?.url, isScheduled: false };
    },
    onSuccess: (_data, args, context) => {
      if (context?.optimisticUrl) URL.revokeObjectURL(context.optimisticUrl);
      if (context?.isScheduled) {
        const scheduledDate = new Date((args.send_at ?? 0) * 1000);
        toast.success(
          `Image scheduled for ${scheduledDate.toLocaleString(undefined, {
            month: "short",
            day: "numeric",
            hour: "numeric",
            minute: "2-digit",
            timeZoneName: "short",
          })}`,
        );
        return;
      }
      queryClient.invalidateQueries({ queryKey: ["messages", convoId] });
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
    },
    onError: (_err, _args, context) => {
      if (context?.optimisticUrl) URL.revokeObjectURL(context.optimisticUrl);
      if (context?.snapshot) {
        queryClient.setQueryData(["messages", convoId], context.snapshot);
      }
      toast.error("Failed to send image");
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


  React.useEffect(() => {
    if (!jumpTargetMessageId) return;

    let cancelled = false;
    const run = async () => {
      let attempts = 0;
      while (!cancelled) {
        const el = document.getElementById(`msg-${jumpTargetMessageId}`);
        if (el) {
          el.scrollIntoView({ behavior: "smooth", block: "center" });
          setHighlightMessageId(jumpTargetMessageId);
          window.setTimeout(() => {
            setHighlightMessageId((current) => (current === jumpTargetMessageId ? null : current));
          }, 2000);
          setJumpTargetMessageId(null);
          return;
        }
        if (!hasNextPage || attempts >= 10) {
          setJumpTargetMessageId(null);
          return;
        }
        attempts += 1;
        await fetchNextPage();
      }
    };

    void run();
    return () => {
      cancelled = true;
    };
  }, [jumpTargetMessageId, hasNextPage, fetchNextPage]);

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
            {dmPartner?.profile_photo_url && (
              <AvatarImage src={dmPartner.profile_photo_url} alt={dmPartner.display_name ?? dmPartner.user_id} />
            )}
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
        {galleryEnabled && (
          <Button
            variant="outline"
            size="sm"
            className="h-8 shrink-0"
            onClick={() => setGalleryOpen(true)}
            aria-label="Open media and links gallery"
          >
            <Images className="mr-1.5 h-4 w-4" />
            Media & Links
          </Button>
        )}
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8 shrink-0"
          onClick={() => setScheduledOpen(true)}
          aria-label="Scheduled messages"
        >
          <Clock className="h-4 w-4" />
        </Button>
        {isGroup && (
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8 shrink-0"
            onClick={() => setParticipantsOpen(true)}
            aria-label="Manage participants"
          >
            <Users className="h-4 w-4" />
          </Button>
        )}
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
            <div
              key={msg.message_id}
              id={`msg-${msg.message_id}`}
              className={cn(
                "rounded-lg transition-colors",
                highlightMessageId === msg.message_id ? "bg-primary/10" : "",
              )}
            >
              <MessageBubble
                message={msg}
                isOwn={msg.sender_id === userId}
                showSender={isGroup}
                conversationId={convoId}
                onReply={(m) => setReplyingTo(m)}
                replyToMessage={msg.reply_to_message_id ? messageById.get(msg.reply_to_message_id) : undefined}
                viewedOnceIds={viewedOnceIds}
                onViewOnce={handleViewOnce}
              />
            </div>
          ))
        )}
      </div>

      {/* Typing indicator */}
      <TypingIndicator conversationId={convoId} />

      {/* Compose */}
      <ComposeBar
        onSendText={(payload) => {
          sendText.mutate({
            ...payload,
            reply_to_message_id: replyingTo?.message_id,
          });
          setReplyingTo(null);
        }}
        onSendImage={(file, options) => sendImage.mutate({
          file,
          consumptionPolicy: options?.consumption_policy,
          caption: options?.caption,
          expires_in_seconds: options?.expires_in_seconds,
          lock_price_cents: options?.lock_price_cents,
          lock_description: options?.lock_description,
          tip_amount_cents: options?.tip_amount_cents,
          tip_payment_method_id: options?.tip_payment_method_id,
          send_at: options?.send_at,
        })}
        sending={sendText.isPending || sendImage.isPending}
        onKeystroke={onKeystroke}
        replyingTo={replyingTo}
        onCancelReply={() => setReplyingTo(null)}
      />


      {galleryEnabled && (
        <ConversationGallery
          open={galleryOpen}
          onOpenChange={setGalleryOpen}
          conversationId={convoId}
          onJumpToMessage={(messageId) => {
            setGalleryOpen(false);
            setJumpTargetMessageId(messageId);
          }}
        />
      )}

      {/* Scheduled messages panel */}
      <ScheduledMessages
        open={scheduledOpen}
        onOpenChange={setScheduledOpen}
        conversationId={convoId}
      />

      {/* Group participants panel */}
      {isGroup && (
        <ParticipantsPanel
          conversationId={convoId}
          open={participantsOpen}
          onClose={() => setParticipantsOpen(false)}
        />
      )}
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
    refetchOnWindowFocus: true,
    refetchOnReconnect: true,
  });
}
