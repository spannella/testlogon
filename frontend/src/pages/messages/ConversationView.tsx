import * as React from "react";
import { useMutation, useQuery, useQueryClient, type InfiniteData } from "@tanstack/react-query";
import { ArrowLeft, Images, Users, Clock, MoreHorizontal, EyeOff, Pin, Phone, Video, Upload, Bell, BellOff } from "lucide-react";
import { toast } from "sonner";
import { ApiError } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import {
  getMessages,
  sendTextMessage,
  sendImageMessage,
  sendGalleryMessage,
  sendFileShareMessage,
  sendVideoShareMessage,
  sendCalendarShareMessage,
  sendCalendarEventMessage,
  sendMeetingPollMessage,
  sendFindDateTimeMessage,
  sendCountdownMessage,
  sendMarketCardMessage,
  sendPositionCardMessage,
  sendCryptoTransferMessage,
  sendProductCardMessage,
  sendOrderCardMessage,
  sendLocationCard,
  createLotteryMessage,
  sendVoiceMessage,
  markRead,
  muteConversation,
  claimHelpdeskConversation,
  transferHelpdeskConversation,
  listHelpdeskGroupAgents,
  createCallInvite,
  acceptCallInvite,
  declineCallInvite,
  endCall,
  type DirectCallMode,
} from "@/api/endpoints/messaging";
import { useAuthStore } from "@/stores/authStore";
import { useLiveLocationShare } from "./useLiveLocationShare";
import { useOfflineStore } from "@/stores/offlineStore";
import type { Conversation, Message, SendTextMessageReq, SendFileShareReq, SendCalendarShareReq, SendCalendarEventReq, SendMeetingPollReq, SendFindDateTimeReq, CreateLotteryMessageReq } from "@/api/types";
import type { MarketCardPayload, PositionCardPayload } from "@/lib/tradingCards";
import type { CryptoTransferPayload } from "@/lib/cryptoTransfer";
import type { ProductCardPayload, OrderCardPayload } from "@/lib/ecomCards";
import type { LocationCardPayload } from "@/lib/locationCards";
import { MessageBubble } from "./MessageBubble";
import { ComposeBar } from "./ComposeBar";
import { PresenceDot } from "./PresenceDot";
import { PaidCallRateBadge } from "./PaidCallRateBadge";
import { resolveCanonicalProfilePath } from "@/components/shared/UserProfileLink";
import { TypingIndicator, useTypingSignal } from "./TypingIndicator";
import { ParticipantsPanel } from "./ParticipantsPanel";
import { isMessagingDmLotteryEnabled, isMessagingGalleryEnabled, isMessagingWebrtcDirectCallEnabled } from "@/lib/featureFlags";
import { ConversationGallery } from "./ConversationGallery";
import { ScheduledMessages } from "./ScheduledMessages";
import { HiddenMessagesPanel } from "./HiddenMessagesPanel";
import { PinnedMessageBanner } from "./PinnedMessageBanner";
import { PinnedMessagesPanel } from "./PinnedMessagesPanel";
import { RecordingsPanel } from "./RecordingsPanel";
import { ThreadPanel } from "./ThreadPanel";
import { useMessageJump } from "./useMessageJump";
import { CallSessionOverlay, type CallSessionUi, type CallUiState } from "./CallSessionOverlay";
import { callStateReducer, createInitialCallMachineState, teardownCallResources, type CallRuntimeResources } from "./callStateMachine";
import { useRtcPeerConnection } from "@/hooks/useRtcPeerConnection";
import { useMediaCapture } from "@/hooks/useMediaCapture";
import { useCallRecording } from "@/hooks/useCallRecording";
import { useCallBillingHeartbeat } from "@/hooks/useCallBillingHeartbeat";
import { getCallRate } from "@/api/endpoints/callBilling";
import { isCallRecordingEnabled, isGroupCallsEnabled } from "@/lib/featureFlags";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
} from "@/components/ui/dropdown-menu";
import { GroupCallButton } from "./GroupCallOverlay";
import { MUTE_OPTIONS, computeMutedUntil, isMuted as isConversationMuted, mutedLabel } from "@/lib/conversationMute";

interface ConversationViewProps {
  conversation: Conversation;
  onBack?: () => void;
  /** Called immediately after a successful helpdesk claim with the new routing state. */
  onClaimSuccess?: (state: string, agentUserId: string) => void;
}

// FE-141: payload for the image/media send mutation (also reused to retry a
// failed upload with the identical arguments).
type ImageUploadArgs = {
  file: File;
  consumptionPolicy?: "none" | "view_once";
  caption?: string;
  expires_in_seconds?: number;
  lock_price_cents?: number;
  lock_description?: string;
  tip_amount_cents?: number;
  tip_payment_method_id?: string;
  send_at?: number;
  encryption_password?: string;
};

export function ConversationView({ conversation, onBack, onClaimSuccess }: ConversationViewProps) {
  const userId = useAuthStore((s) => s.userId);
  const liveLocation = useLiveLocationShare();
  const queryClient = useQueryClient();
  const addToQueueWithId = useOfflineStore((s) => s.addToQueueWithId);
  const isOnline = useOfflineStore((s) => s.isOnline);
  const offlineQueue = useOfflineStore((s) => s.queue);
  const scrollRef = React.useRef<HTMLDivElement>(null);
  const [hasAutoScrolled, setHasAutoScrolled] = React.useState(false);

  const convoId = conversation.conversation_id;
  const isGroup = conversation.type === "group";
  const [participantsOpen, setParticipantsOpen] = React.useState(false);
  const [galleryOpen, setGalleryOpen] = React.useState(false);
  const [scheduledOpen, setScheduledOpen] = React.useState(false);
  const [hiddenOpen, setHiddenOpen] = React.useState(false);
  const [pinsOpen, setPinsOpen] = React.useState(false);
  const [recordingsOpen, setRecordingsOpen] = React.useState(false);
  const galleryEnabled = isMessagingGalleryEnabled();
  const dmLotteryEnabled = isMessagingDmLotteryEnabled();
  const [dismissedPinnedMessageId, setDismissedPinnedMessageId] = React.useState<string | null>(null);
  const [replyingTo, setReplyingTo] = React.useState<Message | null>(null);
  const [viewedOnceIds, setViewedOnceIds] = React.useState<Set<string>>(new Set());
  const [threadPanelOpen, setThreadPanelOpen] = React.useState(false);
  const [threadAnchorMessage, setThreadAnchorMessage] = React.useState<Message | null>(null);
  const [callMachine, dispatchCall] = React.useReducer(callStateReducer, undefined, createInitialCallMachineState);
  const callTimeoutRef = React.useRef<number | null>(null);
  // GAP-0143: callee-side guard timer (separate ref to avoid colliding with the caller-side callTimeoutRef).
  const calleeRingTimerRef = React.useRef<number | null>(null);
  const callResourcesRef = React.useRef<CallRuntimeResources | null>(null);
  const lastCallEventTsRef = React.useRef<number>(0);
  const mediaCapture = useMediaCapture();
  const [isMuted, setIsMuted] = React.useState(false);
  const [isCameraOff, setIsCameraOff] = React.useState(false);
  const handleViewOnce = React.useCallback((id: string) => {
    setViewedOnceIds((prev) => new Set([...prev, id]));
  }, []);

  // ── Drag-and-drop file handling ────────────────────────────────
  const [dragOverChat, setDragOverChat] = React.useState(false);
  const chatDragCount = React.useRef(0);
  const [pendingDropFile, setPendingDropFile] = React.useState<{
    file: File;
    previewUrl: string;
    kind: "image" | "video" | "audio";
  } | null>(null);

  // FE-141: image/media upload progress (0..100) + a Retry affordance for a
  // failed upload. `failedImageArgs` holds the last failing mutation payload.
  const [uploadProgress, setUploadProgress] = React.useState<number | null>(null);
  const [failedImageArgs, setFailedImageArgs] = React.useState<ImageUploadArgs | null>(null);

  const classifyDroppedFile = React.useCallback((file: File): { kind: "image" | "video" | "audio" | null } => {
    if (file.type.startsWith("image/") || file.type === "application/pdf") return { kind: "image" };
    if (file.type.startsWith("video/")) return { kind: "video" };
    if (file.type.startsWith("audio/")) return { kind: "audio" };
    return { kind: null };
  }, []);

  const handleChatDragEnter = React.useCallback((e: React.DragEvent) => {
    if (!e.dataTransfer.types.includes("Files")) return;
    e.preventDefault();
    e.stopPropagation();
    chatDragCount.current++;
    if (chatDragCount.current === 1) setDragOverChat(true);
  }, []);

  const handleChatDragLeave = React.useCallback((e: React.DragEvent) => {
    e.preventDefault();
    chatDragCount.current = Math.max(0, chatDragCount.current - 1);
    if (chatDragCount.current === 0) setDragOverChat(false);
  }, []);

  const handleChatDragOver = React.useCallback((e: React.DragEvent) => {
    if (!e.dataTransfer.types.includes("Files")) return;
    e.preventDefault();
    e.stopPropagation();
    e.dataTransfer.dropEffect = "copy";
  }, []);

  const handleChatDrop = React.useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    chatDragCount.current = 0;
    setDragOverChat(false);

    const files = Array.from(e.dataTransfer.files);
    const file = files[0];
    if (!file) return;

    const { kind } = classifyDroppedFile(file);
    if (kind) {
      const previewUrl = URL.createObjectURL(file);
      setPendingDropFile({ file, previewUrl, kind });
    } else {
      toast.error(`Unsupported file type: ${file.type || "unknown"}`);
    }
  }, [classifyDroppedFile]);

  // Listen for global app-file-drop events for the messages page
  React.useEffect(() => {
    const handler = (e: Event) => {
      const custom = e as CustomEvent<{ files: File[]; context: string }>;
      if (custom.detail.context !== "message") return;
      const file = custom.detail.files[0];
      if (!file) return;

      const cls = classifyDroppedFile(file);
      if (cls.kind) {
        const previewUrl = URL.createObjectURL(file);
        setPendingDropFile({ file, previewUrl, kind: cls.kind });
      } else {
        toast.error(`Unsupported file type: ${file.type || "unknown"}`);
      }
    };
    window.addEventListener("app-file-drop", handler as EventListener);
    return () => window.removeEventListener("app-file-drop", handler as EventListener);
  }, [classifyDroppedFile]);

  // When a dropped file is set, send it via the image mutation
  React.useEffect(() => {
    if (!pendingDropFile) return;
    const { file, previewUrl, kind } = pendingDropFile;
    setPendingDropFile(null);

    if (kind === "image") {
      sendImage.mutate({ file });
    } else if (kind === "video") {
      // Create a form approach for video - use the image path for now since it handles multipart
      sendImage.mutate({ file });
    } else {
      sendImage.mutate({ file });
    }
    URL.revokeObjectURL(previewUrl);
  }, [pendingDropFile]);

  // ── Messages query ──────────────────────────────────────────────

  const { data, isLoading, fetchNextPage, hasNextPage, isFetchingNextPage } =
    useMessagesQuery(convoId);

  const { jumpToMessage, highlightMessageId } = useMessageJump({
    hasNextPage,
    fetchNextPage,
    onMissingMessage: () => toast.error("Could not find that message in this conversation."),
  });

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
    // Merge still-queued offline messages for this conversation at render time
    // (the FeedTimeline pattern). A reconnect refetch replaces the cache and
    // drops pending/failed optimistic messages that aren't on the server yet;
    // sourcing them from the offline store here keeps them visible until they
    // send (and leave the queue) or are discarded.
    const present = new Set(msgs.map((m) => m.message_id));
    for (const action of offlineQueue) {
      if (action.type !== "send_message") continue;
      if (action.payload.conversationId !== convoId) continue;
      const id = `optimistic-offline-${action.id}`;
      if (present.has(id)) continue;
      const req = action.payload.req;
      msgs.push({
        message_id: id,
        conversation_id: convoId,
        sender_id: userId ?? "",
        kind: "text",
        text: req.encryption ? "" : (req.text ?? ""),
        is_encrypted: !!req.encryption,
        encryption: req.encryption,
        created_at: action.enqueuedAt / 1000,
        reactions_counts: {},
        reply_to_message_id: req.reply_to_message_id,
        __offline: {
          queueId: action.id,
          status: (action.__status ?? "pending") as "pending" | "sending" | "failed",
          error: action.__error,
          enqueuedAt: action.enqueuedAt,
        },
      } as Message);
    }
    return msgs;
  }, [data, offlineQueue, convoId, userId]);

  // ── Message lookup map for reply previews ──────────────────────

  const messageById = React.useMemo(() => {
    const map = new Map<string, Message>();
    for (const msg of allMessages) map.set(msg.message_id, msg);
    return map;
  }, [allMessages]);

  const handleViewThread = React.useCallback((anchor: Message) => {
    if (!anchor.thread_id) {
      toast.info("Thread details are unavailable for this message.");
      return;
    }
    setThreadAnchorMessage(anchor);
    setThreadPanelOpen(true);
  }, []);

  const handleReplyAction = React.useCallback((target: Message) => {
    if (target.thread_id) {
      setThreadAnchorMessage(target);
      setThreadPanelOpen(true);
      return;
    }
    setReplyingTo(target);
  }, []);

  const buildReplyLinkagePayload = React.useCallback((target: Message | null) => {
    if (!target) return {};
    const threadRoot = target.thread_root_message_id ?? target.parent_message_id ?? target.message_id;
    return {
      reply_to_message_id: target.message_id,
      parent_message_id: target.message_id,
      ...(target.thread_id ? { thread_id: target.thread_id } : {}),
      ...(threadRoot ? { thread_root_message_id: threadRoot } : {}),
    };
  }, []);

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

  // ── Per-conversation mute (FE-140) ─────────────────────────────
  const nowSec = Math.floor(Date.now() / 1000);
  const conversationMuted = isConversationMuted(conversation.muted_until, nowSec);
  const mutedText = mutedLabel(conversation.muted_until, nowSec);

  const muteMutation = useMutation({
    mutationFn: (mutedUntil: number) => muteConversation(convoId, mutedUntil),
    onSuccess: (_data, mutedUntil) => {
      void queryClient.invalidateQueries({ queryKey: ["conversations"] });
      void queryClient.invalidateQueries({ queryKey: ["conversation", convoId] });
      toast.success(mutedUntil > 0 ? "Conversation muted" : "Conversation unmuted");
    },
    onError: (err) => {
      toast.error(err instanceof Error ? err.message : "Failed to update mute setting");
    },
  });

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
        void queryClient.invalidateQueries({ queryKey: ["scheduled-messages", convoId] });
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
    mutationFn: (args: ImageUploadArgs) => {
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
        encryption_password: args.encryption_password,
        // FE-141: drive the upload progress bar; scheduled sends stay indeterminate.
        onProgress: args.send_at ? undefined : (pct) => setUploadProgress(pct),
      });
    },
    onMutate: async (args) => {
      // FE-141: a fresh attempt clears any prior failure and starts the bar at 0.
      setFailedImageArgs(null);
      setUploadProgress(args.send_at ? null : 0);
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
        void queryClient.invalidateQueries({ queryKey: ["scheduled-messages", convoId] });
        return;
      }
      queryClient.invalidateQueries({ queryKey: ["messages", convoId] });
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
      setUploadProgress(null);
      setFailedImageArgs(null);
    },
    onError: (_err, args, context) => {
      if (context?.optimisticUrl) URL.revokeObjectURL(context.optimisticUrl);
      if (context?.snapshot) {
        queryClient.setQueryData(["messages", convoId], context.snapshot);
      }
      // FE-141: retries inside uploadToPresignedUrl are exhausted by now; offer a
      // manual Retry with the same payload.
      setUploadProgress(null);
      setFailedImageArgs(args);
      toast.error("Failed to send image");
    },
  });

  const sendGallery = useMutation({
    mutationFn: (args: {
      freeFiles: File[];
      lockedFiles: File[];
      text?: string;
      lock_price_cents?: number;
      lock_description?: string;
      expires_in_seconds?: number;
      send_at?: number;
      tip_amount_cents?: number;
      tip_payment_method_id?: string;
    }) => sendGalleryMessage(convoId, args),
    onSuccess: (_data, args) => {
      if (args.send_at) {
        const scheduledDate = new Date(args.send_at * 1000);
        toast.success(
          `Gallery scheduled for ${scheduledDate.toLocaleString(undefined, {
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
    onError: () => toast.error("Failed to send gallery"),
  });

  const sendFileShare = useMutation({
    mutationFn: (params: SendFileShareReq) => sendFileShareMessage(convoId, params),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["messages", convoId] });
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
    },
    onError: () => toast.error("Failed to share file"),
  });

  const videoShareMut = useMutation({
    mutationFn: (params: { video_id: string; text?: string }) =>
      sendVideoShareMessage(convoId, params),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["messages", convoId] });
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
    },
    onError: (err: any) => toast.error(err?.response?.data?.detail || "Failed to share video"),
  });

  const sendCalendarShare = useMutation({
    mutationFn: (params: SendCalendarShareReq) => sendCalendarShareMessage(convoId, params),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["messages", convoId] });
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
    },
    onError: () => toast.error("Failed to share calendar"),
  });

  const sendCalendarEvent = useMutation({
    mutationFn: (params: SendCalendarEventReq) => sendCalendarEventMessage(convoId, params),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["messages", convoId] });
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
    },
    onError: () => toast.error("Failed to share event"),
  });

  const sendMeetingPoll = useMutation({
    mutationFn: (params: SendMeetingPollReq) => sendMeetingPollMessage(convoId, params),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["messages", convoId] });
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
    },
    onError: () => toast.error("Failed to create poll"),
  });

  const sendFindDateTime = useMutation({
    mutationFn: (params: SendFindDateTimeReq) => sendFindDateTimeMessage(convoId, params),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["messages", convoId] });
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
    },
    onError: () => toast.error("Failed to create Find a Time poll"),
  });

  const sendCountdown = useMutation({
    mutationFn: (params: {
      title: string;
      target_datetime: number;
      associated_event_type?: "broadcast" | "call" | "calendar" | "custom";
      associated_event_id?: string;
    }) => sendCountdownMessage(convoId, params),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["messages", convoId] });
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
    },
    onError: () => toast.error("Failed to create countdown"),
  });

  const sendMarketCard = useMutation({
    mutationFn: (payload: MarketCardPayload) => sendMarketCardMessage(convoId, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["messages", convoId] });
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
    },
    onError: () => toast.error("Failed to share market"),
  });

  const sendPositionCard = useMutation({
    mutationFn: (payload: PositionCardPayload) => sendPositionCardMessage(convoId, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["messages", convoId] });
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
    },
    onError: () => toast.error("Failed to share position"),
  });

  const sendCryptoTransfer = useMutation({
    mutationFn: (payload: CryptoTransferPayload) => sendCryptoTransferMessage(convoId, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["messages", convoId] });
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
      toast.success("Crypto sent");
    },
    onError: () => toast.error("Failed to send crypto"),
  });

  const sendProductCard = useMutation({
    mutationFn: (payload: ProductCardPayload) => sendProductCardMessage(convoId, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["messages", convoId] });
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
    },
    onError: () => toast.error("Failed to share product"),
  });

  const sendOrderCard = useMutation({
    mutationFn: (payload: OrderCardPayload) => sendOrderCardMessage(convoId, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["messages", convoId] });
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
    },
    onError: () => toast.error("Failed to share purchase"),
  });

  const sendLocation = useMutation({
    mutationFn: (payload: LocationCardPayload) => sendLocationCard(convoId, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["messages", convoId] });
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
    },
    onError: () => toast.error("Failed to share location"),
  });

  const sendLottery = useMutation({
    mutationFn: (params: Omit<CreateLotteryMessageReq, "conversation_id">) =>
      createLotteryMessage({ ...params, conversation_id: convoId }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["messages", convoId] });
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
      toast.success(data.idempotent ? "Lottery message already sent" : "Lottery message sent");
    },
    onError: (err: unknown) => {
      if (err instanceof ApiError) {
        toast.error(err.detail);
        return;
      }
      toast.error("Failed to send lottery message");
    },
  });

  const sendVoice = useMutation({
    mutationFn: (args: {
      blob: Blob;
      meta: {
        duration: number;
        waveform: number[];
        contentType: string;
        consumption_policy?: "none" | "listen_once";
        reply_to_message_id?: string | null;
        send_at?: number | null;
      };
    }) =>
      sendVoiceMessage(convoId, args.blob, {
        durationSeconds: args.meta.duration,
        waveform: args.meta.waveform,
        contentType: args.meta.contentType,
        consumption_policy: args.meta.consumption_policy,
        reply_to_message_id: args.meta.reply_to_message_id,
        send_at: args.meta.send_at,
      }),
    onSuccess: (_data, args) => {
      queryClient.invalidateQueries({ queryKey: ["messages", convoId] });
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
      if (args.meta.send_at) {
        toast.success("Voice message scheduled");
      } else {
        toast.success("Voice message sent");
      }
    },
    onError: () => toast.error("Failed to send voice message"),
  });

  // MVA-010: synthesize the current draft into a TTS voice message.
  const sendTts = useMutation({
    mutationFn: async (args: { text: string; reply_to_message_id?: string | null }) => {
      const { createTtsVoiceMessage } = await import("@/api/endpoints/messagingAi");
      return createTtsVoiceMessage(convoId, {
        text: args.text,
        reply_to_message_id: args.reply_to_message_id ?? undefined,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["messages", convoId] });
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
      toast.success("Voice message sent");
    },
    onError: async (err) => {
      const { ApiError } = await import("@/api/client");
      if (err instanceof ApiError && err.status === 404) {
        toast.error("Text-to-speech is not enabled on this server");
      } else if (err instanceof ApiError && err.status === 429) {
        toast.error("Too many requests — try again shortly");
      } else if (err instanceof ApiError && err.status === 400) {
        toast.error("Text is too long to synthesize");
      } else {
        toast.error("Failed to synthesize voice message");
      }
    },
  });

  const claimMutation = useMutation({
    mutationFn: () => claimHelpdeskConversation(convoId),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
      queryClient.invalidateQueries({ queryKey: ["helpdesk-queue"] });
      // Immediately notify parent so it can update activeConvo without waiting for refetch.
      onClaimSuccess?.(data.state, data.assigned_agent_user_id);
    },
    onError: () => toast.error("Failed to claim conversation"),
  });

  const [transferTarget, setTransferTarget] = React.useState("");
  const [transferDialogOpen, setTransferDialogOpen] = React.useState(false);
  const transferMutation = useMutation({
    mutationFn: (targetId: string) => transferHelpdeskConversation(convoId, targetId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
      queryClient.invalidateQueries({ queryKey: ["helpdesk-queue"] });
      setTransferDialogOpen(false);
      setTransferTarget("");
      toast.success("Conversation transferred");
    },
    onError: () => toast.error("Failed to transfer conversation"),
  });

  // HMH-007: fellow agents in this helpdesk group, for the transfer picker.
  const transferGroupId = conversation.routing_group_id ?? "";
  const transferAgentsQuery = useQuery({
    queryKey: ["helpdesk-group-agents", transferGroupId],
    queryFn: () => listHelpdeskGroupAgents(transferGroupId),
    enabled: transferDialogOpen && !!transferGroupId,
    staleTime: 30_000,
  });
  const transferAgents = (transferAgentsQuery.data ?? []).filter((a) => !a.is_self);

  // ── Conversation title / header ────────────────────────────────

  const title = conversation.title
    ?? (conversation.participants
        .filter((p) => p.user_id !== userId)
        .map((p) => p.display_name ?? p.user_id)
        .join(", ") || "Conversation");

  const participantCount = conversation.participants.length;

  // Owner attribution for the shared position card (falls back to "You").
  const currentUserName =
    conversation.participants.find((p) => p.user_id === userId)?.display_name ?? "You";

  // Resolve a sender id to a friendly display name for message/reply labels
  // (falls back to the raw id when a participant isn't found).
  const senderNameById = React.useMemo(() => {
    const m = new Map<string, string>();
    for (const p of conversation.participants) {
      if (p.display_name) m.set(p.user_id, p.display_name);
    }
    return m;
  }, [conversation.participants]);
  const resolveSenderName = React.useCallback(
    (id: string) => (id === userId ? "You" : senderNameById.get(id) ?? id),
    [senderNameById, userId],
  );

  // DM partner for presence dot
  const dmPartner = !isGroup
    ? conversation.participants.find((p) => p.user_id !== userId)
    : undefined;
  const dmPartnerProfilePath = dmPartner
    ? resolveCanonicalProfilePath({ userId: dmPartner.user_id, displayName: dmPartner.display_name })
    : null;
  const callsEnabled = !isGroup && !!dmPartner && isMessagingWebrtcDirectCallEnabled();

  // ── WebRTC peer connection hook ────────────────────────────────
  const rtcEnabled = callMachine.phase !== "idle" &&
    !["declined", "busy", "timeout", "ended", "failure"].includes(callMachine.phase);

  const { resources: rtcResources, localStream: rtcLocalStream, remoteStream: rtcRemoteStream, connectionState: rtcConnectionState, iceConnectionState: rtcIceConnectionState } = useRtcPeerConnection({
    callId: callMachine.callId,
    conversationId: convoId,
    role: callMachine.role,
    mode: callMachine.mode,
    phase: callMachine.phase,
    peerId: dmPartner?.user_id ?? "",
    userId: userId ?? "",
    enabled: rtcEnabled && !!callMachine.callId,
    retryCount: callMachine.retryCount,
    onConnect: () => dispatchCall({ type: "CONNECT" }),
    onConnectionLost: (msg) => dispatchCall({ type: "CONNECTION_LOST", message: msg }),
    onFail: (msg) => dispatchCall({ type: "FAIL", message: msg }),
  });

  React.useEffect(() => {
    if (rtcResources) {
      callResourcesRef.current = rtcResources;
    }
  }, [rtcResources]);

  const callRecordingEnabled = callsEnabled && isCallRecordingEnabled();
  const callRecording = useCallRecording({
    callId: callMachine.callId,
    userId: userId ?? "",
    localStream: rtcLocalStream ?? mediaCapture.stream ?? null,
    remoteStream: rtcRemoteStream ?? null,
    isConnected: callMachine.phase === "connected",
    enabled: callRecordingEnabled,
  });

  React.useEffect(() => {
    if (callRecording.recordingState === "recording" && callRecording.recordingId) {
      dispatchCall({ type: "RECORDING_STARTED", recordingId: callRecording.recordingId });
    } else if (callRecording.recordingState === "consent_pending" && callRecording.consentPendingFrom) {
      dispatchCall({ type: "RECORDING_REQUEST_RECEIVED", requestedBy: callRecording.consentPendingFrom });
    } else if (callRecording.recordingState === "consent_pending" && callRecording.isInitiator) {
      dispatchCall({ type: "RECORDING_REQUEST_SENT" });
    } else if (["stopping", "uploading", "complete"].includes(callRecording.recordingState)) {
      dispatchCall({ type: "RECORDING_STOPPED" });
    }
  }, [callRecording.recordingState, callRecording.recordingId, callRecording.consentPendingFrom, callRecording.isInitiator]);

  React.useEffect(() => {
    if (callRecording.recordingState === "recording") {
      const handler = (e: BeforeUnloadEvent) => {
        e.preventDefault();
        e.returnValue = "A recording is in progress. If you leave, the recording will be lost.";
      };
      window.addEventListener("beforeunload", handler);
      return () => window.removeEventListener("beforeunload", handler);
    }
  }, [callRecording.recordingState]);

  React.useEffect(() => {
    if (callRecording.recordingState === "uploading") {
      toast.loading("Uploading call recording...", { id: "recording-upload" });
    } else if (callRecording.recordingState === "complete") {
      toast.success("Call recording saved.", { id: "recording-upload" });
    } else if (callRecording.recordingState === "error") {
      toast.error(`Recording failed: ${callRecording.error ?? "Unknown error"}`, { id: "recording-upload" });
    }
  }, [callRecording.recordingState, callRecording.error]);

  // ── Paid-call billing heartbeat (GAP-0016) ─────────────────────
  // Look up the DM partner's call rate so we know whether this is a paid call.
  const callPartnerId = dmPartner?.user_id;
  const { data: callRate } = useQuery({
    queryKey: ["call-rate", callPartnerId],
    queryFn: () => getCallRate(callPartnerId as string),
    enabled: callsEnabled && !!callPartnerId,
    staleTime: 5 * 60_000,
  });
  const isPaidCall = !!callRate?.enabled && (callRate?.rate_cents_per_minute ?? 0) > 0;

  const clearCallTimeout = React.useCallback(() => {
    if (callTimeoutRef.current) {
      window.clearTimeout(callTimeoutRef.current);
      callTimeoutRef.current = null;
    }
  }, []);

  React.useEffect(() => {
    if (callMachine.phase !== "reconnecting") return;
    const timer = window.setTimeout(() => dispatchCall({ type: "RECONNECT_ATTEMPT" }), 1000);
    return () => window.clearTimeout(timer);
  }, [callMachine.phase]);

  React.useEffect(() => {
    if (["ended", "failed", "failure", "declined", "busy", "timeout", "idle"].includes(callMachine.phase)) {
      teardownCallResources(callResourcesRef.current);
    }
  }, [callMachine.phase]);

  // GAP-0143: callee-side guard — auto-dismiss the ringing overlay if the
  // `call.missed` SSE event is lost/delayed. Mirrors the caller-side 30s timer
  // (line ~856). Fires at ringing_timeout (30s, MESSAGING_WEBRTC_CALL_RINGING_TIMEOUT_SECONDS)
  // + 2s grace, giving the SSE event time to arrive before the local guard fires.
  React.useEffect(() => {
    if (callMachine.phase !== "incoming_ringing") return;
    const CALLEE_RING_GUARD_MS = 32_000;
    calleeRingTimerRef.current = window.setTimeout(() => {
      // SSE event was never received — dismiss locally. REMOTE_DECLINE on
      // incoming_ringing transitions to `timeout` (callStateMachine REMOTE_DECLINE).
      dispatchCall({ type: "REMOTE_DECLINE", reason: "timeout" });
      calleeRingTimerRef.current = null;
    }, CALLEE_RING_GUARD_MS);
    return () => {
      if (calleeRingTimerRef.current) {
        window.clearTimeout(calleeRingTimerRef.current);
        calleeRingTimerRef.current = null;
      }
    };
  }, [callMachine.phase]);

  // GAP-0144: on the `failure` phase, signal the backend so the remote peer is
  // notified (call.end SSE → END_REMOTE on the remote side). Local teardown
  // already ran in the effect above; this sends the missing `end` action.
  React.useEffect(() => {
    if (callMachine.phase !== "failure") return;
    const cid = callMachine.callId;
    if (!cid) return;
    // Best-effort: the idempotency key guards against React strict-mode double
    // fire; a failed POST is swallowed (the stale-session backstop is the fallback).
    callActionMutation.mutate(
      { action: "end", callId: cid, reason: "reconnect_failed" },
      { onError: () => {} },
    );
    // callActionMutation is a stable useMutation ref; intentionally omitted from deps.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [callMachine.phase, callMachine.callId]);

  React.useEffect(() => () => {
    clearCallTimeout();
    if (calleeRingTimerRef.current) {
      window.clearTimeout(calleeRingTimerRef.current);
      calleeRingTimerRef.current = null;
    }
    teardownCallResources(callResourcesRef.current);
  }, [clearCallTimeout]);

  const callMutation = useMutation({
    mutationFn: (args: { mode: DirectCallMode; calleeUserId: string; conversationId: string }) =>
      createCallInvite(args.conversationId, {
        callee_user_id: args.calleeUserId,
        mode: args.mode,
        idempotency_key: `ui-invite-${Date.now()}`,
      }),
  });

  const callActionMutation = useMutation({
    mutationFn: async (args: { action: "accept" | "decline" | "end"; callId: string; reason?: string }) => {
      if (args.action === "accept") return acceptCallInvite(args.callId, `ui-accept-${Date.now()}`);
      if (args.action === "decline") return declineCallInvite(args.callId, { reason: "declined", idempotency_key: `ui-decline-${Date.now()}` });
      return endCall(args.callId, { reason: args.reason ?? "ended", idempotency_key: `ui-end-${Date.now()}` });
    },
  });

  // Drive billing heartbeats while a paid call is connected (GAP-0016).
  // GAP-0147: capture the latest heartbeat so the in-call billing overlay can
  // render the running cost ticker, balance, and low-balance warning.
  const callBilling = useCallBillingHeartbeat({
    callId: callMachine.callId,
    enabled: callMachine.phase === "connected" && isPaidCall,
    onEndCall: () => {
      if (!callMachine.callId) {
        dispatchCall({ type: "END_LOCAL" });
        return;
      }
      callActionMutation.mutate(
        { action: "end", callId: callMachine.callId },
        {
          onSuccess: () => dispatchCall({ type: "END_REMOTE" }),
          onError: () => dispatchCall({ type: "FAIL" }),
        },
      );
      toast.error("Call ended: insufficient balance.");
    },
    onLowBalance: (mins) =>
      toast.warning(`Low balance — about ${mins} minute(s) of call time remaining.`),
  });

  const extractCallErrorCode = (err: unknown): string => {
    if (err instanceof ApiError) {
      const body = err.body as { detail?: { code?: string } } | undefined;
      return body?.detail?.code ?? "";
    }
    return "";
  };

  const startOutgoingCall = async (mode: DirectCallMode) => {
    if (!dmPartner || !callsEnabled) return;
    clearCallTimeout();
    dispatchCall({ type: "START_OUTGOING", mode, peerName: dmPartner.display_name ?? dmPartner.user_id });

    // CALL-003: Acquire media BEFORE sending invite
    const localStream = await mediaCapture.acquire(mode);
    if (!localStream) {
      // Permission denied or device not found — abort without sending invite
      const errorMsg = mediaCapture.error?.message ?? "Could not access microphone/camera.";
      dispatchCall({ type: "FAIL", message: errorMsg });
      toast.error(errorMsg);
      return;
    }

    // Attach to runtime resources for the peer connection hook
    callResourcesRef.current = {
      ...callResourcesRef.current,
      localStream,
      cleanedUp: false,
    };

    callMutation.mutate(
      {
        mode,
        calleeUserId: dmPartner.user_id,
        conversationId: convoId,
      },
      {
        onSuccess: (res) => {
          dispatchCall({ type: "OUTGOING_RINGING", callId: res.call_id });
          // WebRTC negotiation is now handled by useRtcPeerConnection hook.
          // REMOTE_ACCEPT will be dispatched when the callee accepts via SSE.
          callTimeoutRef.current = window.setTimeout(async () => {
            dispatchCall({ type: "REMOTE_DECLINE", reason: "timeout" });
            if (res.call_id) {
              try {
                const { timeoutCall } = await import("@/api/endpoints/messaging");
                await timeoutCall(res.call_id, { reason: "no_answer" });
              } catch { /* best-effort */ }
            }
          }, 30_000);
        },
        onError: (err) => {
          const code = extractCallErrorCode(err);
          if (code === "call_busy") {
            dispatchCall({ type: "REMOTE_DECLINE", reason: "busy" });
            return;
          }
          if (code === "call_declined") {
            dispatchCall({ type: "REMOTE_DECLINE", reason: "declined" });
            return;
          }
          if (code === "call_timeout") {
            dispatchCall({ type: "REMOTE_DECLINE", reason: "timeout" });
            return;
          }
          dispatchCall({ type: "FAIL", message: "Call failed to connect." });
        },
      },
    );
  };

  React.useEffect(() => {
    const onCallEvent = (event: Event) => {
      const custom = event as CustomEvent<Record<string, unknown>>;
      const detail = custom.detail ?? {};
      if (detail.conversation_id !== convoId) return;
      const eventTs = Number(detail.event_ts ?? detail.created_at ?? 0);
      if (Number.isFinite(eventTs) && eventTs > 0) {
        if (eventTs < lastCallEventTsRef.current) return;
        lastCallEventTsRef.current = eventTs;
      }
      const eventType = String(detail.event_type ?? "");
      const callId = typeof detail.call_id === "string" ? detail.call_id : undefined;
      const mode = detail.mode === "video" ? "video" : "audio";
      const reason = typeof detail.reason === "string" ? detail.reason : undefined;
      const callerId = typeof detail.caller_user_id === "string" ? detail.caller_user_id : undefined;
      const calleeId = typeof detail.callee_user_id === "string" ? detail.callee_user_id : undefined;
      const isCurrentUserCallee = !!userId && calleeId === userId;
      const isCurrentUserCaller = !!userId && callerId === userId;
      if (eventType === "call.invite" && isCurrentUserCallee) {
        dispatchCall({
          type: "INCOMING_INVITE",
          mode,
          callId,
          peerName: dmPartner?.display_name ?? callerId ?? "Unknown caller",
        });
      } else if (eventType === "call.accept" && isCurrentUserCaller) {
        dispatchCall({ type: "REMOTE_ACCEPT" });
      } else if (eventType === "call.decline" && isCurrentUserCaller) {
        dispatchCall({ type: "REMOTE_DECLINE", reason: reason === "busy" ? "busy" : "declined" });
      } else if (eventType === "call.missed") {
        // If I'm the callee, dismiss any ringing UI
        if (isCurrentUserCallee) {
          dispatchCall({ type: "REMOTE_DECLINE", reason: "timeout" });
        }
      } else if (eventType === "call.end") {
        dispatchCall({ type: "END_REMOTE" });
      }
    };
    window.addEventListener("messaging:call-event", onCallEvent as EventListener);
    return () => window.removeEventListener("messaging:call-event", onCallEvent as EventListener);
  }, [convoId, dmPartner?.display_name, userId]);

  React.useEffect(() => {
    const onOffline = () => dispatchCall({ type: "NETWORK_OFFLINE" });
    const onOnline = () => dispatchCall({ type: "NETWORK_ONLINE" });
    const onVisibility = () => {
      if (document.visibilityState === "visible") {
        dispatchCall({ type: "TAB_VISIBLE" });
      } else {
        dispatchCall({ type: "TAB_HIDDEN" });
      }
    };
    window.addEventListener("offline", onOffline);
    window.addEventListener("online", onOnline);
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      window.removeEventListener("offline", onOffline);
      window.removeEventListener("online", onOnline);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, []);

  const latestPinnedMessageId = conversation.latest_pinned_message_id;
  const latestPinnedAt = conversation.latest_pinned_at;
  const latestPinnedMessage = latestPinnedMessageId ? messageById.get(latestPinnedMessageId) : undefined;
  const latestPinnedPreview = latestPinnedMessage?.text
    ?? (latestPinnedMessage?.is_encrypted ? "[Encrypted message]" : undefined)
    ?? (latestPinnedMessage?.kind === "image" ? "[Image]" : undefined)
    ?? (latestPinnedMessage?.kind === "file" ? "[File]" : undefined)
    ?? (latestPinnedMessage?.kind === "video" ? "[Video]" : undefined)
    ?? (latestPinnedMessage?.kind === "audio" ? "[Audio]" : undefined)
    ?? "Pinned message";

  // Typing signal
  const onKeystroke = useTypingSignal(convoId);


  React.useEffect(() => {
    const storageKey = `messaging:pinned-banner-dismissed:${convoId}`;
    const cached = window.sessionStorage.getItem(storageKey);
    setDismissedPinnedMessageId(cached);
  }, [convoId]);

  const bannerDismissedForCurrentPin = latestPinnedMessageId && dismissedPinnedMessageId === latestPinnedMessageId;
  const overlayState: CallUiState =
    callMachine.phase === "reconnecting" ? "reconnecting"
      : callMachine.phase === "outgoing_inviting" ? "outgoing_inviting"
      : callMachine.phase;
  const overlaySession: CallSessionUi = {
    state: overlayState,
    direction: callMachine.role === "callee" ? "incoming" : "outgoing",
    mode: callMachine.mode,
    peerName: callMachine.peerName,
    callId: callMachine.callId,
    reasonMessage: callMachine.reasonMessage,
  };


  // ── Render ──────────────────────────────────────────────────────

  return (
    <div
      className="relative flex h-full flex-col"
      onDragEnter={handleChatDragEnter}
      onDragLeave={handleChatDragLeave}
      onDragOver={handleChatDragOver}
      onDrop={handleChatDrop}
      data-testid="conversation-drop-zone"
    >
      {dragOverChat && (
        <div className="absolute inset-0 z-20 flex items-center justify-center bg-background/60 backdrop-blur-sm rounded-lg border-2 border-dashed border-primary" data-testid="chat-drop-overlay">
          <div className="flex flex-col items-center gap-2 text-primary">
            <Upload className="h-10 w-10" />
            <p className="text-sm font-medium">Drop file to attach</p>
          </div>
        </div>
      )}
      {/* Header */}
      <div className="flex items-center gap-3 border-b border-border px-4 py-3">
        {onBack && (
          <Button variant="ghost" size="icon" className="md:hidden h-8 w-8" onClick={onBack}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
        )}
        <div className="relative">
          {dmPartner && dmPartnerProfilePath ? (
            <a
              href={dmPartnerProfilePath}
              aria-label={`Open ${dmPartner.display_name ?? dmPartner.user_id} profile`}
              className="block rounded-full hover:opacity-90"
            >
              <Avatar className="h-9 w-9">
                {dmPartner.profile_photo_url && (
                  <AvatarImage src={dmPartner.profile_photo_url} alt={dmPartner.display_name ?? dmPartner.user_id} />
                )}
                <AvatarFallback className="text-xs">
                  {title.slice(0, 2).toUpperCase()}
                </AvatarFallback>
              </Avatar>
            </a>
          ) : (
            <Avatar className="h-9 w-9">
              <AvatarFallback className="text-xs">
                {title.slice(0, 2).toUpperCase()}
              </AvatarFallback>
            </Avatar>
          )}
          {dmPartner && <PresenceDot userId={dmPartner.user_id} />}
        </div>
        <div className="min-w-0 flex-1">
          {dmPartner && dmPartnerProfilePath ? (
            <a
              href={dmPartnerProfilePath}
              className="truncate text-sm font-semibold hover:underline"
              aria-label={`Open ${dmPartner.display_name ?? dmPartner.user_id} profile`}
            >
              {dmPartner.display_name ?? dmPartner.user_id}
            </a>
          ) : (
            <p className="truncate text-sm font-semibold">{title}</p>
          )}
          {isGroup && (
            <p className="flex items-center gap-1 text-xs text-muted-foreground">
              <Users className="h-3 w-3" />
              {participantCount} participant{participantCount !== 1 && "s"}
            </p>
          )}
          {conversationMuted && (
            <p className="flex items-center gap-1 text-xs text-muted-foreground" aria-label={mutedText}>
              <BellOff className="h-3 w-3" />
              {mutedText}
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
        {callsEnabled && (
          <>
            {callPartnerId && <PaidCallRateBadge partnerUserId={callPartnerId} />}
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 shrink-0"
              onClick={() => startOutgoingCall("audio")}
              aria-label="Start audio call"
              disabled={callMutation.isPending || callMachine.phase !== "idle"}
            >
              <Phone className="h-4 w-4" />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 shrink-0"
              onClick={() => startOutgoingCall("video")}
              aria-label="Start video call"
              disabled={callMutation.isPending || callMachine.phase !== "idle"}
            >
              <Video className="h-4 w-4" />
            </Button>
          </>
        )}
        {isGroup && isGroupCallsEnabled() && (
          <GroupCallButton conversationId={convoId} userId={userId ?? ""} isGroup={isGroup} />
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
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="h-8 w-8 shrink-0" aria-label="Conversation menu">
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={() => setScheduledOpen(true)}>
              <Clock className="mr-2 h-4 w-4" />
              Scheduled messages
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => setPinsOpen(true)}>
              <Pin className="mr-2 h-4 w-4" />
              View all pins
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => setHiddenOpen(true)}>
              <EyeOff className="mr-2 h-4 w-4" />
              Hidden messages
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            {conversationMuted ? (
              <DropdownMenuItem
                onClick={() => muteMutation.mutate(0)}
                disabled={muteMutation.isPending}
              >
                <Bell className="mr-2 h-4 w-4" />
                Unmute
              </DropdownMenuItem>
            ) : (
              <DropdownMenuSub>
                <DropdownMenuSubTrigger>
                  <BellOff className="mr-2 h-4 w-4" />
                  Mute notifications
                </DropdownMenuSubTrigger>
                <DropdownMenuSubContent>
                  {MUTE_OPTIONS.map((opt) => (
                    <DropdownMenuItem
                      key={opt.id}
                      onClick={() =>
                        muteMutation.mutate(
                          computeMutedUntil(opt.id, Math.floor(Date.now() / 1000)),
                        )
                      }
                      disabled={muteMutation.isPending}
                    >
                      {opt.label}
                    </DropdownMenuItem>
                  ))}
                </DropdownMenuSubContent>
              </DropdownMenuSub>
            )}
            {callRecordingEnabled && (
              <DropdownMenuItem onClick={() => setRecordingsOpen(true)}>
                <Video className="mr-2 h-4 w-4" />
                Recordings
              </DropdownMenuItem>
            )}
          </DropdownMenuContent>
        </DropdownMenu>
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

      {latestPinnedMessageId && !bannerDismissedForCurrentPin && (
        <PinnedMessageBanner
          latestPinnedMessageId={latestPinnedMessageId}
          latestPinnedAt={latestPinnedAt}
          previewText={latestPinnedPreview}
          onViewAllPins={() => setPinsOpen(true)}
          onJumpToMessage={jumpToMessage}
          onDismiss={() => {
            const storageKey = `messaging:pinned-banner-dismissed:${convoId}`;
            window.sessionStorage.setItem(storageKey, latestPinnedMessageId);
            setDismissedPinnedMessageId(latestPinnedMessageId);
          }}
        />
      )}

      {/* Helpdesk routing banner */}
      {conversation.routing_mode === "helpdesk_bridge" && conversation.routing_state && (
        <>
          <HelpdeskRoutingBanner
            conversation={conversation}
            currentUserId={userId ?? ""}
            onClaim={() => claimMutation.mutate()}
            isClaiming={claimMutation.isPending}
            onTransfer={() => setTransferDialogOpen(true)}
          />
          {transferDialogOpen && (
            <div className="flex items-center gap-2 border-b border-border bg-muted/40 px-4 py-2 text-xs">
              <select
                value={transferTarget}
                onChange={(e) => setTransferTarget(e.target.value)}
                className="flex-1 rounded border border-input bg-background px-2 py-1 text-xs"
                aria-label="Transfer to agent"
              >
                <option value="">
                  {transferAgentsQuery.isLoading
                    ? "Loading agents…"
                    : transferAgents.length === 0
                      ? "No other agents available"
                      : "Select an agent…"}
                </option>
                {transferAgents.map((a) => (
                  <option key={a.user_id} value={a.user_id}>
                    {a.display_name}{a.online ? " · online" : " · offline"}
                  </option>
                ))}
              </select>
              <Button
                size="sm"
                variant="default"
                className="h-7 shrink-0"
                onClick={() => transferMutation.mutate(transferTarget.trim())}
                disabled={!transferTarget.trim() || transferMutation.isPending}
              >
                {transferMutation.isPending ? "Transferring…" : "Transfer"}
              </Button>
              <Button
                size="sm"
                variant="ghost"
                className="h-7 shrink-0"
                onClick={() => { setTransferDialogOpen(false); setTransferTarget(""); }}
              >
                Cancel
              </Button>
            </div>
          )}
        </>
      )}

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
                onReply={handleReplyAction}
                onViewThread={handleViewThread}
                replyToMessage={msg.reply_to_message_id ? messageById.get(msg.reply_to_message_id) : undefined}
                viewedOnceIds={viewedOnceIds}
                onViewOnce={handleViewOnce}
                resolveSenderName={resolveSenderName}
                onStopLiveLocation={
                  msg.kind === "live_location" &&
                  liveLocation.active?.shareId === (msg.share_id ?? undefined)
                    ? () => { void liveLocation.stop(); }
                    : undefined
                }
              />
            </div>
          ))
        )}
      </div>

      {/* Typing indicator */}
      <TypingIndicator conversationId={convoId} />

      {/* FE-141: media upload progress + retry-on-failure affordance. */}
      {uploadProgress !== null && !failedImageArgs && (
        <div className="px-3 pt-1" data-testid="upload-progress">
          <div className="flex items-center gap-2">
            <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
              <div
                className="h-full rounded-full bg-primary transition-all"
                style={{ width: `${uploadProgress}%` }}
              />
            </div>
            <span className="text-xs text-muted-foreground tabular-nums">{uploadProgress}%</span>
          </div>
        </div>
      )}
      {failedImageArgs && (
        <div
          className="mx-3 mt-1 flex items-center justify-between gap-2 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-1.5"
          data-testid="upload-failed"
        >
          <span className="text-xs text-destructive">Upload failed.</span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              className="text-xs font-medium text-primary hover:underline"
              onClick={() => {
                const args = failedImageArgs;
                setFailedImageArgs(null);
                if (args) sendImage.mutate(args);
              }}
            >
              Retry
            </button>
            <button
              type="button"
              className="text-xs text-muted-foreground hover:underline"
              onClick={() => setFailedImageArgs(null)}
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      {/* Compose */}
      <ComposeBar
        conversationId={convoId}
        onSendText={(payload) => {
          const fullPayload = {
            ...payload,
            ...buildReplyLinkagePayload(replyingTo),
          };
          // Only queue non-scheduled messages — scheduled messages need server-side
          // delivery at the chosen time and should not be silently deferred.
          // Use the synchronous navigator.onLine as well as the store flag: the
          // store's isOnline lags the browser offline event by a tick, and a send
          // fired in that window would otherwise take the online path and create a
          // second optimistic bubble.
          const browserOffline = typeof navigator !== "undefined" && !navigator.onLine;
          if ((!isOnline || browserOffline) && !fullPayload.send_at) {
            const queueId = `offline-${Date.now()}-${Math.random().toString(36).slice(2)}`;

            // 1. Add to persistent queue with known ID
            addToQueueWithId(queueId, { type: "send_message", payload: { conversationId: convoId, req: fullPayload } });

            // 2. Inject optimistic message into React Query cache
            const optimisticOffline: Message = {
              message_id: `optimistic-offline-${queueId}`,
              conversation_id: convoId,
              sender_id: userId ?? "",
              kind: "text",
              text: fullPayload.encryption ? "" : (fullPayload.text ?? ""),
              is_encrypted: !!fullPayload.encryption,
              encryption: fullPayload.encryption,
              created_at: Date.now() / 1000,
              reactions_counts: {},
              reply_to_message_id: fullPayload.reply_to_message_id,
              __offline: {
                queueId,
                status: "pending",
                enqueuedAt: Date.now(),
              },
            };

            // 2. The conversation view renders offline-queue messages from the
            // store (allMessages render-merge), so we do NOT inject a copy into
            // the messages cache here — doing both produced a duplicate bubble
            // that survived a reconnect refetch (and broke discard).

            // 3. Update sidebar preview
            queryClient.setQueriesData<InfiniteData<{ conversations: Conversation[]; next_cursor?: string }>>(
              { queryKey: ["conversations"] },
              (old) => {
                if (!old?.pages) return old;
                return {
                  ...old,
                  pages: old.pages.map((page) => ({
                    ...page,
                    conversations: (page.conversations ?? []).map((c: Conversation) =>
                      c.conversation_id === convoId
                        ? { ...c, last_message: optimisticOffline, last_message_at: optimisticOffline.created_at }
                        : c,
                    ),
                  })),
                };
              },
            );

            toast.info("You're offline — message queued");
            setReplyingTo(null);
            return;
          }
          sendText.mutate(fullPayload);
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
          encryption_password: options?.encryption_password,
        })}
        onSendGallery={(params) => sendGallery.mutate(params)}
        onSendFileShare={(params) => sendFileShare.mutate(params)}
        onSendVideoShare={(params) => videoShareMut.mutate(params)}
        onSendCalendarShare={(params) => sendCalendarShare.mutate(params)}
        onSendCalendarEvent={(params) => sendCalendarEvent.mutate(params)}
        onSendMeetingPoll={(params) => sendMeetingPoll.mutate(params)}
        onSendFindDateTime={(params) => sendFindDateTime.mutate(params)}
        onSendCountdown={(params) => sendCountdown.mutate(params)}
        onSendMarketCard={(payload) => sendMarketCard.mutate(payload)}
        onSendPositionCard={(payload) => sendPositionCard.mutate(payload)}
        onSendCryptoTransfer={!isGroup ? (payload) => sendCryptoTransfer.mutate(payload) : undefined}
        onSendProductCard={(payload) => sendProductCard.mutate(payload)}
        onSendOrderCard={(payload) => sendOrderCard.mutate(payload)}
        onSendLocation={(payload) => sendLocation.mutate(payload)}
        onSendLiveLocation={(durationSec) => { void liveLocation.start(convoId, durationSec); }}
        liveLocationStarting={liveLocation.starting}
        recipientName={dmPartner?.display_name}
        currentUserName={currentUserName}
        onSendLottery={!isGroup && dmLotteryEnabled ? (params) => sendLottery.mutate(params) : undefined}
        onSendVoiceMessage={(blob, meta) => sendVoice.mutate({ blob, meta })}
        onSendTtsVoice={(ttsText, opts) =>
          sendTts.mutateAsync({ text: ttsText, reply_to_message_id: opts.reply_to_message_id }).then(() => setReplyingTo(null))
        }
        sending={sendText.isPending || sendImage.isPending || sendGallery.isPending || sendFileShare.isPending || videoShareMut.isPending || sendCalendarShare.isPending || sendCalendarEvent.isPending || sendMeetingPoll.isPending || sendCountdown.isPending || sendLottery.isPending || sendVoice.isPending || sendTts.isPending}
        onKeystroke={onKeystroke}
        replyingTo={replyingTo}
        onCancelReply={() => setReplyingTo(null)}
      />


      {galleryEnabled && (
        <ConversationGallery
          open={galleryOpen}
          onOpenChange={setGalleryOpen}
          conversationId={convoId}
          resolveSenderName={resolveSenderName}
          onJumpToMessage={(messageId) => {
            setGalleryOpen(false);
            jumpToMessage(messageId);
          }}
        />
      )}

      {/* Scheduled messages panel */}
      <ScheduledMessages
        open={scheduledOpen}
        onOpenChange={setScheduledOpen}
        conversationId={convoId}
      />


      <HiddenMessagesPanel
        open={hiddenOpen}
        onOpenChange={setHiddenOpen}
        conversationId={convoId}
        onJumpToMessage={(messageId) => {
          setHiddenOpen(false);
          jumpToMessage(messageId);
        }}
      />

      <PinnedMessagesPanel
        open={pinsOpen}
        onOpenChange={setPinsOpen}
        conversationId={convoId}
        participants={conversation.participants}
        messageById={messageById}
        onJumpToMessage={(messageId) => {
          setPinsOpen(false);
          jumpToMessage(messageId);
        }}
      />

      {callRecordingEnabled && (
        <RecordingsPanel
          open={recordingsOpen}
          onOpenChange={setRecordingsOpen}
          conversationId={convoId}
        />
      )}

      <ThreadPanel
        open={threadPanelOpen}
        onOpenChange={setThreadPanelOpen}
        conversationId={convoId}
        anchorMessage={threadAnchorMessage}
        currentUserId={userId ?? undefined}
      />

      {/* Group participants panel */}
      {isGroup && (
        <ParticipantsPanel
          conversationId={convoId}
          open={participantsOpen}
          onClose={() => setParticipantsOpen(false)}
        />
      )}

      <CallSessionOverlay
        session={overlaySession}
        conversationId={convoId}
        voicemailEligible={callsEnabled}
        isBusy={callActionMutation.isPending}
        localStream={rtcLocalStream ?? mediaCapture.stream ?? null}
        remoteStream={rtcRemoteStream ?? null}
        peerConnection={rtcResources?.peerConnection ?? null}
        connectionState={rtcConnectionState}
        iceConnectionState={rtcIceConnectionState}
        onAccept={async () => {
          if (!callMachine.callId) return;

          // CALL-003: Acquire media before accepting
          const localStream = await mediaCapture.acquire(callMachine.mode);
          if (!localStream) {
            // Cannot acquire media — decline the call
            const errorMsg = mediaCapture.error?.message ?? "Could not access microphone/camera.";
            callActionMutation.mutate(
              { action: "decline", callId: callMachine.callId },
              { onSettled: () => dispatchCall({ type: "FAIL", message: errorMsg }) },
            );
            toast.error(`Call failed: ${errorMsg}`);
            return;
          }

          callResourcesRef.current = {
            ...callResourcesRef.current,
            localStream,
            cleanedUp: false,
          };

          dispatchCall({ type: "LOCAL_ACCEPT" });
          callActionMutation.mutate(
            { action: "accept", callId: callMachine.callId },
            {
              onSuccess: () => {
                // CONNECT will be dispatched by useRtcPeerConnection when
                // RTCPeerConnection.connectionState === "connected"
              },
              onError: () => dispatchCall({ type: "FAIL" }),
            },
          );
        }}
        onDecline={() => {
          if (!callMachine.callId) return;
          callActionMutation.mutate(
            { action: "decline", callId: callMachine.callId },
            {
              onSuccess: () => dispatchCall({ type: "REMOTE_DECLINE", reason: "declined" }),
              onError: () => dispatchCall({ type: "FAIL" }),
            },
          );
        }}
        isMuted={isMuted}
        isCameraOff={isCameraOff}
        onToggleMute={() => {
          const stream = callResourcesRef.current?.localStream ?? mediaCapture.stream;
          const audioTrack = stream?.getAudioTracks()[0];
          if (audioTrack) {
            audioTrack.enabled = !audioTrack.enabled;
            setIsMuted(!audioTrack.enabled);
          }
        }}
        onToggleCamera={() => {
          const stream = callResourcesRef.current?.localStream ?? mediaCapture.stream;
          const videoTrack = stream?.getVideoTracks()[0];
          if (videoTrack) {
            videoTrack.enabled = !videoTrack.enabled;
            setIsCameraOff(!videoTrack.enabled);
          }
        }}
        onEnd={() => {
          if (callRecording.recordingState === "recording") {
            callRecording.stopRecording();
          }
          if (!callMachine.callId) {
            dispatchCall({ type: "END_LOCAL" });
            return;
          }
          callActionMutation.mutate(
            { action: "end", callId: callMachine.callId },
            {
              onSuccess: () => dispatchCall({ type: "END_REMOTE" }),
              onError: () => dispatchCall({ type: "FAIL" }),
            },
          );
        }}
        onDismiss={() => {
          if (callRecording.recordingState === "recording") {
            callRecording.stopRecording();
          }
          clearCallTimeout();
          teardownCallResources(callResourcesRef.current);
          mediaCapture.release();
          setIsMuted(false);
          setIsCameraOff(false);
          dispatchCall({ type: "RESET" });
        }}
        isRecording={callRecording.recordingState === "recording"}
        recordingDuration={callRecording.duration}
        onRequestRecording={() => callRecording.requestRecording()}
        onStopRecording={() => callRecording.stopRecording()}
        recordingEnabled={callRecordingEnabled}
        showRecordingConsent={callRecording.recordingState === "consent_pending" && !!callRecording.consentPendingFrom}
        recordingConsentFrom={callRecording.consentPendingFrom}
        onConsentRecording={(accept: boolean) => callRecording.respondToRequest(accept)}
        isPaidCall={isPaidCall}
        billingTotalCostCents={callBilling?.total_cost_cents}
        billingRateCentsPerMinute={callBilling?.rate_cents_per_minute}
        billingElapsedSeconds={callBilling?.elapsed_seconds}
        billingBalanceRemainingCents={callBilling?.balance_remaining_cents}
        billingWarnLowBalance={callBilling?.warn_low_balance}
        billingMinutesRemaining={callBilling?.minutes_remaining}
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
    refetchOnWindowFocus: true,
    refetchOnReconnect: true,
  });
}

// ─── Helpdesk Routing Banner ─────────────────────────────────────

interface HelpdeskRoutingBannerProps {
  conversation: Conversation;
  currentUserId: string;
  onClaim: () => void;
  isClaiming: boolean;
  onTransfer?: () => void;
}

function HelpdeskRoutingBanner({ conversation, currentUserId, onClaim, isClaiming, onTransfer }: HelpdeskRoutingBannerProps) {
  const state = conversation.routing_state ?? "";
  const assignedAgent = conversation.active_agent_user_id ?? "";
  // Agent-only fields (routing_group_id / active_agent_user_id) are present in
  // the payload only for helpdesk agents (HMH-008), so their presence tells us
  // the viewer is an agent vs the customer.
  const isAgent = Boolean(conversation.routing_group_id);

  let bgClass = "bg-muted";
  let text = "";
  let showClaim = false;
  let showTransfer = false;

  if (!isAgent) {
    // Customer-facing status — never a Claim action, never an agent identity.
    if (state === "awaiting_agent") {
      bgClass = "bg-amber-50 border-amber-200 text-amber-800";
      text = "Connecting you to an agent…";
    } else if (state === "assigned") {
      bgClass = "bg-green-50 border-green-200 text-green-800";
      text = "An agent has joined this chat";
    } else if (state === "paused_no_agents_online") {
      bgClass = "bg-red-50 border-red-200 text-red-800";
      text = "No agents are online right now — we'll connect you as soon as one is available";
    } else if (state === "closed") {
      bgClass = "bg-muted border-border text-muted-foreground";
      text = "This support chat is closed";
    } else {
      return null;
    }
  } else if (state === "awaiting_agent") {
    bgClass = "bg-amber-50 border-amber-200 text-amber-800";
    text = "Waiting for agent";
    showClaim = true;
  } else if (state === "assigned" && assignedAgent === currentUserId) {
    bgClass = "bg-green-50 border-green-200 text-green-800";
    text = "You are handling this conversation";
    showTransfer = true;
  } else if (state === "assigned") {
    bgClass = "bg-yellow-50 border-yellow-200 text-yellow-800";
    text = "Assigned to another agent";
  } else if (state === "paused_no_agents_online") {
    bgClass = "bg-red-50 border-red-200 text-red-800";
    text = "No agents online — will resume when an agent comes online";
  } else if (state === "closed") {
    bgClass = "bg-muted border-border text-muted-foreground";
    text = "Conversation closed";
  } else {
    return null;
  }

  return (
    <div className={cn("flex items-center gap-3 border-b px-4 py-2 text-sm font-medium", bgClass)}>
      <span className="flex-1">{text}</span>
      {showClaim && (
        <Button
          size="sm"
          variant="outline"
          className="h-7 shrink-0"
          onClick={onClaim}
          disabled={isClaiming}
          aria-label="Claim this helpdesk conversation"
        >
          {isClaiming ? "Claiming…" : "Claim"}
        </Button>
      )}
      {showTransfer && onTransfer && (
        <Button
          size="sm"
          variant="outline"
          className="h-7 shrink-0"
          onClick={onTransfer}
          aria-label="Transfer this helpdesk conversation"
        >
          Transfer
        </Button>
      )}
    </div>
  );
}
