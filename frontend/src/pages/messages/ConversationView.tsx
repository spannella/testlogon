import * as React from "react";
import { useMutation, useQueryClient, type InfiniteData } from "@tanstack/react-query";
import { ArrowLeft, Images, Users, Clock, MoreHorizontal, EyeOff, Pin, Phone, Video } from "lucide-react";
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
  createLotteryMessage,
  sendVoiceMessage,
  markRead,
  claimHelpdeskConversation,
  createCallInvite,
  acceptCallInvite,
  declineCallInvite,
  endCall,
  type DirectCallMode,
} from "@/api/endpoints/messaging";
import { useAuthStore } from "@/stores/authStore";
import { useOfflineStore } from "@/stores/offlineStore";
import type { Conversation, Message, SendTextMessageReq, SendFileShareReq, SendCalendarShareReq, SendCalendarEventReq, SendMeetingPollReq, CreateLotteryMessageReq } from "@/api/types";
import { MessageBubble } from "./MessageBubble";
import { ComposeBar } from "./ComposeBar";
import { PresenceDot } from "./PresenceDot";
import { resolveCanonicalProfilePath } from "@/components/shared/UserProfileLink";
import { TypingIndicator, useTypingSignal } from "./TypingIndicator";
import { ParticipantsPanel } from "./ParticipantsPanel";
import { isMessagingDmLotteryEnabled, isMessagingGalleryEnabled, isMessagingWebrtcDirectCallEnabled } from "@/lib/featureFlags";
import { ConversationGallery } from "./ConversationGallery";
import { ScheduledMessages } from "./ScheduledMessages";
import { HiddenMessagesPanel } from "./HiddenMessagesPanel";
import { PinnedMessageBanner } from "./PinnedMessageBanner";
import { PinnedMessagesPanel } from "./PinnedMessagesPanel";
import { ThreadPanel } from "./ThreadPanel";
import { useMessageJump } from "./useMessageJump";
import { CallSessionOverlay, type CallSessionUi, type CallUiState } from "./CallSessionOverlay";
import { callStateReducer, createInitialCallMachineState, teardownCallResources, type CallRuntimeResources } from "./callStateMachine";
import { useRtcPeerConnection } from "@/hooks/useRtcPeerConnection";
import { useMediaCapture } from "@/hooks/useMediaCapture";
import { useCallRecording } from "@/hooks/useCallRecording";
import { isCallRecordingEnabled, isGroupCallsEnabled } from "@/lib/featureFlags";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { GroupCallButton } from "./GroupCallOverlay";

interface ConversationViewProps {
  conversation: Conversation;
  onBack?: () => void;
  /** Called immediately after a successful helpdesk claim with the new routing state. */
  onClaimSuccess?: (state: string, agentUserId: string) => void;
}

export function ConversationView({ conversation, onBack, onClaimSuccess }: ConversationViewProps) {
  const userId = useAuthStore((s) => s.userId);
  const queryClient = useQueryClient();
  const addToQueue = useOfflineStore((s) => s.addToQueue);
  const isOnline = useOfflineStore((s) => s.isOnline);
  const scrollRef = React.useRef<HTMLDivElement>(null);
  const [hasAutoScrolled, setHasAutoScrolled] = React.useState(false);

  const convoId = conversation.conversation_id;
  const isGroup = conversation.type === "group";
  const [participantsOpen, setParticipantsOpen] = React.useState(false);
  const [galleryOpen, setGalleryOpen] = React.useState(false);
  const [scheduledOpen, setScheduledOpen] = React.useState(false);
  const [hiddenOpen, setHiddenOpen] = React.useState(false);
  const [pinsOpen, setPinsOpen] = React.useState(false);
  const galleryEnabled = isMessagingGalleryEnabled();
  const dmLotteryEnabled = isMessagingDmLotteryEnabled();
  const [dismissedPinnedMessageId, setDismissedPinnedMessageId] = React.useState<string | null>(null);
  const [replyingTo, setReplyingTo] = React.useState<Message | null>(null);
  const [viewedOnceIds, setViewedOnceIds] = React.useState<Set<string>>(new Set());
  const [threadPanelOpen, setThreadPanelOpen] = React.useState(false);
  const [threadAnchorMessage, setThreadAnchorMessage] = React.useState<Message | null>(null);
  const [callMachine, dispatchCall] = React.useReducer(callStateReducer, undefined, createInitialCallMachineState);
  const callTimeoutRef = React.useRef<number | null>(null);
  const callResourcesRef = React.useRef<CallRuntimeResources | null>(null);
  const lastCallEventTsRef = React.useRef<number>(0);
  const mediaCapture = useMediaCapture();
  const [isMuted, setIsMuted] = React.useState(false);
  const [isCameraOff, setIsCameraOff] = React.useState(false);
  const handleViewOnce = React.useCallback((id: string) => {
    setViewedOnceIds((prev) => new Set([...prev, id]));
  }, []);

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
    return msgs;
  }, [data]);

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
      encryption_password?: string;
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
        encryption_password: args.encryption_password,
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
  const dmPartnerProfilePath = dmPartner
    ? resolveCanonicalProfilePath({ userId: dmPartner.user_id, displayName: dmPartner.display_name })
    : null;
  const callsEnabled = !isGroup && !!dmPartner && isMessagingWebrtcDirectCallEnabled();

  // ── WebRTC peer connection hook ────────────────────────────────
  const rtcEnabled = callMachine.phase !== "idle" &&
    !["declined", "busy", "timeout", "ended", "failure"].includes(callMachine.phase);

  const { resources: rtcResources, localStream: rtcLocalStream, remoteStream: rtcRemoteStream } = useRtcPeerConnection({
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

  React.useEffect(() => () => {
    clearCallTimeout();
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
    mutationFn: async (args: { action: "accept" | "decline" | "end"; callId: string }) => {
      if (args.action === "accept") return acceptCallInvite(args.callId, `ui-accept-${Date.now()}`);
      if (args.action === "decline") return declineCallInvite(args.callId, { reason: "declined", idempotency_key: `ui-decline-${Date.now()}` });
      return endCall(args.callId, { reason: "ended", idempotency_key: `ui-end-${Date.now()}` });
    },
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
    <div className="flex h-full flex-col">
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
        <HelpdeskRoutingBanner
          conversation={conversation}
          currentUserId={userId ?? ""}
          onClaim={() => claimMutation.mutate()}
          isClaiming={claimMutation.isPending}
        />
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
              />
            </div>
          ))
        )}
      </div>

      {/* Typing indicator */}
      <TypingIndicator conversationId={convoId} />

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
          if (!isOnline && !fullPayload.send_at) {
            addToQueue({ type: "send_message", payload: { conversationId: convoId, req: fullPayload } });
            toast.info("You're offline — message queued and will send when reconnected");
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
        onSendLottery={!isGroup && dmLotteryEnabled ? (params) => sendLottery.mutate(params) : undefined}
        onSendVoiceMessage={(blob, meta) => sendVoice.mutate({ blob, meta })}
        sending={sendText.isPending || sendImage.isPending || sendGallery.isPending || sendFileShare.isPending || videoShareMut.isPending || sendCalendarShare.isPending || sendCalendarEvent.isPending || sendMeetingPoll.isPending || sendLottery.isPending || sendVoice.isPending}
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
        isBusy={callActionMutation.isPending}
        localStream={rtcLocalStream ?? mediaCapture.stream ?? null}
        remoteStream={rtcRemoteStream ?? null}
        peerConnection={rtcResources?.peerConnection ?? null}
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
}

function HelpdeskRoutingBanner({ conversation, currentUserId, onClaim, isClaiming }: HelpdeskRoutingBannerProps) {
  const state = conversation.routing_state ?? "";
  const assignedAgent = conversation.active_agent_user_id ?? "";

  let bgClass = "bg-muted";
  let text = "";
  let showClaim = false;

  if (state === "awaiting_agent") {
    bgClass = "bg-amber-50 border-amber-200 text-amber-800";
    text = "Waiting for agent";
    showClaim = true;
  } else if (state === "assigned" && assignedAgent === currentUserId) {
    bgClass = "bg-green-50 border-green-200 text-green-800";
    text = "You are handling this conversation";
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
    </div>
  );
}
