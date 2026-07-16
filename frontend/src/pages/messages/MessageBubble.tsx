import { useState, useEffect, useRef, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { MoreHorizontal, Forward, Trash2, Lock, Loader2, Pencil, Info, Download, X, Reply, Smile, SmilePlus, DollarSign, Eye, EyeOff, CreditCard, Check, FileText, CalendarDays, CalendarCheck, Users, Flag, Dices, Mic, Clock, AlertCircle, RotateCcw, Languages } from "lucide-react";
import { useMutation, useQuery, useQueryClient, type InfiniteData } from "@tanstack/react-query";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { isMessagingEncryptionEnabled, isMessagingTranslationEnabled, messagingTranslationDefaultLang } from "@/lib/featureFlags";
import { translateMessage } from "@/api/endpoints/messagingAi";
import { isEmojiOnly } from "@/utils/emoji";
import { MessageText } from "@/components/shared/MessageText";
import { ReactionEmoji } from "@/components/shared/ReactionEmoji";
import { EmojiPicker } from "@/components/shared/EmojiPicker";
import { ReactionDetailPopover } from "./ReactionDetailPopover";
import {
  decryptMessage,
  decryptBytes,
  isMessageCryptoSupported,
  MessageCryptoError,
  type MessageEncryptionEnvelope,
} from "@/lib/messageEncryption";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import {
  buildAttachmentDownloadUrl,
  consumeOnceMediaAttachment,
  createOnceMediaAttachmentGrant,
  deleteMessage,
  editMessage,
  markViewed,
  reactToMessage,
  hideMessage,
  reportMessage,
  sendMessageTip,
  sendTextMessage,
  unlockMessage,
  unlockLotteryMessage,
  getMeetingPoll,
  voteMeetingPoll,
  confirmMeetingPoll,
} from "@/api/endpoints/messaging";
import { createEvent } from "@/api/endpoints/calendar";
import { ApiError } from "@/api/client";
import type { GalleryImageItem, Message, MeetingPollAttachment, FindDateTimeAttachment, PaymentMethod } from "@/api/types";
import { getPaymentMethods } from "@/api/endpoints/billing";
import { FileMessageCard } from "./FileMessageCard";
import { WaveformPlayer } from "./WaveformPlayer";
import { VoicemailBubble } from "./VoicemailBubble";
import { TranscriptControl } from "./TranscriptControl";
import { CountdownCard } from "./CountdownCard";
import { FindDateTimeCard } from "./FindDateTimeCard";
import { VideoShareCard } from "./VideoShareCard";
import { ReadReceipts, ViewTracker } from "./ReadReceipts";
import { DeliveryStatus } from "./DeliveryStatus";
import { ForwardDialog } from "./ForwardDialog";
import { MessageDetailsSheet } from "./MessageDetailsSheet";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { FilePreview } from "@/pages/files/FilePreview";
import { downloadUrl, sharedPreviewUrl } from "@/api/endpoints/files";
import type { FileEntry } from "@/api/types";
import { ReportContentModal, type ReportContentPayload } from "@/components/shared/ReportContentModal";
import { useOfflineStore } from "@/stores/offlineStore";
import {
  updateOfflineMessageStatus,
  removeOptimisticMessage,
} from "@/lib/offlineMessageHelpers";

const QUICK_EMOJIS = ["👍", "❤️", "😂", "😮", "😢", "🙏"];

// MSG-011: emoji added by double-tapping a message (quick-react).
const QUICK_REACT_EMOJI = "❤️";

// MSG-011: the EmojiPicker emits custom emojis as ":shortcode:"; reactions are
// stored under the "custom:shortcode" key (see ReactionEmoji). Normalize here.
function normalizeReactionKey(picked: string): string {
  const m = /^:([a-zA-Z0-9_-]+):$/.exec(picked);
  if (m) return `custom:${(m[1] ?? "").toLowerCase()}`;
  return picked;
}

interface MessageBubbleProps {
  message: Message;
  isOwn: boolean;
  showSender?: boolean;
  conversationId: string;
  onReply?: (message: Message) => void;
  onViewThread?: (message: Message) => void;
  replyToMessage?: Message;
  viewedOnceIds?: Set<string>;
  onViewOnce?: (messageId: string) => void;
  /** Resolve a sender id (sub/email) to a friendly display name. */
  resolveSenderName?: (id: string) => string;
}

type LotteryRevealPhase = "idle" | "unlocking" | "revealing" | "revealed";

function LotterySpinner({ phase, reducedMotion }: { phase: LotteryRevealPhase; reducedMotion: boolean }) {
  if (phase === "idle") return null;
  if (reducedMotion) {
    return <Loader2 className="h-4 w-4 animate-spin" aria-hidden />;
  }
  return (
    <div className="relative h-4 w-4" aria-hidden>
      <div className={cn(
        "absolute inset-0 rounded-full border-2 border-primary/30 border-t-primary",
        phase === "unlocking" ? "animate-spin" : "",
      )} />
      <div className={cn(
        "absolute inset-[3px] rounded-full bg-primary/70",
        phase === "revealing" ? "animate-pulse" : "",
      )} />
    </div>
  );
}

// Message kinds that render their own caption below an attachment card; the
// generic text render is skipped for these to avoid a duplicate caption.
const ATTACHMENT_CAPTION_KINDS = new Set([
  "file_share",
  "calendar_share",
  "calendar_event",
  "meeting_poll",
  "find_datetime",
]);

const onceLabel = (message: Message): string | undefined => {
  if (message.consumption_policy === "view_once") return "View once";
  if (message.consumption_policy === "listen_once") return "Listen once";
  return undefined;
};

const consumeTrigger = (message: Message): "open" | "play" => (message.media_kind === "image" ? "open" : "play");

const playbackThresholdSeconds = (message: Message): number => {
  if (message.media_kind === "video" || message.media_kind === "audio") return 1.2;
  return 0;
};

const onceErrorMessageFromCode = (code: string | undefined): string => {
  switch (code) {
    case "already_consumed":
      return "Already consumed on another device.";
    case "grant_expired":
      return "Grant expired. Please try opening again.";
    case "consume_threshold_not_met":
      return "Playback threshold not reached yet. Keep playing and retry.";
    case "invalid_grant":
      return "Unable to validate once-media grant.";
    default:
      return "Unable to open once-media attachment.";
  }
};

function formatBytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 ** 2).toFixed(1)} MB`;
}

const openBlobInEphemeralWindow = (blob: Blob) => {
  const objectUrl = URL.createObjectURL(blob);
  const opened = window.open(objectUrl, "_blank", "noopener,noreferrer");

  // Revoke quickly to reduce in-memory persistence; delay allows the new tab to read it.
  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 60_000);
  if (!opened) {
    URL.revokeObjectURL(objectUrl);
  }
};

const buildS3ObjectUrl = (bucket?: string, key?: string): string | undefined => {
  if (!bucket || !key) return undefined;
  return `/mock/s3/${bucket}/${encodeURIComponent(key).replace(/%2F/g, "/")}`;
};

function replyPreviewText(msg: Message): string {
  if (msg.kind === "image") return "[Image]";
  if (msg.kind === "video") return "[Video]";
  if (msg.kind === "audio") return "[Audio]";
  if (msg.kind === "voice_message") return "[Voice message]";
  if (msg.kind === "voicemail") return "[Voicemail]";
  if (msg.kind === "countdown") return `[Countdown: ${msg.countdown_title ?? msg.text ?? ""}]`;
  if (msg.kind === "gif") return "[GIF]";
  if (msg.kind === "sticker") return "[Sticker]";
  if (msg.kind === "find_datetime") return "[Find a Time]";
  if (msg.kind === "file") return msg.file?.name ? `[File: ${msg.file.name}]` : "[File]";
  if (msg.is_encrypted) return "[Encrypted message]";
  return (msg.text ?? "").slice(0, 80) || "[Message]";
}

// ─── MeetingPollCard ──────────────────────────────────────────────

interface MeetingPollCardProps {
  pollStub: MeetingPollAttachment;
  conversationId: string;
  isOwn: boolean;
  currentUserId?: string;
}

function MeetingPollCard({ pollStub, conversationId, isOwn }: MeetingPollCardProps) {
  const queryClient = useQueryClient();

  const { data: poll, isLoading } = useQuery({
    queryKey: ["poll", pollStub.poll_id, conversationId],
    queryFn: () => getMeetingPoll(conversationId, pollStub.poll_id),
    refetchInterval: pollStub.status === "open" ? 15000 : false,
  });

  const voteMut = useMutation({
    mutationFn: (votes: Record<string, "yes" | "no" | "maybe">) =>
      voteMeetingPoll(conversationId, pollStub.poll_id, votes),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["poll", pollStub.poll_id, conversationId] }),
    onError: () => toast.error("Failed to vote"),
  });

  const confirmMut = useMutation({
    mutationFn: ({ slotId, calendarId }: { slotId: string; calendarId?: string }) =>
      confirmMeetingPoll(conversationId, pollStub.poll_id, slotId, calendarId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["poll", pollStub.poll_id, conversationId] }),
    onError: () => toast.error("Failed to confirm slot"),
  });

  const status = poll?.status ?? pollStub.status;
  const isConfirmed = status === "confirmed";
  const confirmedSlot = poll?.slots?.find((s) => s.slot_id === poll.confirmed_slot_id);

  function formatSlotTime(startUtc: string, endUtc: string): string {
    const s = new Date(startUtc);
    const e = new Date(endUtc);
    const date = s.toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" });
    const startT = s.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
    const endT = e.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
    return `${date}, ${startT} – ${endT}`;
  }

  async function handleAddToCalendar(startUtc: string, endUtc: string) {
    // Try to add to first calendar — best effort
    try {
      const { getCalendars } = await import("@/api/endpoints/calendar");
      const cals = await getCalendars();
      const firstCal = cals[0];
      if (!firstCal) { toast.error("No calendars found"); return; }
      await createEvent(firstCal.calendar_id, {
        name: pollStub.title,
        start_utc: startUtc,
        end_utc: endUtc,
        all_day: false,
      });
      toast.success("Added to your calendar");
    } catch {
      toast.error("Failed to add to calendar");
    }
  }

  return (
    <div className="mt-1 rounded-lg border bg-background text-foreground p-3 max-w-sm space-y-2">
      {/* Header */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <Users className="h-5 w-5 shrink-0 text-primary/70" />
          <p className="font-medium text-sm">{poll?.title ?? pollStub.title}</p>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          <span className="text-xs bg-muted rounded-full px-2 py-0.5">
            {poll?.duration_minutes ?? pollStub.duration_minutes} min
          </span>
          {isConfirmed ? (
            <span className="text-xs bg-green-100 text-green-700 rounded-full px-2 py-0.5">✅ Confirmed</span>
          ) : (
            <span className="text-xs bg-blue-100 text-blue-700 rounded-full px-2 py-0.5">🗳️ Voting open</span>
          )}
        </div>
      </div>

      {/* Confirmed slot */}
      {isConfirmed && confirmedSlot && (
        <div className="rounded-md bg-green-50 border border-green-200 px-3 py-2 space-y-1">
          <p className="text-sm font-medium text-green-800">
            {formatSlotTime(confirmedSlot.start_utc, confirmedSlot.end_utc)}
          </p>
          <button
            type="button"
            className="text-xs text-primary hover:underline"
            onClick={() => handleAddToCalendar(confirmedSlot.start_utc, confirmedSlot.end_utc)}
          >
            Add to My Calendar
          </button>
        </div>
      )}

      {/* Slot votes (when open) */}
      {!isConfirmed && (
        <div className="space-y-1">
          {isLoading && <p className="text-xs text-muted-foreground">Loading…</p>}
          {poll?.slots.map((slot) => (
            <div key={slot.slot_id} className="rounded border bg-muted px-2 py-1.5 space-y-1">
              <p className="text-xs font-medium">{formatSlotTime(slot.start_utc, slot.end_utc)}</p>
              <div className="flex flex-wrap items-center gap-2">
                {(["yes", "maybe", "no"] as const).map((choice) => {
                  const label = choice === "yes" ? "👍" : choice === "maybe" ? "🤔" : "👎";
                  const count = choice === "yes" ? slot.yes_count : choice === "maybe" ? slot.maybe_count : slot.no_count;
                  return (
                    <button
                      key={choice}
                      type="button"
                      onClick={() => voteMut.mutate({ [slot.slot_id]: choice })}
                      className={cn(
                        "inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs transition-colors border",
                        slot.my_vote === choice
                          ? "bg-primary text-primary-foreground border-primary"
                          : "hover:bg-muted border-transparent",
                      )}
                    >
                      {label} {count > 0 && count}
                    </button>
                  );
                })}
                {isOwn && (
                  <button
                    type="button"
                    onClick={() => confirmMut.mutate({ slotId: slot.slot_id })}
                    className="text-xs text-primary hover:underline ml-auto"
                  >
                    Confirm →
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── PWA-005: Offline Status Badge ───────────────────────────────

interface OfflineStatusBadgeProps {
  offline: NonNullable<Message["__offline"]>;
  onRetry?: () => void;
  onDiscard?: () => void;
}

function OfflineStatusBadge({ offline, onRetry, onDiscard }: OfflineStatusBadgeProps) {
  if (offline.status === "pending") {
    return (
      <div
        className="flex items-center gap-1 text-xs text-muted-foreground mt-1 animate-pulse"
        role="status"
        aria-label="Message queued, will send when online"
      >
        <Clock className="h-3 w-3" />
        <span>Sending when online...</span>
      </div>
    );
  }

  if (offline.status === "sending") {
    return (
      <div
        className="flex items-center gap-1 text-xs text-blue-500 mt-1"
        role="status"
        aria-label="Sending message"
      >
        <Loader2 className="h-3 w-3 animate-spin" />
        <span>Sending...</span>
      </div>
    );
  }

  if (offline.status === "failed") {
    return (
      <div
        className="flex items-center gap-1 text-xs text-destructive mt-1 flex-wrap"
        role="alert"
        aria-label={`Message failed to send: ${offline.error ?? "Unknown error"}`}
      >
        <AlertCircle className="h-3 w-3 shrink-0" />
        <span>{offline.error ?? "Failed to send"}</span>
        {onRetry && (
          <Button
            variant="ghost"
            size="sm"
            className="h-5 px-1.5 text-xs text-destructive hover:text-destructive"
            onClick={(e) => { e.stopPropagation(); onRetry(); }}
            aria-label="Retry sending message"
          >
            <RotateCcw className="h-3 w-3 mr-0.5" />
            Retry
          </Button>
        )}
        {onDiscard && (
          <Button
            variant="ghost"
            size="sm"
            className="h-5 px-1.5 text-xs text-muted-foreground hover:text-destructive"
            onClick={(e) => { e.stopPropagation(); onDiscard(); }}
            aria-label="Discard queued message"
          >
            <Trash2 className="h-3 w-3 mr-0.5" />
            Discard
          </Button>
        )}
      </div>
    );
  }

  return null;
}

export function MessageBubble({ message, isOwn, showSender, conversationId, onReply, onViewThread, replyToMessage, viewedOnceIds, onViewOnce, resolveSenderName }: MessageBubbleProps) {
  const senderLabel = (id: string) => resolveSenderName?.(id) ?? id;
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [forwardOpen, setForwardOpen] = useState(false);
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  const [decryptOpen, setDecryptOpen] = useState(false);
  const [decrypting, setDecrypting] = useState(false);
  const [decryptPassword, setDecryptPassword] = useState("");
  const [decryptError, setDecryptError] = useState<string | null>(null);
  const [decryptedText, setDecryptedText] = useState<string | null>(null);
  const [decryptedMediaUrl, setDecryptedMediaUrl] = useState<string | null>(null);
  const [openingOnce, setOpeningOnce] = useState(false);
  const [onceError, setOnceError] = useState<string | null>(null);
  const [isEditing, setIsEditing] = useState(false);
  const [editText, setEditText] = useState("");
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [lightboxOpen, setLightboxOpen] = useState(false);
  const [emojiPickerOpen, setEmojiPickerOpen] = useState(false);
  const [fullPickerOpen, setFullPickerOpen] = useState(false);
  // MSG-011: emoji currently playing the pop animation (briefly set on add).
  const [animatingEmoji, setAnimatingEmoji] = useState<string | null>(null);
  const [tipStep, setTipStep] = useState<null | "amount" | "confirm">(null);
  const [tipAmount, setTipAmount] = useState("");
  const [selectedPaymentMethodId, setSelectedPaymentMethodId] = useState<string | null>(null);
  const [showDecryptPassword, setShowDecryptPassword] = useState(false);
  const [expiryCountdown, setExpiryCountdown] = useState<string | null>(null);
  const [unlockDialogOpen, setUnlockDialogOpen] = useState(false);
  const [unlockPaymentMethodId, setUnlockPaymentMethodId] = useState<string | null>(null);
  const [fileSharePreviewOpen, setFileSharePreviewOpen] = useState(false);
  const [filePreviewOpen, setFilePreviewOpen] = useState(false);
  // BOT-002: quick-reply buttons are disabled after the first tap.
  const [quickReplySent, setQuickReplySent] = useState(false);
  const [reportOpen, setReportOpen] = useState(false);
  const [reportServerError, setReportServerError] = useState<string | null>(null);
  const [reportTarget, setReportTarget] = useState<"message" | "attachment">("message");
  const [lotteryRevealPhase, setLotteryRevealPhase] = useState<LotteryRevealPhase>("idle");
  const [lotteryRevealError, setLotteryRevealError] = useState<string | null>(null);
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(false);
  const revealTimerRef = useRef<number | null>(null);
  // MVA-006: per-message translation. `translatedText` holds the fetched
  // translation; `showOriginal` toggles between original and translation.
  const [translatedText, setTranslatedText] = useState<string | null>(
    message.translation?.translated_text ?? null,
  );
  const [translationLang, setTranslationLang] = useState<string | null>(
    message.translation?.target_lang ?? null,
  );
  const [showOriginal, setShowOriginal] = useState(false);

  const viewOnceTextRevealed = viewedOnceIds?.has(message.message_id) ?? false;

  const { data: paymentMethods = [] } = useQuery<PaymentMethod[]>({
    queryKey: ["billing", "payment-methods"],
    queryFn: getPaymentMethods,
    staleTime: 5 * 60 * 1000,
    enabled: !isOwn, // only needed for recipient bubbles (Send Tip, Unlock)
  });

  useEffect(() => {
    if (!message.expires_at) return;
    const compute = () => {
      const diffSec = Math.floor(message.expires_at! - Date.now() / 1000);
      if (diffSec <= 0) { setExpiryCountdown("expired"); return; }
      const h = Math.floor(diffSec / 3600);
      const m = Math.floor((diffSec % 3600) / 60);
      const s = diffSec % 60;
      if (h > 0) setExpiryCountdown(`in ${h}h ${m}m`);
      else if (m > 0) setExpiryCountdown(`in ${m}m ${s}s`);
      else setExpiryCountdown(`in ${s}s`);
    };
    compute();
    const id = setInterval(compute, 1000);
    return () => clearInterval(id);
  }, [message.expires_at]);

  // When the message expires client-side, refresh both messages and conversations
  // so the backend expired state propagates to the sidebar preview.
  useEffect(() => {
    if (expiryCountdown === "expired") {
      void queryClient.invalidateQueries({ queryKey: ["messages", conversationId] });
      void queryClient.invalidateQueries({ queryKey: ["conversations"] });
    }
  }, [expiryCountdown, queryClient, conversationId]);

  // MVA-005/006: when the server projects a translation (auto-translate on),
  // adopt it as the displayed translation without an extra fetch.
  useEffect(() => {
    if (message.translation?.translated_text) {
      setTranslatedText(message.translation.translated_text);
      setTranslationLang(message.translation.target_lang ?? null);
    }
  }, [message.translation?.translated_text, message.translation?.target_lang]);

  const deleteMut = useMutation({
    mutationFn: () => deleteMessage(conversationId, message.message_id),
    onSuccess: () => {
      toast.success("Message deleted");
      void queryClient.invalidateQueries({ queryKey: ["messages", conversationId] });
      setDeleteConfirmOpen(false);
    },
    onError: () => toast.error("Failed to delete message"),
  });

  const editMut = useMutation({
    mutationFn: (text: string) => editMessage(conversationId, message.message_id, { text }),
    onSuccess: () => {
      toast.success("Message edited");
      void queryClient.invalidateQueries({ queryKey: ["messages", conversationId] });
      setIsEditing(false);
    },
    onError: () => toast.error("Failed to edit message"),
  });

  // MVA-006: translate this message into the viewer's target language.
  const translateMut = useMutation({
    mutationFn: (targetLang: string) =>
      translateMessage(conversationId, message.message_id, targetLang),
    onSuccess: (resp) => {
      setTranslatedText(resp.translated_text);
      setTranslationLang(resp.target_lang);
      setShowOriginal(false);
    },
    onError: (err) => {
      if (err instanceof ApiError && err.status === 404) {
        toast.error("Translation is not enabled on this server");
      } else if (err instanceof ApiError && err.status === 429) {
        toast.error("Too many translation requests — try again shortly");
      } else if (err instanceof ApiError && err.status === 400) {
        toast.error("This message cannot be translated");
      } else {
        toast.error("Failed to translate message");
      }
    },
  });

  const reactMut = useMutation({
    mutationFn: (emoji: string) => {
      const alreadyReacted = (message.my_reactions ?? []).includes(emoji);
      const action = alreadyReacted ? "remove" : "add";
      // MSG-011: play the pop animation only when adding a reaction.
      const playPopAnimation = action === "add";
      return reactToMessage(conversationId, message.message_id, emoji, action).then(async () => {
        await queryClient.invalidateQueries({ queryKey: ["messages", conversationId] });
        void queryClient.invalidateQueries({ queryKey: ["conversations"] });
        // Start the pop animation only once the badge is actually rendered
        // (i.e. after the refetch lands), otherwise the 320ms window expires
        // during the network round-trip and the badge mounts without the class.
        if (playPopAnimation) {
          setAnimatingEmoji(emoji);
          window.setTimeout(
            () => setAnimatingEmoji((cur) => (cur === emoji ? null : cur)),
            320,
          );
        }
      });
    },
    onError: (err: unknown) => {
      const detail =
        err instanceof ApiError ? (err.body as { detail?: string } | undefined)?.detail : undefined;
      toast.error(detail || "Failed to react");
    },
  });

  // MSG-011: double-tap the message body to quickly add/remove a heart reaction.
  const handleQuickReact = useCallback(() => {
    if (message.__offline || message.revoked_at) return;
    reactMut.mutate(QUICK_REACT_EMOJI);
  }, [message.__offline, message.revoked_at, reactMut]);

  // MSG-011: pick from the full emoji picker (incl. custom emojis) as a reaction.
  const handlePickReaction = useCallback(
    (picked: string) => {
      reactMut.mutate(normalizeReactionKey(picked));
      setFullPickerOpen(false);
      setEmojiPickerOpen(false);
    },
    [reactMut],
  );

  const hideMut = useMutation({
    mutationFn: () => hideMessage(conversationId, message.message_id),
    onMutate: async () => {
      await queryClient.cancelQueries({ queryKey: ["messages", conversationId] });
      const snapshot = queryClient.getQueryData(["messages", conversationId]);

      queryClient.setQueryData<InfiniteData<{ messages: Message[]; next_cursor?: string }>>(
        ["messages", conversationId],
        (old) => {
          if (!old?.pages?.length) return old;
          return {
            ...old,
            pages: old.pages.map((page) => ({
              ...page,
              messages: (page.messages ?? []).filter((m) => m.message_id !== message.message_id),
            })),
          };
        },
      );

      return { snapshot };
    },
    onSuccess: () => {
      toast.success("Message hidden");
      void queryClient.invalidateQueries({ queryKey: ["hidden-messages", conversationId] });
    },
    onError: (_err, _vars, context) => {
      if (context?.snapshot) {
        queryClient.setQueryData(["messages", conversationId], context.snapshot);
      }
      toast.error("Failed to hide message");
    },
  });

  const reportMut = useMutation({
    mutationFn: ({ topics, reason_text }: ReportContentPayload) => reportMessage(conversationId, message.message_id, {
      reason_code: topics[0] ?? "",
      statement: reason_text,
    }),
    onSuccess: () => {
      toast.success("Report received");
      setReportOpen(false);
      setReportServerError(null);
      setReportTarget("message");
    },
    onError: (error) => {
      if (error instanceof ApiError && typeof error.message === "string" && error.message.trim()) {
        setReportServerError(error.message);
      } else {
        setReportServerError("Could not submit report. Please try again.");
      }
      toast.error("Could not submit report. Please try again.");
    },
  });

  const unlockMut = useMutation({
    mutationFn: (paymentMethodId?: string | null) =>
      unlockMessage(conversationId, message.message_id, paymentMethodId ?? undefined),
    onSuccess: () => {
      toast.success("Message unlocked!");
      setUnlockDialogOpen(false);
      void queryClient.invalidateQueries({ queryKey: ["messages", conversationId] });
      // Also refresh sidebar so the preview shows the unlocked text instead of "[Locked message]"
      void queryClient.invalidateQueries({ queryKey: ["conversations"] });
    },
    onError: () => toast.error("Failed to unlock message"),
  });
  const unlockLotteryMut = useMutation({
    mutationFn: () => unlockLotteryMessage(message.message_id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["messages", conversationId] });
      void queryClient.invalidateQueries({ queryKey: ["conversations"] });
    },
  });

  const tipMut = useMutation({
    mutationFn: () => {
      const cents = Math.round(parseFloat(tipAmount) * 100);
      if (isNaN(cents) || cents < 1) throw new Error("Invalid tip amount");
      if (!selectedPaymentMethodId) throw new Error("Select a payment method");
      return sendMessageTip(conversationId, message.message_id, {
        amount_cents: cents,
        currency: "USD",
        payment_method_id: selectedPaymentMethodId,
      });
    },
    onSuccess: () => {
      toast.success("Tip sent!");
      setTipStep(null);
      setTipAmount("");
      setSelectedPaymentMethodId(null);
      void queryClient.invalidateQueries({ queryKey: ["messages", conversationId] });
    },
    onError: (err: Error) => toast.error(err.message || "Failed to send tip"),
  });

  // BOT-002: tapping a quick-reply sends its `value` as a regular text message.
  const quickReplyMut = useMutation({
    mutationFn: (value: string) => sendTextMessage(conversationId, { text: value }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["messages", conversationId] });
    },
    onError: (err: Error) => {
      setQuickReplySent(false);
      toast.error(err.message || "Failed to send reply");
    },
  });

  const time = new Date(message.created_at * 1000).toLocaleTimeString(undefined, {
    hour: "numeric",
    minute: "2-digit",
  });
  const threadReplyCount = typeof message.thread_reply_count === "number" ? message.thread_reply_count : undefined;
  const hasThreadEntry = !!message.has_thread && !!threadReplyCount && threadReplyCount > 0;
  const threadReplyLabel = threadReplyCount === 1 ? "1 reply" : `${threadReplyCount ?? 0} replies`;
  const threadLastActivityLabel =
    message.thread_last_reply_at && message.thread_last_reply_at > 0
      ? new Date(message.thread_last_reply_at * 1000).toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" })
      : undefined;

  if (message.revoked_at || message.revoked) {
    return (
      <div className={cn("flex", isOwn ? "justify-end" : "justify-start")}>
        <div className="max-w-[75%] rounded-2xl px-4 py-2 text-sm italic text-muted-foreground bg-muted/50">
          Message deleted
        </div>
      </div>
    );
  }

  const isFileKind = message.kind === "file" || message.kind === "audio" || message.kind === "video";
  const isLotteryMessage = message.lottery?.message_type === "lottery_dm";
  const lotteryLockedForRecipient = !!(isLotteryMessage && message.lottery?.lock_state === "locked" && !isOwn);
  const lotterySelectedOutcome = message.lottery?.selected_outcome;
  const lotterySelectedMediaUrl = buildS3ObjectUrl(
    message.lottery?.selected_outcome?.media_metadata?.bucket,
    message.lottery?.selected_outcome?.media_metadata?.key,
  );
  const lotteryShowingTransition = lotteryRevealPhase === "unlocking" || lotteryRevealPhase === "revealing";
  const showLotteryLockCard = lotteryLockedForRecipient || lotteryShowingTransition;

  useEffect(() => {
    const media = window.matchMedia("(prefers-reduced-motion: reduce)");
    const sync = () => setPrefersReducedMotion(media.matches);
    sync();
    media.addEventListener("change", sync);
    return () => media.removeEventListener("change", sync);
  }, []);

  useEffect(() => {
    setLotteryRevealError(null);
    setLotteryRevealPhase(message.lottery?.lock_state === "unlocked" ? "revealed" : "idle");
    if (revealTimerRef.current) {
      window.clearTimeout(revealTimerRef.current);
      revealTimerRef.current = null;
    }
  }, [message.message_id, message.lottery?.lock_state]);

  useEffect(() => () => {
    if (revealTimerRef.current) {
      window.clearTimeout(revealTimerRef.current);
      revealTimerRef.current = null;
    }
  }, []);

  const startLotteryReveal = () => {
    if (prefersReducedMotion) {
      setLotteryRevealPhase("revealed");
      toast.success("Lottery unlocked!");
      return;
    }
    setLotteryRevealPhase("revealing");
    revealTimerRef.current = window.setTimeout(() => {
      setLotteryRevealPhase("revealed");
      toast.success("Lottery unlocked!");
      revealTimerRef.current = null;
    }, 850);
  };

  const handleUnlockLottery = async () => {
    if (unlockLotteryMut.isPending) return;
    setLotteryRevealError(null);
    setLotteryRevealPhase("unlocking");
    try {
      await unlockLotteryMut.mutateAsync();
      startLotteryReveal();
    } catch (error) {
      const fallback = "Unable to unlock lottery right now. Please retry.";
      if (error instanceof ApiError && error.status === 429) {
        setLotteryRevealError("Too many unlock attempts. Please wait a moment, then retry.");
      } else if (error instanceof ApiError && error.message.trim()) {
        setLotteryRevealError(error.message);
      } else {
        setLotteryRevealError(fallback);
      }
      setLotteryRevealPhase("idle");
    }
  };

  const handleDecrypt = async () => {
    if (!message.encryption || !decryptPassword || decrypting) return;

    setDecryptError(null);
    setDecrypting(true);
    try {
      const isMedia = message.kind === "image" || message.kind === "file" || message.kind === "video";
      if (isMedia) {
        const url = message.image?.url ?? message.file?.url;
        if (!url) throw new Error("No URL for encrypted media");
        const resp = await fetch(url);
        if (!resp.ok) throw new Error("Failed to fetch encrypted media");
        const encryptedBytes = new Uint8Array(await resp.arrayBuffer());
        const decryptedBytesResult = await decryptBytes(encryptedBytes, message.encryption as MessageEncryptionEnvelope, decryptPassword);
        const contentType = message.image?.content_type ?? message.file?.content_type ?? "application/octet-stream";
        const blob = new Blob([decryptedBytesResult], { type: contentType });
        setDecryptedMediaUrl(URL.createObjectURL(blob));
      } else {
        const decrypted = await decryptMessage(message.encryption as MessageEncryptionEnvelope, decryptPassword);
        setDecryptedText(decrypted);
      }
      setDecryptOpen(false);
      setDecryptPassword("");
      setDecryptError(null);
    } catch (err) {
      if (err instanceof MessageCryptoError && err.code === "wrong_password") {
        setDecryptError("Wrong password. Please try again.");
      } else if (err instanceof MessageCryptoError && err.code === "tampered_payload") {
        setDecryptError("This encrypted message appears corrupted or tampered.");
      } else {
        setDecryptError("Unable to decrypt message. Please retry.");
      }
    } finally {
      setDecrypting(false);
    }
  };

  const handleOpenOnceAttachment = async () => {
    if (openingOnce || !message.consumption_policy || message.consumption_state === "consumed") return;
    setOpeningOnce(true);
    setOnceError(null);
    try {
      // Step 1: Create grant (validates state is pending)
      const grant = await createOnceMediaAttachmentGrant(conversationId, message.message_id);

      // Step 2: Download BEFORE consuming — the download endpoint validates state == pending
      const url = buildAttachmentDownloadUrl(conversationId, message.message_id, grant.grant_token);
      const response = await fetch(url, {
        method: "GET",
        credentials: "include",
        cache: "no-store",
        referrerPolicy: "no-referrer",
      });
      if (!response.ok) {
        throw new Error("once_media_fetch_failed");
      }
      const blob = await response.blob();

      // Step 3: Consume (mark as used) AFTER downloading
      const trigger = consumeTrigger(message);
      await consumeOnceMediaAttachment(conversationId, message.message_id, grant.grant_token, {
        consumption_attempt_id: `attempt-${message.message_id}-${Date.now()}`,
        trigger,
        playback_seconds: playbackThresholdSeconds(message),
      });

      // Step 4: Open the blob in an ephemeral window
      openBlobInEphemeralWindow(blob);
      await queryClient.invalidateQueries({ queryKey: ["messages", conversationId] });
    } catch (err) {
      if (err instanceof ApiError && err.body && typeof err.body === "object") {
        const detail = (err.body as { detail?: { code?: string } }).detail;
        setOnceError(onceErrorMessageFromCode(detail?.code));
      } else {
        setOnceError("Unable to open once-media attachment.");
      }
    } finally {
      setOpeningOnce(false);
    }
  };

  const encryptedEnabled = isMessagingEncryptionEnabled();
  const encryptedSupported = encryptedEnabled && isMessageCryptoSupported();
  const hasDecryptableEnvelope = Boolean(message.encryption);
  const showUnsupportedEncryptedState = message.is_encrypted && (!encryptedSupported || !hasDecryptableEnvelope);
  const onceMediaLabel = onceLabel(message);
  const canForward = !message.consumption_policy;
  // MVA-006: a message is translatable if the feature is enabled, it is a text
  // message with visible text, and it is not encrypted / view-once / a locked
  // message the viewer cannot read.
  const canTranslate =
    isMessagingTranslationEnabled() &&
    message.kind === "text" &&
    !message.is_encrypted &&
    !message.view_once &&
    !(message.lock_price_cents && !isOwn && !message.is_unlocked) &&
    typeof message.text === "string" &&
    message.text.trim().length > 0;

  return (
    <>
      <div className={cn("flex", isOwn ? "justify-end" : "justify-start")}>
        <div
          data-testid="message-bubble"
          onDoubleClick={handleQuickReact}
          className={cn(
            "group relative max-w-[75%] rounded-2xl px-4 py-2 transition-opacity",
            isOwn
              ? "bg-primary text-primary-foreground"
              : "bg-muted text-foreground",
            message.__offline?.status === "pending" && "opacity-70",
            message.__offline?.status === "sending" && "opacity-85",
            message.__offline?.status === "failed" && "opacity-90 ring-1 ring-destructive/30",
          )}
        >
          {!message.__offline && (<div className={cn(
            "absolute -top-2 opacity-0 transition-opacity group-hover:opacity-100 flex items-center gap-0.5",
            isOwn ? "left-0 -translate-x-full pr-1" : "right-0 translate-x-full pl-1",
          )}>
            {/* Quick emoji reactions */}
            <div className="relative">
              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7 rounded-full bg-background shadow-sm"
                onClick={() => setEmojiPickerOpen((v) => !v)}
                aria-label="React"
              >
                <Smile className="h-3.5 w-3.5" />
              </Button>
              {emojiPickerOpen && (
                <div className={cn(
                  "absolute top-full mt-1 z-50 flex items-center gap-1 rounded-full border border-border bg-popover p-1 shadow-lg",
                  isOwn ? "right-0" : "left-0",
                )}>
                  {QUICK_EMOJIS.map((emoji) => (
                    <button
                      key={emoji}
                      onClick={() => { reactMut.mutate(emoji); setEmojiPickerOpen(false); }}
                      className={cn(
                        "flex h-7 w-7 items-center justify-center rounded-full text-base transition-colors hover:bg-accent",
                        (message.my_reactions ?? []).includes(emoji) && "bg-primary/10",
                      )}
                    >
                      {emoji}
                    </button>
                  ))}
                  {/* MSG-011: open the full emoji picker (incl. custom emojis) */}
                  <button
                    aria-label="More reactions"
                    data-testid="reaction-more-button"
                    onClick={() => { setEmojiPickerOpen(false); setFullPickerOpen(true); }}
                    className="flex h-7 w-7 items-center justify-center rounded-full text-base transition-colors hover:bg-accent"
                  >
                    <SmilePlus className="h-4 w-4" />
                  </button>
                </div>
              )}
              {/* MSG-011: full emoji picker for reactions (Unicode + custom) */}
              {fullPickerOpen && (
                <div className={cn(
                  "absolute top-full mt-1 z-50",
                  isOwn ? "right-0" : "left-0",
                )}>
                  <EmojiPicker
                    onSelect={handlePickReaction}
                    onClose={() => setFullPickerOpen(false)}
                  />
                </div>
              )}
            </div>

            {/* Reply button */}
            {onReply && (
              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7 rounded-full bg-background shadow-sm"
                onClick={() => onReply(message)}
                aria-label="Reply"
              >
                <Reply className="h-3.5 w-3.5" />
              </Button>
            )}

            {/* More actions dropdown */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon" className="h-7 w-7 rounded-full bg-background shadow-sm" aria-label="Message actions">
                  <MoreHorizontal className="h-3.5 w-3.5" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align={isOwn ? "start" : "end"}>
                <DropdownMenuItem onClick={() => setDetailsOpen(true)}>
                  <Info className="mr-2 h-4 w-4" /> Details
                </DropdownMenuItem>
                {canForward && (
                  <DropdownMenuItem onClick={() => setForwardOpen(true)}>
                    <Forward className="mr-2 h-4 w-4" /> Forward
                  </DropdownMenuItem>
                )}
                {onReply && (
                  <DropdownMenuItem onClick={() => onReply(message)}>
                    <Reply className="mr-2 h-4 w-4" /> Reply
                  </DropdownMenuItem>
                )}
                {canTranslate && (
                  <DropdownMenuItem
                    onClick={() => translateMut.mutate(messagingTranslationDefaultLang)}
                    disabled={translateMut.isPending}
                  >
                    {translateMut.isPending ? (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    ) : (
                      <Languages className="mr-2 h-4 w-4" />
                    )}{" "}
                    Translate
                  </DropdownMenuItem>
                )}
                <DropdownMenuItem onClick={() => hideMut.mutate()} disabled={hideMut.isPending}>
                  {hideMut.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <EyeOff className="mr-2 h-4 w-4" />} Hide for me
                </DropdownMenuItem>
                {!isOwn && (
                  <DropdownMenuItem onClick={() => { setReportTarget("message"); setReportOpen(true); }}>
                    <Flag className="mr-2 h-4 w-4" /> Report message
                  </DropdownMenuItem>
                )}
                {!isOwn && (
                  paymentMethods.length === 0 ? (
                    <TooltipProvider delayDuration={100}>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <div>
                            <DropdownMenuItem disabled className="cursor-not-allowed opacity-50">
                              <DollarSign className="mr-2 h-4 w-4" /> Send Tip
                            </DropdownMenuItem>
                          </div>
                        </TooltipTrigger>
                        <TooltipContent side="right">
                          Add a payment method in Billing to send tips
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  ) : (
                    <DropdownMenuItem onClick={() => {
                      const def = paymentMethods.find((m) => m.is_default) ?? paymentMethods[0];
                      setSelectedPaymentMethodId(def?.payment_method_id ?? null);
                      setTipStep("amount");
                    }}>
                      <DollarSign className="mr-2 h-4 w-4" /> Send Tip
                    </DropdownMenuItem>
                  )
                )}
                {isOwn && !message.is_encrypted && !message.lock_price_cents && message.kind === "text" && (
                  <DropdownMenuItem onClick={() => { setEditText(message.text ?? ""); setIsEditing(true); }}>
                    <Pencil className="mr-2 h-4 w-4" /> Edit
                  </DropdownMenuItem>
                )}
                {isOwn && (
                  <DropdownMenuItem
                    className="text-destructive focus:text-destructive"
                    onClick={() => setDeleteConfirmOpen(true)}
                  >
                    <Trash2 className="mr-2 h-4 w-4" /> Delete
                  </DropdownMenuItem>
                )}
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
          )}

          {replyToMessage && (
            <div className={cn(
              "mb-1.5 rounded-lg border-l-2 px-2 py-1 text-xs",
              isOwn
                ? "border-primary-foreground/40 bg-primary-foreground/10"
                : "border-primary/40 bg-muted",
            )}>
              <p className="font-semibold opacity-70 mb-0.5">{senderLabel(replyToMessage.sender_id)}</p>
              <p className="line-clamp-2 opacity-60">{replyPreviewText(replyToMessage)}</p>
            </div>
          )}

          {showSender && !isOwn && (
            <p className="mb-0.5 text-xs font-semibold text-primary">
              {message.sender_type === "bot" ? (message.bot_name ?? message.sender_id) : senderLabel(message.sender_id)}
              {message.sender_type === "bot" && (
                <span className="ml-1 inline-flex items-center rounded border px-1 py-0 text-[10px] font-medium text-muted-foreground align-middle">Bot</span>
              )}
            </p>
          )}

          {onceMediaLabel && (
            <div className="mb-1 text-[10px] uppercase tracking-wide">
              <span className={cn(
                "rounded-full px-2 py-0.5 font-semibold",
                isOwn ? "bg-primary-foreground/20 text-primary-foreground" : "bg-background/70",
              )}>{onceMediaLabel}</span>
              {message.consumption_state && (
                <span className="ml-2 text-muted-foreground">{message.consumption_state}</span>
              )}
            </div>
          )}

          {(expiryCountdown === "expired" || message.expired) ? (
            <div className="flex items-center gap-1.5 rounded-lg bg-muted/50 px-3 py-2 text-xs text-muted-foreground italic">
              <EyeOff className="h-3.5 w-3.5 shrink-0" />
              This message has expired
            </div>
          ) : showLotteryLockCard ? (
            <div className="space-y-2 rounded-lg border border-amber-300/70 bg-amber-50/60 px-3 py-2">
              <div className="inline-flex items-center gap-1.5 rounded-full bg-amber-100 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-amber-800">
                <Lock className="h-3 w-3" />
                Locked lottery
              </div>
              <p className="text-xs text-amber-900">
                {lotteryRevealPhase === "unlocking"
                  ? "Contacting server to unlock your lottery outcome…"
                  : lotteryRevealPhase === "revealing"
                  ? "Unlock complete. Revealing your outcome…"
                  : "Unlock this lottery message to reveal your outcome."}
              </p>
              <Button
                type="button"
                size="sm"
                variant="secondary"
                className="h-7 px-2 text-xs"
                onClick={() => void handleUnlockLottery()}
                disabled={unlockLotteryMut.isPending || lotteryRevealPhase === "revealing"}
              >
                {lotteryRevealPhase === "unlocking" || lotteryRevealPhase === "revealing" ? (
                  <>
                    <span className="mr-1 inline-flex"><LotterySpinner phase={lotteryRevealPhase} reducedMotion={prefersReducedMotion} /></span>
                    {lotteryRevealPhase === "revealing" ? "Revealing…" : "Unlocking…"}
                  </>
                ) : (
                  <>
                    <Dices className="mr-1 h-3 w-3" />
                    Unlock outcome
                  </>
                )}
              </Button>
              {!prefersReducedMotion && lotteryRevealPhase === "revealing" && (
                <p className="text-[10px] text-amber-800">Spinner animation is enabled. Outcome appears after a short reveal.</p>
              )}
              {prefersReducedMotion && lotteryRevealPhase === "unlocking" && (
                <p className="text-[10px] text-amber-800">Reduced motion enabled: reveal animation is minimized.</p>
              )}
              {lotteryRevealError && (
                <p className="text-[10px] text-amber-800">Unlock failed: {lotteryRevealError}. Your message is unchanged — please retry.</p>
              )}
            </div>
          ) : isLotteryMessage ? (
            <div className="space-y-1.5 rounded-lg border border-primary/20 bg-primary/5 px-3 py-2">
              <div className="inline-flex items-center gap-1.5 rounded-full bg-primary/15 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-primary">
                <Dices className="h-3 w-3" />
                {message.lottery?.lock_state === "locked" ? "Lottery (locked)" : "Lottery result"}
              </div>
              {message.lottery?.lock_state === "locked" ? (
                <p className="text-xs text-muted-foreground">
                  Waiting for recipient to unlock this lottery message.
                </p>
              ) : lotterySelectedOutcome ? (
                <>
                  <p className="text-xs font-medium">
                    Outcome: {lotterySelectedOutcome.outcome_id}
                  </p>
                  {lotterySelectedOutcome.payload_type === "text" ? (
                    lotterySelectedOutcome.text_content ? (
                      <p className="whitespace-pre-wrap break-words text-sm">{lotterySelectedOutcome.text_content}</p>
                    ) : (
                      <p className="text-xs text-muted-foreground">Text outcome selected (no text payload).</p>
                    )
                  ) : lotterySelectedOutcome.payload_type === "image" ? (
                    lotterySelectedMediaUrl ? (
                      <img
                        src={lotterySelectedMediaUrl}
                        alt="Lottery image outcome"
                        className="mt-1 max-h-64 rounded-lg object-cover"
                      />
                    ) : (
                      <p className="text-xs text-muted-foreground">
                        Image outcome selected{lotterySelectedOutcome.media_asset_id ? ` · Asset: ${lotterySelectedOutcome.media_asset_id}` : ""}.
                      </p>
                    )
                  ) : lotterySelectedOutcome.payload_type === "video" ? (
                    lotterySelectedMediaUrl ? (
                      <video
                        src={lotterySelectedMediaUrl}
                        className="mt-1 max-h-64 w-full rounded-lg"
                        controls
                        playsInline
                        preload="metadata"
                      />
                    ) : (
                      <p className="text-xs text-muted-foreground">
                        Video outcome selected{lotterySelectedOutcome.media_asset_id ? ` · Asset: ${lotterySelectedOutcome.media_asset_id}` : ""}.
                      </p>
                    )
                  ) : (
                    <p className="text-xs text-muted-foreground">
                      {String(lotterySelectedOutcome.payload_type).toUpperCase()} outcome selected
                    </p>
                  )}
                </>
              ) : (
                <p className="text-xs text-muted-foreground">Outcome not available yet.</p>
              )}
            </div>
          ) : message.lock_price_cents && !message.is_unlocked && !isOwn ? (
            // Recipient view: locked message — show paywall BEFORE any decrypt UI so that
            // encryption does not bypass the unlock requirement.
            <div className="space-y-2">
              {/* Blurred preview for locked single images */}
              {message.kind === "image" && message.image?.preview_url && (
                <div className="relative overflow-hidden rounded-lg">
                  <img
                    src={message.image.preview_url}
                    alt="Locked image preview"
                    className="w-full max-h-48 object-cover"
                    style={{ imageRendering: "pixelated", filter: "blur(2px)", transform: "scale(1.05)" }}
                  />
                  <div className="absolute inset-0 flex items-center justify-center bg-black/20">
                    <Lock className="h-8 w-8 text-white drop-shadow" />
                  </div>
                </div>
              )}
              <div className="inline-flex items-center gap-1.5 rounded-full bg-background/60 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide">
                <Lock className="h-3 w-3" />
                {`Lock · $${(message.lock_price_cents / 100).toFixed(2)}`}
              </div>
              {message.lock_description && (
                <p className="text-xs text-muted-foreground italic">{message.lock_description}</p>
              )}
              {paymentMethods.length === 0 ? (
                <TooltipProvider delayDuration={100}>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <div>
                        <Button type="button" size="sm" variant="secondary" className="h-7 px-2 text-xs cursor-not-allowed opacity-50" disabled>
                          <CreditCard className="mr-1 h-3 w-3" />
                          {`Unlock for $${(message.lock_price_cents / 100).toFixed(2)}`}
                        </Button>
                      </div>
                    </TooltipTrigger>
                    <TooltipContent>Add a payment method in Billing to unlock this message</TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              ) : (
                <Button
                  type="button"
                  size="sm"
                  variant="secondary"
                  className="h-7 px-2 text-xs"
                  onClick={() => {
                    const def = paymentMethods.find((m) => m.is_default) ?? paymentMethods[0];
                    setUnlockPaymentMethodId(def?.payment_method_id ?? null);
                    setUnlockDialogOpen(true);
                  }}
                >
                  <CreditCard className="mr-1 h-3 w-3" />
                  {`Unlock for $${(message.lock_price_cents / 100).toFixed(2)}`}
                </Button>
              )}
            </div>
          ) : message.is_encrypted ? (
            // Encrypted message — shown after lock is cleared (non-owner has paid, or sender, or no lock)
            <div className="space-y-1">
              <span className="inline-flex items-center gap-1 rounded-full bg-background/60 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide">
                <Lock className="h-3 w-3" /> Encrypted
              </span>
              {(message.kind === "image" || isFileKind) ? (
                decryptedMediaUrl ? (
                  message.kind === "image" ? (
                    <img src={decryptedMediaUrl} alt="Decrypted image" className="max-h-64 rounded-lg object-cover mt-1" />
                  ) : message.kind === "video" ? (
                    <video src={decryptedMediaUrl} className="max-h-64 rounded-lg mt-1 w-full" controls playsInline />
                  ) : (
                    <a
                      href={decryptedMediaUrl}
                      download={message.file?.name ?? "file"}
                      className="mt-1 inline-flex items-center gap-1.5 rounded-md bg-background/60 px-3 py-1.5 text-sm hover:bg-background/80"
                    >
                      <Download className="h-4 w-4" />
                      Download {message.file?.name ?? "file"}
                    </a>
                  )
                ) : (
                  <>
                    <p className="whitespace-pre-wrap break-words text-sm italic">
                      {message.kind === "image" ? "Encrypted image" : message.kind === "video" ? "Encrypted video" : "Encrypted file"}
                    </p>
                    {!showUnsupportedEncryptedState && (
                      <div>
                        <Button
                          size="sm"
                          variant="secondary"
                          className="h-7 px-2 text-xs"
                          onClick={() => { setDecryptOpen(true); setDecryptError(null); }}
                        >
                          Decrypt to view
                        </Button>
                      </div>
                    )}
                  </>
                )
              ) : decryptedText ? (
                <p
                  className={cn(
                    "whitespace-pre-wrap break-words text-sm",
                    isEmojiOnly(decryptedText) && "text-5xl leading-relaxed py-1",
                  )}
                >
                  {decryptedText}
                </p>
              ) : (
                <>
                  <p className="whitespace-pre-wrap break-words text-sm italic">
                    {showUnsupportedEncryptedState
                      ? "Encrypted message unsupported"
                      : "Encrypted message"}
                  </p>
                  {showUnsupportedEncryptedState ? (
                    <p className="text-xs text-muted-foreground">
                      Update to a client with encrypted messaging support and verify your environment enables it.
                    </p>
                  ) : (
                    <div className="space-y-1">
                      <p className="text-xs text-muted-foreground">
                        {isOwn
                          ? "To change content, delete and resend this encrypted message."
                          : "End-to-end encrypted — decrypt to read."}
                      </p>
                      <Button
                        type="button"
                        size="sm"
                        variant="secondary"
                        className="h-7 px-2 text-xs"
                        onClick={() => {
                          setDecryptOpen(true);
                          setDecryptError(null);
                        }}
                      >
                        Decrypt message
                      </Button>
                    </div>
                  )}
                </>
              )}
            </div>
          ) : message.lock_price_cents && isOwn ? (
            // Sender view: show lock badge + the original text they sent
            <div className="space-y-1.5">
              <div className="inline-flex items-center gap-1.5 rounded-full bg-primary-foreground/20 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-primary-foreground">
                <Lock className="h-3 w-3" />
                {`Locked · $${(message.lock_price_cents / 100).toFixed(2)}`}
              </div>
              {message.text && <p className="whitespace-pre-wrap break-words text-sm">{message.text}</p>}
              {message.lock_description && (
                <p className="text-xs opacity-70 italic">{message.lock_description}</p>
              )}
            </div>
          ) : isEditing ? (
            <div className="space-y-1.5">
              <textarea
                value={editText}
                onChange={(e) => setEditText(e.target.value)}
                rows={3}
                className="w-full resize-none rounded-lg border border-input bg-background px-3 py-2 text-sm text-foreground"
                autoFocus
              />
              <div className="flex gap-1.5">
                <Button
                  size="sm"
                  className="h-7 px-2 text-xs"
                  onClick={() => editMut.mutate(editText.trim())}
                  disabled={editMut.isPending || !editText.trim()}
                >
                  {editMut.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : "Save"}
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-7 px-2 text-xs"
                  onClick={() => setIsEditing(false)}
                  disabled={editMut.isPending}
                >
                  Cancel
                </Button>
              </div>
            </div>
          ) : message.view_once && !isOwn && message.kind === "text" ? (
            // text === null means backend has already consumed this view-once — always show stub
            message.text === null ? (
              <div className="flex items-center gap-1.5 rounded-lg border-2 border-dashed border-muted-foreground/30 bg-muted/20 px-3 py-2 text-sm text-muted-foreground">
                <EyeOff className="h-4 w-4" />
                Already viewed
              </div>
            ) : viewOnceTextRevealed ? (
              <p
                className={cn(
                  "whitespace-pre-wrap break-words text-sm",
                  isEmojiOnly(message.text) && "text-5xl leading-relaxed py-1",
                )}
              >
                {message.text}
              </p>
            ) : (
              <button
                type="button"
                onClick={() => {
                  onViewOnce?.(message.message_id);
                  if (!message.message_id.startsWith("optimistic-")) {
                    markViewed(conversationId, message.message_id).catch(() => {});
                  }
                }}
                className="flex items-center gap-1.5 rounded-lg border-2 border-dashed border-primary/40 bg-primary/5 px-3 py-2 text-sm text-primary hover:bg-primary/10"
              >
                <Eye className="h-4 w-4" />
                Tap to view once
              </button>
            )
          ) : message.text && !ATTACHMENT_CAPTION_KINDS.has(message.kind) ? (
            // Attachment kinds (file/calendar/poll/find-time) render their own
            // caption below the card — skip here to avoid a duplicate.
            <MessageText text={message.text} />
          ) : null}

          {/* MVA-006: inline translation with a Show original toggle. */}
          {translatedText && message.kind === "text" && !showOriginal && (
            <div className="mt-1.5 rounded-md border-l-2 border-primary/40 bg-muted/30 px-2 py-1.5">
              <div className="mb-0.5 flex items-center gap-1 text-[10px] uppercase tracking-wide text-muted-foreground">
                <Languages className="h-3 w-3" />
                <span>Translated{translationLang ? ` · ${translationLang}` : ""}</span>
              </div>
              <p className="whitespace-pre-wrap break-words text-sm">{translatedText}</p>
              <button
                type="button"
                className="mt-1 text-xs font-medium text-primary hover:underline"
                onClick={() => setShowOriginal(true)}
              >
                Show original
              </button>
            </div>
          )}
          {translatedText && message.kind === "text" && showOriginal && (
            <button
              type="button"
              className="mt-1 block text-xs font-medium text-primary hover:underline"
              onClick={() => setShowOriginal(false)}
            >
              Show translation
            </button>
          )}

          {message.preview?.url && (
            <a
              href={message.preview.url}
              className="mt-2 flex items-start gap-2 rounded-lg border bg-muted/40 p-2 hover:bg-muted/60 transition-colors no-underline"
              onClick={(e) => {
                if (message.preview!.url!.startsWith("/")) {
                  e.preventDefault();
                  navigate(message.preview!.url!);
                }
              }}
            >
              {message.preview.image_url && (
                <img src={message.preview.image_url} className="h-14 w-14 rounded object-cover shrink-0" alt="" />
              )}
              <div className="min-w-0">
                {message.preview.title && (
                  <p className="text-sm font-medium line-clamp-2">{message.preview.title}</p>
                )}
                {message.preview.site_name && (
                  <p className="text-xs text-muted-foreground">{message.preview.site_name}</p>
                )}
              </div>
            </a>
          )}

          {message.kind === "image" && !message.is_encrypted && expiryCountdown !== "expired" && !message.expired && (
            message.consumption_policy === "view_once" && !isOwn ? (
              // View-once image for recipient: show tap-to-view, not the actual image
              message.consumption_state === "consumed" || !message.image?.url ? (
                <div className="mt-1 flex h-24 w-48 items-center justify-center rounded-lg bg-muted/50 text-xs text-muted-foreground">
                  Already viewed
                </div>
              ) : (
                <button
                  type="button"
                  disabled={openingOnce}
                  onClick={() => void handleOpenOnceAttachment()}
                  className="mt-1 flex h-24 w-48 flex-col items-center justify-center gap-1 rounded-lg border-2 border-dashed border-primary/40 bg-primary/5 hover:bg-primary/10 text-primary"
                >
                  {openingOnce ? (
                    <Loader2 className="h-5 w-5 animate-spin" />
                  ) : (
                    <>
                      <Lock className="h-5 w-5" />
                      <span className="text-xs font-medium">Tap to view once</span>
                    </>
                  )}
                </button>
              )
            ) : typeof message.image?.url === "string" ? (
              // Normal image or own view-once: show actual image
              <button
                type="button"
                aria-label="Open message image"
                onClick={() => {
                  if (message.consumption_policy && !isOwn) {
                    void handleOpenOnceAttachment();
                  } else {
                    setLightboxOpen(true);
                    // Track that this user viewed/opened the image
                    if (!message.message_id.startsWith("optimistic-")) {
                      markViewed(conversationId, message.message_id).catch(() => {});
                    }
                  }
                }}
                className="mt-1 block"
              >
                <img
                  src={message.image.url}
                  alt="Shared image"
                  className="max-h-64 rounded-lg object-cover"
                />
              </button>
            ) : null
          )}

          {message.kind === "gallery" && expiryCountdown !== "expired" && !message.expired && (
            <div className="space-y-2 mt-1">
              {/* Free items grid (images + videos) */}
              {message.free_images && message.free_images.length > 0 && (
                <div className="grid grid-cols-3 gap-1">
                  {(message.free_images as GalleryImageItem[]).map((item, i) => (
                    item.url ? (
                      item.content_type?.startsWith("video/") ? (
                        <video
                          key={i}
                          src={item.url}
                          className="w-full aspect-square object-cover rounded"
                          muted
                          playsInline
                          preload="metadata"
                          controls
                        />
                      ) : (
                        <img
                          key={i}
                          src={item.url}
                          alt={item.filename ?? `Image ${i + 1}`}
                          className="w-full aspect-square object-cover rounded"
                        />
                      )
                    ) : null
                  ))}
                </div>
              )}

              {/* Locked items section */}
              {(message.locked_image_count ?? 0) > 0 && (
                <div>
                  {message.locked_images ? (
                    // Unlocked: show full grid
                    <div className="grid grid-cols-3 gap-1">
                      {(message.locked_images as GalleryImageItem[]).map((item, i) => (
                        item.url ? (
                          item.content_type?.startsWith("video/") ? (
                            <video
                              key={i}
                              src={item.url}
                              className="w-full aspect-square object-cover rounded"
                              muted
                              playsInline
                              preload="metadata"
                              controls
                            />
                          ) : (
                            <img
                              key={i}
                              src={item.url}
                              alt={item.filename ?? `Locked image ${i + 1}`}
                              className="w-full aspect-square object-cover rounded"
                            />
                          )
                        ) : null
                      ))}
                    </div>
                  ) : (
                    // Locked: show blurred previews if available, else placeholder grid
                    <div>
                      <div className="grid grid-cols-3 gap-1 opacity-70">
                        {Array.from({ length: Math.min(message.locked_image_count ?? 0, 6) }).map((_, i) => (
                          <div key={i} className="relative aspect-square rounded overflow-hidden bg-muted/60 flex items-center justify-center">
                            <Lock className="h-4 w-4 text-muted-foreground" />
                          </div>
                        ))}
                      </div>
                      <div className="mt-1.5 flex items-center gap-2 flex-wrap">
                        <div className="inline-flex items-center gap-1.5 rounded-full bg-background/60 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide">
                          <Lock className="h-3 w-3" />
                          {`${message.locked_image_count} locked item${message.locked_image_count !== 1 ? "s" : ""} · $${((message.lock_price_cents ?? 0) / 100).toFixed(2)}`}
                        </div>
                        {!isOwn && message.lock_price_cents && (
                          paymentMethods.length === 0 ? (
                            <TooltipProvider delayDuration={100}>
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <div>
                                    <Button type="button" size="sm" variant="secondary" className="h-7 px-2 text-xs cursor-not-allowed opacity-50" disabled>
                                      <CreditCard className="mr-1 h-3 w-3" />
                                      {`Unlock for $${(message.lock_price_cents / 100).toFixed(2)}`}
                                    </Button>
                                  </div>
                                </TooltipTrigger>
                                <TooltipContent>Add a payment method in Billing to unlock this message</TooltipContent>
                              </Tooltip>
                            </TooltipProvider>
                          ) : (
                            <Button
                              type="button"
                              size="sm"
                              variant="secondary"
                              className="h-7 px-2 text-xs"
                              onClick={() => {
                                const def = paymentMethods.find((m) => m.is_default) ?? paymentMethods[0];
                                setUnlockPaymentMethodId(def?.payment_method_id ?? null);
                                setUnlockDialogOpen(true);
                              }}
                            >
                              <CreditCard className="mr-1 h-3 w-3" />
                              {`Unlock for $${(message.lock_price_cents / 100).toFixed(2)}`}
                            </Button>
                          )
                        )}
                      </div>
                      {message.lock_description && (
                        <p className="mt-1 text-xs text-muted-foreground italic">{message.lock_description}</p>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {isFileKind && !message.is_encrypted && expiryCountdown !== "expired" && !message.expired && typeof message.file?.name === "string" && (
            <>
              <FileMessageCard
                fileName={message.file.name}
                fileUrl={typeof message.file?.url === "string" ? message.file.url : undefined}
                kind={message.kind}
                isOwn={isOwn}
                consumptionState={message.consumption_state}
                onceError={onceError}
                opening={openingOnce}
                onOpen={() => {
                  if (message.consumption_policy) {
                    void handleOpenOnceAttachment();
                    return;
                  }
                  setFilePreviewOpen(true);
                }}
              />
              {!isOwn && (
                <button
                  type="button"
                  className="mt-1 text-xs text-muted-foreground hover:text-destructive"
                  onClick={() => {
                    setReportTarget("attachment");
                    setReportOpen(true);
                  }}
                >
                  Report attachment
                </button>
              )}
              {filePreviewOpen && message.file?.url && (
                <FilePreview
                  file={{
                    name: message.file.name,
                    path: "",
                    type: "file",
                    size: message.file.size,
                    content_type: message.file.content_type,
                  } as FileEntry}
                  files={[]}
                  previewSrcUrl={message.file.url}
                  onClose={() => setFilePreviewOpen(false)}
                  onNavigate={() => {}}
                  onDownload={() => { if (message.file?.url) window.open(message.file.url, "_blank", "noopener,noreferrer"); }}
                />
              )}
            </>
          )}

          {message.kind === "file_share" && message.file_share && (
            <>
              <div className="mt-1 rounded-lg border bg-background text-foreground p-3 flex gap-3 items-start max-w-xs">
                <FileText className="h-8 w-8 shrink-0 text-muted-foreground" />
                <div className="min-w-0 flex-1 space-y-1">
                  <p className="font-medium text-sm truncate">{message.file_share.name}</p>
                  {message.file_share.size != null && (
                    <p className="text-xs text-muted-foreground">{formatBytes(message.file_share.size)}</p>
                  )}
                  <span className={cn(
                    "inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium",
                    message.file_share.permission === "write"
                      ? "bg-amber-100 text-amber-800"
                      : "bg-blue-100 text-blue-800",
                  )}>
                    {message.file_share.permission === "write" ? "View + Edit" : "View only"}
                  </span>
                  {message.file_share.is_encrypted && (
                    <span className="text-xs text-muted-foreground flex items-center gap-1">
                      <Lock className="h-3 w-3" /> Encrypted
                    </span>
                  )}
                  <div className="flex items-center gap-2 pt-0.5">
                    {!message.file_share.is_encrypted && (
                      <button
                        type="button"
                        className="text-xs text-primary hover:underline"
                        onClick={() => setFileSharePreviewOpen(true)}
                      >
                        Preview
                      </button>
                    )}
                    <a
                      href="/files"
                      className="text-xs text-primary hover:underline whitespace-nowrap"
                      onClick={(e) => e.stopPropagation()}
                    >
                      Open in Files
                    </a>
                  </div>
                </div>
              </div>
              {fileSharePreviewOpen && message.file_share && (
                <FilePreview
                  file={{
                    name: message.file_share.name,
                    path: message.file_share.path,
                    type: "file",
                    size: message.file_share.size,
                    content_type: message.file_share.content_type,
                    is_encrypted: message.file_share.is_encrypted,
                  } as FileEntry}
                  files={[]}
                  previewSrcUrl={
                    isOwn
                      ? downloadUrl(message.file_share.path)
                      : sharedPreviewUrl(message.file_share.owner, message.file_share.path)
                  }
                  onClose={() => setFileSharePreviewOpen(false)}
                  onNavigate={() => {}}
                  onDownload={() => {
                    const url = isOwn
                      ? downloadUrl(message.file_share!.path)
                      : sharedPreviewUrl(message.file_share!.owner, message.file_share!.path);
                    window.open(url, "_blank", "noopener,noreferrer");
                  }}
                />
              )}
            </>
          )}
          {message.kind === "file_share" && message.text && (
            <p className="mt-1 text-sm">{message.text}</p>
          )}

          {/* ── Video share card ── */}
          {message.kind === "video_share" && message.video_share && (
            <VideoShareCard videoShare={message.video_share} />
          )}
          {message.kind === "video_share" && message.text && (
            <p className="mt-1 text-sm">{message.text}</p>
          )}

          {/* ── Voice message ── */}
          {message.kind === "voice_message" && message.voice_message && (
            <div className="mt-1" data-testid="voice-message-bubble">
              <div className="flex items-center gap-2 mb-1">
                <Mic className="h-4 w-4 text-muted-foreground shrink-0" />
                <span className="text-xs text-muted-foreground">Voice message</span>
              </div>
              <WaveformPlayer
                audioUrl={message.voice_message.audio_url}
                waveform={message.voice_message.waveform_data}
                durationSeconds={message.voice_message.duration_seconds}
                consumed={message.consumption_state === "consumed"}
              />
              <TranscriptControl
                conversationId={conversationId}
                messageId={message.message_id}
                existingTranscript={message.voice_message.transcript}
                existingLang={message.voice_message.transcript_lang}
              />
            </div>
          )}

          {/* ── Voicemail (CALL-014) ── */}
          {message.kind === "voicemail" && message.voicemail && (
            <VoicemailBubble message={message} conversationId={conversationId} />
          )}

          {/* ── Calendar share card ── */}
          {message.kind === "calendar_share" && message.calendar_share && (
            <div className="mt-1 rounded-lg border bg-background text-foreground p-3 flex gap-3 items-start max-w-xs">
              <CalendarDays className="h-8 w-8 shrink-0 text-primary/70" />
              <div className="min-w-0 flex-1 space-y-1">
                <p className="font-medium text-sm truncate">{message.calendar_share.name}</p>
                <span className={cn(
                  "inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium",
                  message.calendar_share.permission === "write"
                    ? "bg-amber-100 text-amber-800"
                    : "bg-blue-100 text-blue-800",
                )}>
                  {message.calendar_share.permission === "write" ? "View + Edit" : "View only"}
                </span>
                <div className="flex flex-wrap items-center gap-2 pt-0.5">
                  <a href="/calendar" className="text-xs text-primary hover:underline">View Calendar</a>
                  {message.calendar_share.booking_public_url && (
                    <a
                      href={message.calendar_share.booking_public_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-primary hover:underline"
                    >
                      Book a time →
                    </a>
                  )}
                </div>
              </div>
            </div>
          )}
          {message.kind === "calendar_share" && message.text && (
            <p className="mt-1 text-sm">{message.text}</p>
          )}

          {/* ── Calendar event card ── */}
          {message.kind === "calendar_event" && message.calendar_event && (() => {
            const ev = message.calendar_event;
            const start = ev.start_utc ? new Date(ev.start_utc) : null;
            const dateStr = ev.all_day
              ? (ev.all_day_date ?? "")
              : (start?.toLocaleString(undefined, {
                  weekday: "short",
                  month: "short",
                  day: "numeric",
                  hour: "numeric",
                  minute: "2-digit",
                }) ?? "");
            return (
              <div className="mt-1 rounded-lg border bg-background text-foreground p-3 flex gap-3 items-start max-w-xs">
                <CalendarCheck className="h-8 w-8 shrink-0 text-primary/70" />
                <div className="min-w-0 flex-1 space-y-1">
                  <p className="font-medium text-sm truncate">{ev.name}</p>
                  {dateStr && <p className="text-xs text-muted-foreground">{dateStr}</p>}
                  <div className="flex flex-wrap gap-2 pt-0.5">
                    <a
                      href={`/event/${ev.calendar_id}/${ev.event_id}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-primary hover:underline"
                    >
                      View details
                    </a>
                    <a
                      href={`/calendar/public/event/${ev.calendar_id}/${ev.event_id}/ical`}
                      download
                      className="text-xs text-primary hover:underline"
                    >
                      Download .ics
                    </a>
                  </div>
                </div>
              </div>
            );
          })()}
          {message.kind === "calendar_event" && message.text && (
            <p className="mt-1 text-sm">{message.text}</p>
          )}

          {/* ── Meeting poll card ── */}
          {message.kind === "meeting_poll" && message.meeting_poll && (
            <MeetingPollCard
              pollStub={message.meeting_poll as MeetingPollAttachment}
              conversationId={conversationId}
              isOwn={isOwn}
            />
          )}
          {message.kind === "meeting_poll" && message.text && (
            <p className="mt-1 text-sm">{message.text}</p>
          )}

          {/* ── Find-a-DateTime card (MSG-009) ── */}
          {message.kind === "find_datetime" && message.find_datetime && (
            <FindDateTimeCard
              stub={message.find_datetime as FindDateTimeAttachment}
              isOwn={isOwn}
            />
          )}
          {message.kind === "find_datetime" && message.text && (
            <p className="mt-1 text-sm">{message.text}</p>
          )}

          {/* ── Countdown card (MSG-010) ── */}
          {message.kind === "countdown" &&
            message.countdown_title &&
            message.target_datetime != null && (
              <CountdownCard
                title={message.countdown_title}
                targetDatetime={message.target_datetime}
                associatedEventType={message.associated_event_type ?? "custom"}
                associatedEventId={message.associated_event_id}
              />
            )}

          {/* ── GIF message (MSG-008) ── */}
          {message.kind === "gif" && message.gif_url && (
            <div className="max-w-xs" data-testid="gif-message">
              <img
                src={message.gif_url}
                alt={message.gif_alt_text || "GIF"}
                className="rounded-lg w-full"
                style={{
                  aspectRatio: `${message.gif_width || 320} / ${message.gif_height || 240}`,
                }}
                loading="lazy"
                decoding="async"
              />
            </div>
          )}

          {/* ── Sticker message (MSG-008) ── */}
          {message.kind === "sticker" && message.sticker_url && (
            <div className="h-32 w-32" data-testid="sticker-message">
              <img
                src={message.sticker_url}
                alt={message.sticker_alt_text || "Sticker"}
                className="h-full w-full object-contain"
                loading="lazy"
                decoding="async"
              />
            </div>
          )}

          {message.tip_amount_cents && message.tip_amount_cents > 0 && (
            <div className={cn(
              "mt-1 inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium",
              isOwn ? "bg-green-400/30 text-green-200" : "bg-green-500/20 text-green-700",
            )}>
              <DollarSign className="h-3 w-3" />
              Tip: ${(message.tip_amount_cents / 100).toFixed(2)}
            </div>
          )}

          {message.quick_replies && message.quick_replies.length > 0 && message.sender_type === "bot" && (
            <div className="mt-2 flex flex-wrap gap-2" data-testid="quick-replies">
              {message.quick_replies.map((qr, i) => (
                <Button
                  key={i}
                  variant="outline"
                  size="sm"
                  disabled={quickReplySent}
                  onClick={() => {
                    setQuickReplySent(true);
                    quickReplyMut.mutate(qr.value);
                  }}
                  data-testid={`quick-reply-${i}`}
                >
                  {qr.label}
                </Button>
              ))}
            </div>
          )}

          {message.reactions_counts && Object.keys(message.reactions_counts).length > 0 && (
            <div className="mt-1 flex flex-wrap items-center gap-1" data-testid="reaction-bar">
              {Object.entries(message.reactions_counts).map(([emoji, count]) => (
                <button
                  key={emoji}
                  type="button"
                  data-testid={`reaction-badge-${emoji}`}
                  onClick={() => reactMut.mutate(emoji)}
                  className={cn(
                    "msg011-reaction-badge inline-flex items-center rounded-full bg-background/80 px-1.5 py-0.5 text-xs transition-colors hover:bg-accent",
                    (message.my_reactions ?? []).includes(emoji) && "bg-primary/20 ring-1 ring-primary/40",
                    animatingEmoji === emoji && "reaction-badge-enter",
                  )}
                >
                  <ReactionEmoji reactionKey={emoji} /> {count > 1 && <span className="ml-0.5">{count}</span>}
                </button>
              ))}
              {/* MSG-011: tap to see who reacted with what */}
              <ReactionDetailPopover
                conversationId={conversationId}
                messageId={message.message_id}
                emojis={Object.keys(message.reactions_counts)}
                counts={message.reactions_counts}
                trigger={
                  <button
                    type="button"
                    aria-label="See who reacted"
                    data-testid="reaction-details-trigger"
                    className="inline-flex h-5 items-center rounded-full px-1.5 text-xs text-muted-foreground transition-colors hover:bg-accent"
                  >
                    <Info className="h-3 w-3" />
                  </button>
                }
              />
            </div>
          )}

          {hasThreadEntry && (
            <button
              type="button"
              onClick={() => onViewThread?.(message)}
              className={cn(
                "mt-1 inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs transition-colors",
                isOwn
                  ? "border-primary-foreground/30 bg-primary-foreground/10 hover:bg-primary-foreground/20"
                  : "border-border bg-background/70 hover:bg-muted",
              )}
            >
              <span className="font-medium">View thread</span>
              <span aria-hidden>·</span>
              <span>{threadReplyLabel}</span>
              {threadLastActivityLabel && (
                <>
                  <span aria-hidden>·</span>
                  <span>Last activity {threadLastActivityLabel}</span>
                </>
              )}
            </button>
          )}

          <div className={cn(
            "mt-1 flex items-center gap-1 text-[10px]",
            isOwn ? "text-primary-foreground/60 justify-end" : "text-muted-foreground",
          )}>
            {(message.edited_at || message.edited) && <span>edited</span>}
            {expiryCountdown && (
              <span className={cn(
                "rounded px-1",
                isOwn ? "bg-orange-400/30 text-orange-200" : "bg-orange-500/20 text-orange-600",
              )}>
                expires {expiryCountdown}
              </span>
            )}
            {message.view_once && message.kind === "text" && (
              <span className={cn(
                "rounded px-1",
                isOwn ? "bg-purple-400/30 text-purple-200" : "bg-purple-500/20 text-purple-600",
              )}>
                view once
              </span>
            )}
            <span>{time}</span>
            <DeliveryStatus message={message} isOwn={isOwn} />
          </div>

          {/* PWA-005: Offline status badge */}
          {message.__offline && (
            <OfflineStatusBadge
              offline={message.__offline}
              onRetry={() => {
                if (!message.__offline) return;
                const { retryAction } = useOfflineStore.getState();
                retryAction(message.__offline.queueId);
                updateOfflineMessageStatus(queryClient, message.__offline.queueId, "pending");
                toast.info("Message re-queued");
              }}
              onDiscard={() => {
                if (!message.__offline) return;
                const { removeFromQueue } = useOfflineStore.getState();
                removeFromQueue(message.__offline.queueId);
                removeOptimisticMessage(queryClient, conversationId, message.message_id);
                toast.info("Queued message discarded");
              }}
            />
          )}
        </div>
      </div>

      <ReadReceipts conversationId={conversationId} messageId={message.message_id} isOwn={isOwn} />

      <ViewTracker
        conversationId={conversationId}
        messageId={message.message_id}
        isOwn={isOwn}
        skipMarkViewed={message.view_once && message.kind === "text"}
      />

      <ForwardDialog
        open={forwardOpen}
        onOpenChange={setForwardOpen}
        message={message}
        sourceConversationId={conversationId}
      />

      <ConfirmDialog
        open={deleteConfirmOpen}
        onOpenChange={setDeleteConfirmOpen}
        title="Delete Message"
        description="This message will be deleted for everyone. This cannot be undone."
        confirmLabel="Delete"
        variant="danger"
        onConfirm={() => deleteMut.mutate()}
        loading={deleteMut.isPending}
      />

      <Dialog
        open={decryptOpen}
        onOpenChange={(open) => {
          setDecryptOpen(open);
          if (!open) {
            setDecryptPassword("");
            setDecryptError(null);
            setShowDecryptPassword(false);
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {message.kind === "image" ? "Decrypt image" : message.kind === "video" ? "Decrypt video" : isFileKind ? "Decrypt file" : "Decrypt message"}
            </DialogTitle>
            <DialogDescription>
              Enter the shared password to decrypt this {message.kind === "image" ? "image" : message.kind === "video" ? "video" : isFileKind ? "file" : "message"} locally on your device.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-2">
            <div className="relative">
              <input
                type={showDecryptPassword ? "text" : "password"}
                value={decryptPassword}
                onChange={(e) => setDecryptPassword(e.target.value)}
                placeholder="Password"
                className="w-full rounded-md border border-input bg-background px-3 py-2 pr-9 text-sm"
                autoComplete="off"
              />
              <button
                type="button"
                onClick={() => setShowDecryptPassword((v) => !v)}
                className="absolute inset-y-0 right-2 flex items-center text-muted-foreground hover:text-foreground"
                tabIndex={-1}
              >
                {showDecryptPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
            {decryptError && <p className="text-xs text-red-600">{decryptError}</p>}
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setDecryptOpen(false)} disabled={decrypting}>
              Cancel
            </Button>
            <Button onClick={() => void handleDecrypt()} disabled={decrypting || !decryptPassword}>
              {decrypting ? <Loader2 className="h-4 w-4 animate-spin" /> : "Decrypt"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <MessageDetailsSheet
        open={detailsOpen}
        onOpenChange={setDetailsOpen}
        message={message}
        conversationId={conversationId}
      />

      <ReportContentModal
        open={reportOpen}
        onOpenChange={(open) => {
          setReportOpen(open);
          if (!open && !reportMut.isPending) {
            setReportServerError(null);
            setReportTarget("message");
          }
        }}
        title={reportTarget === "attachment" ? "Report attachment" : "Report message"}
        description={reportTarget === "attachment"
          ? "Share why this attachment should be reviewed. Recent conversation context will be included automatically."
          : "Share why this message should be reviewed. Recent conversation context will be included automatically."}
        isSubmitting={reportMut.isPending}
        serverError={reportServerError}
        onSubmit={async (payload) => {
          setReportServerError(null);
          await reportMut.mutateAsync(payload);
        }}
      />

      <Dialog
        open={tipStep !== null}
        onOpenChange={(open) => {
          if (!open) { setTipStep(null); setTipAmount(""); setSelectedPaymentMethodId(null); }
        }}
      >
        <DialogContent className="max-w-sm">
          {tipStep === "amount" && (
            <>
              <DialogHeader>
                <DialogTitle>Send Tip</DialogTitle>
                <DialogDescription>Choose an amount and payment method.</DialogDescription>
              </DialogHeader>

              <div className="space-y-4">
                {/* Amount */}
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">Amount (USD)</label>
                  <input
                    type="number"
                    min="0.01"
                    step="0.01"
                    value={tipAmount}
                    onChange={(e) => setTipAmount(e.target.value)}
                    placeholder="e.g. 5.00"
                    className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                    autoFocus
                  />
                </div>

                {/* Payment method selector */}
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">Payment method</label>
                  <div className="space-y-2">
                    {paymentMethods.map((pm) => {
                      const label = pm.brand
                        ? `${pm.brand.charAt(0).toUpperCase() + pm.brand.slice(1)} •••• ${pm.last4}`
                        : (pm.label ?? pm.method_type);
                      const isSelected = selectedPaymentMethodId === pm.payment_method_id;
                      return (
                        <button
                          key={pm.payment_method_id}
                          type="button"
                          onClick={() => setSelectedPaymentMethodId(pm.payment_method_id)}
                          className={cn(
                            "flex w-full items-center gap-3 rounded-lg border px-3 py-2.5 text-sm transition-colors hover:bg-accent",
                            isSelected ? "border-primary bg-primary/5" : "border-border",
                          )}
                        >
                          <CreditCard className="h-4 w-4 shrink-0 text-muted-foreground" />
                          <span className="flex-1 text-left">{label}</span>
                          {pm.is_default && (
                            <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">Default</span>
                          )}
                          {isSelected && <Check className="h-4 w-4 text-primary" />}
                        </button>
                      );
                    })}
                  </div>
                </div>
              </div>

              <DialogFooter>
                <Button variant="outline" onClick={() => setTipStep(null)}>Cancel</Button>
                <Button
                  onClick={() => setTipStep("confirm")}
                  disabled={!tipAmount || parseFloat(tipAmount) < 0.01 || !selectedPaymentMethodId}
                >
                  Continue
                </Button>
              </DialogFooter>
            </>
          )}

          {tipStep === "confirm" && (() => {
            const pm = paymentMethods.find((m) => m.payment_method_id === selectedPaymentMethodId);
            const pmLabel = pm?.brand
              ? `${pm.brand.charAt(0).toUpperCase() + pm.brand.slice(1)} •••• ${pm.last4}`
              : (pm?.label ?? pm?.method_type ?? "selected card");
            const dollars = parseFloat(tipAmount).toFixed(2);
            return (
              <>
                <DialogHeader>
                  <DialogTitle>Confirm tip</DialogTitle>
                  <DialogDescription>Please review before sending.</DialogDescription>
                </DialogHeader>

                <div className="rounded-lg border border-border bg-muted/40 p-4 space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Amount</span>
                    <span className="font-semibold">${dollars} USD</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Payment</span>
                    <span className="flex items-center gap-1.5">
                      <CreditCard className="h-3.5 w-3.5 text-muted-foreground" />
                      {pmLabel}
                    </span>
                  </div>
                </div>

                <DialogFooter>
                  <Button variant="outline" onClick={() => setTipStep("amount")} disabled={tipMut.isPending}>
                    Back
                  </Button>
                  <Button onClick={() => tipMut.mutate()} disabled={tipMut.isPending}>
                    {tipMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : `Send $${dollars} tip`}
                  </Button>
                </DialogFooter>
              </>
            );
          })()}
        </DialogContent>
      </Dialog>

      {/* Unlock dialog */}
      <Dialog
        open={unlockDialogOpen}
        onOpenChange={(open) => { if (!open) { setUnlockDialogOpen(false); setUnlockPaymentMethodId(null); } }}
      >
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Lock className="h-4 w-4" />
              Unlock message
            </DialogTitle>
            <DialogDescription>
              Pay ${((message.lock_price_cents ?? 0) / 100).toFixed(2)} to unlock this message.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            {message.lock_description && (
              <p className="rounded-lg border border-border bg-muted/40 px-3 py-2 text-sm text-muted-foreground italic">
                {message.lock_description}
              </p>
            )}
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Payment method</label>
              <div className="space-y-2">
                {paymentMethods.map((pm) => {
                  const label = pm.brand
                    ? `${pm.brand.charAt(0).toUpperCase() + pm.brand.slice(1)} •••• ${pm.last4}`
                    : (pm.label ?? pm.method_type);
                  const isSelected = unlockPaymentMethodId === pm.payment_method_id;
                  return (
                    <button
                      key={pm.payment_method_id}
                      type="button"
                      onClick={() => setUnlockPaymentMethodId(pm.payment_method_id)}
                      className={cn(
                        "flex w-full items-center gap-3 rounded-lg border px-3 py-2.5 text-sm transition-colors hover:bg-accent",
                        isSelected ? "border-primary bg-primary/5" : "border-border",
                      )}
                    >
                      <CreditCard className="h-4 w-4 shrink-0 text-muted-foreground" />
                      <span className="flex-1 text-left">{label}</span>
                      {pm.is_default && (
                        <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">Default</span>
                      )}
                      {isSelected && <Check className="h-4 w-4 text-primary" />}
                    </button>
                  );
                })}
              </div>
            </div>
            <div className="rounded-lg border border-border bg-muted/40 p-3 text-sm">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Total charge</span>
                <span className="font-semibold">${((message.lock_price_cents ?? 0) / 100).toFixed(2)} USD</span>
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setUnlockDialogOpen(false)} disabled={unlockMut.isPending}>
              Cancel
            </Button>
            <Button
              onClick={() => unlockMut.mutate(unlockPaymentMethodId)}
              disabled={unlockMut.isPending || !unlockPaymentMethodId}
            >
              {unlockMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : `Pay & Unlock`}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Image lightbox */}
      {message.kind === "image" && typeof message.image?.url === "string" && (
        <Dialog open={lightboxOpen} onOpenChange={setLightboxOpen}>
          <DialogContent className="max-w-4xl p-0 overflow-hidden bg-black/90 border-none">
            <DialogHeader className="absolute top-0 right-0 z-10 flex flex-row items-center gap-2 p-3">
              {!isOwn && (
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    setReportTarget("attachment");
                    setReportOpen(true);
                  }}
                  className="inline-flex items-center gap-1 rounded-full bg-white/10 px-2.5 py-1.5 text-xs text-white hover:bg-white/20"
                >
                  <Flag className="h-3.5 w-3.5" /> Report image
                </button>
              )}
              <a
                href={message.image.url}
                download
                className="inline-flex h-8 w-8 items-center justify-center rounded-full bg-white/10 text-white hover:bg-white/20"
                onClick={(e) => {
                  e.stopPropagation();
                  if (!message.message_id.startsWith("optimistic-")) {
                    markViewed(conversationId, message.message_id).catch(() => {});
                  }
                }}
              >
                <Download className="h-4 w-4" />
              </a>
              <button
                onClick={() => setLightboxOpen(false)}
                className="inline-flex h-8 w-8 items-center justify-center rounded-full bg-white/10 text-white hover:bg-white/20"
              >
                <X className="h-4 w-4" />
              </button>
            </DialogHeader>
            <DialogTitle className="sr-only">Image preview</DialogTitle>
            <DialogDescription className="sr-only">Full-size image view</DialogDescription>
            <div className="flex items-center justify-center min-h-[60vh] p-4">
              <img
                src={message.image.url}
                alt="Full size image"
                className="max-h-[80vh] max-w-full object-contain rounded-lg"
              />
            </div>
          </DialogContent>
        </Dialog>
      )}
    </>
  );
}
