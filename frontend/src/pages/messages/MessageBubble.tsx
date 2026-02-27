import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { MoreHorizontal, Forward, Trash2, Lock, Loader2, Pencil, Info, Download, X, Reply, Smile, DollarSign, Eye, EyeOff, CreditCard, Check, FileText, CalendarDays, CalendarCheck, Users } from "lucide-react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { isMessagingEncryptionEnabled } from "@/lib/featureFlags";
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
  sendMessageTip,
  unlockMessage,
  getMeetingPoll,
  voteMeetingPoll,
  confirmMeetingPoll,
} from "@/api/endpoints/messaging";
import { createEvent } from "@/api/endpoints/calendar";
import { ApiError } from "@/api/client";
import type { GalleryImageItem, Message, MeetingPollAttachment, PaymentMethod } from "@/api/types";
import { getPaymentMethods } from "@/api/endpoints/billing";
import { FileMessageCard } from "./FileMessageCard";
import { ReadReceipts, ViewTracker } from "./ReadReceipts";
import { ForwardDialog } from "./ForwardDialog";
import { MessageDetailsSheet } from "./MessageDetailsSheet";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { FilePreview } from "@/pages/files/FilePreview";
import { downloadUrl, sharedPreviewUrl } from "@/api/endpoints/files";
import type { FileEntry } from "@/api/types";

const QUICK_EMOJIS = ["👍", "❤️", "😂", "😮", "😢", "🙏"];

interface MessageBubbleProps {
  message: Message;
  isOwn: boolean;
  showSender?: boolean;
  conversationId: string;
  onReply?: (message: Message) => void;
  replyToMessage?: Message;
  viewedOnceIds?: Set<string>;
  onViewOnce?: (messageId: string) => void;
}

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

function replyPreviewText(msg: Message): string {
  if (msg.kind === "image") return "[Image]";
  if (msg.kind === "video") return "[Video]";
  if (msg.kind === "audio") return "[Audio]";
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
    <div className="mt-1 rounded-lg border bg-muted/40 p-3 max-w-sm space-y-2">
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
            <div key={slot.slot_id} className="rounded border bg-background/60 px-2 py-1.5 space-y-1">
              <p className="text-xs">{formatSlotTime(slot.start_utc, slot.end_utc)}</p>
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

export function MessageBubble({ message, isOwn, showSender, conversationId, onReply, replyToMessage, viewedOnceIds, onViewOnce }: MessageBubbleProps) {
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
  const [tipStep, setTipStep] = useState<null | "amount" | "confirm">(null);
  const [tipAmount, setTipAmount] = useState("");
  const [selectedPaymentMethodId, setSelectedPaymentMethodId] = useState<string | null>(null);
  const [showDecryptPassword, setShowDecryptPassword] = useState(false);
  const [expiryCountdown, setExpiryCountdown] = useState<string | null>(null);
  const [unlockDialogOpen, setUnlockDialogOpen] = useState(false);
  const [unlockPaymentMethodId, setUnlockPaymentMethodId] = useState<string | null>(null);
  const [fileSharePreviewOpen, setFileSharePreviewOpen] = useState(false);
  const [filePreviewOpen, setFilePreviewOpen] = useState(false);

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

  const reactMut = useMutation({
    mutationFn: (emoji: string) => {
      const alreadyReacted = (message.my_reactions ?? []).includes(emoji);
      const action = alreadyReacted ? "remove" : "add";
      return reactToMessage(conversationId, message.message_id, emoji, action).then(() => {
        void queryClient.invalidateQueries({ queryKey: ["messages", conversationId] });
      });
    },
    onError: () => toast.error("Failed to react"),
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

  const time = new Date(message.created_at * 1000).toLocaleTimeString(undefined, {
    hour: "numeric",
    minute: "2-digit",
  });

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

  return (
    <>
      <div className={cn("flex", isOwn ? "justify-end" : "justify-start")}>
        <div
          className={cn(
            "group relative max-w-[75%] rounded-2xl px-4 py-2",
            isOwn
              ? "bg-primary text-primary-foreground"
              : "bg-muted text-foreground",
          )}
        >
          <div className={cn(
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
                  "absolute top-full mt-1 z-50 flex gap-1 rounded-full border border-border bg-popover p-1 shadow-lg",
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
                <Button variant="ghost" size="icon" className="h-7 w-7 rounded-full bg-background shadow-sm">
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

          {replyToMessage && (
            <div className={cn(
              "mb-1.5 rounded-lg border-l-2 px-2 py-1 text-xs",
              isOwn
                ? "border-primary-foreground/40 bg-primary-foreground/10"
                : "border-primary/40 bg-muted",
            )}>
              <p className="font-semibold opacity-70 mb-0.5">{replyToMessage.sender_id}</p>
              <p className="line-clamp-2 opacity-60">{replyPreviewText(replyToMessage)}</p>
            </div>
          )}

          {showSender && !isOwn && (
            <p className="mb-0.5 text-xs font-semibold text-primary">
              {message.sender_id}
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
                <p className="whitespace-pre-wrap break-words text-sm">{decryptedText}</p>
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
                        To change content, delete and resend this encrypted message.
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
              <p className="whitespace-pre-wrap break-words text-sm">{message.text}</p>
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
          ) : message.text ? (
            <p className="whitespace-pre-wrap break-words text-sm">{message.text}</p>
          ) : null}

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
              <div className="mt-1 rounded-lg border bg-muted/40 p-3 flex gap-3 items-start max-w-xs">
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

          {/* ── Calendar share card ── */}
          {message.kind === "calendar_share" && message.calendar_share && (
            <div className="mt-1 rounded-lg border bg-muted/40 p-3 flex gap-3 items-start max-w-xs">
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
              <div className="mt-1 rounded-lg border bg-muted/40 p-3 flex gap-3 items-start max-w-xs">
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

          {message.tip_amount_cents && message.tip_amount_cents > 0 && (
            <div className={cn(
              "mt-1 inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium",
              isOwn ? "bg-green-400/30 text-green-200" : "bg-green-500/20 text-green-700",
            )}>
              <DollarSign className="h-3 w-3" />
              Tip: ${(message.tip_amount_cents / 100).toFixed(2)}
            </div>
          )}

          {message.reactions_counts && Object.keys(message.reactions_counts).length > 0 && (
            <div className="mt-1 flex flex-wrap gap-1">
              {Object.entries(message.reactions_counts).map(([emoji, count]) => (
                <button
                  key={emoji}
                  type="button"
                  onClick={() => reactMut.mutate(emoji)}
                  className={cn(
                    "inline-flex items-center rounded-full bg-background/80 px-1.5 py-0.5 text-xs transition-colors hover:bg-accent",
                    (message.my_reactions ?? []).includes(emoji) && "bg-primary/20 ring-1 ring-primary/40",
                  )}
                >
                  {emoji} {count > 1 && <span className="ml-0.5">{count}</span>}
                </button>
              ))}
            </div>
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
          </div>
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
