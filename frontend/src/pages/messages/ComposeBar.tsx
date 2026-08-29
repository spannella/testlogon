import * as React from "react";
import { Send, Paperclip, Loader2, Lock, Eye, EyeOff, EyeOff as EyeSlash, Headphones, X, ImageIcon, Clock, Reply, Globe, DollarSign, FileText, Images, FolderOpen, CalendarDays, CalendarCheck, Users, Dices, Video, Mic, Timer, Smile, Sticker as StickerIcon, Plus, Check, TrendingUp, Activity, Package, ShoppingBag } from "lucide-react";
import { useQuery, useQueryClient, useMutation } from "@tanstack/react-query";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { GifPicker } from "@/components/shared/GifPicker";
import { StickerPicker } from "@/components/shared/StickerPicker";
import { EmojiPicker } from "@/components/shared/EmojiPicker";
import { replaceShortcodes } from "@/utils/emoji";
import { sendGifMessage, sendStickerMessage, uploadConversationMedia } from "@/api/endpoints/messaging";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import {
  isMessagingEncryptionEnabled,
  isMessagingListenOnceAudioEnabled,
  isMessagingViewOnceImageEnabled,
  isMessagingViewOnceVideoEnabled,
  isMessagingDraftsEnabled,
  isMessagingTtsEnabled,
} from "@/lib/featureFlags";
import { encryptMessage, type MessageEncryptionEnvelope } from "@/lib/messageEncryption";
import type { Message, PaymentMethod, SendTextMessageReq, FileEntry, SendFileShareReq, SendCalendarShareReq, SendCalendarEventReq, SendMeetingPollReq, SendFindDateTimeReq, CreateLotteryMessageReq } from "@/api/types";
import { CalendarPickerDialog } from "./CalendarPickerDialog";
import { EventPickerDialog } from "./EventPickerDialog";
import { MeetingPollComposer } from "./MeetingPollComposer";
import { FindDateTimeComposer } from "./FindDateTimeComposer";
import { CountdownComposerDialog, type CountdownSubmitData } from "./CountdownComposerDialog";
import { MarketCardComposerDialog } from "./MarketCardComposerDialog";
import { PositionCardComposerDialog } from "./PositionCardComposerDialog";
import { CryptoSendComposerDialog } from "./CryptoSendComposerDialog";
import { ProductCardComposerDialog } from "./ProductCardComposerDialog";
import { OrderShareComposerDialog } from "./OrderShareComposerDialog";
import type { MarketCardPayload, PositionCardPayload } from "@/lib/tradingCards";
import type { CryptoTransferPayload } from "@/lib/cryptoTransfer";
import type { ProductCardPayload, OrderCardPayload } from "@/lib/ecomCards";
import { getPaymentMethods } from "@/api/endpoints/billing";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { FilePickerDialog } from "./FilePickerDialog";
import { VideoPickerDialog } from "./VideoPickerDialog";
import { VoiceRecorder } from "./VoiceRecorder";
import { useConversationDrafts } from "./useConversationDrafts";

interface ComposeBarProps {
  conversationId: string;
  onSendText: (payload: SendTextMessageReq) => void;
  onSendImage?: (file: File, options?: {
    consumption_policy?: "none" | "view_once";
    caption?: string;
    expires_in_seconds?: number;
    lock_price_cents?: number;
    lock_description?: string;
    tip_amount_cents?: number;
    tip_payment_method_id?: string;
    send_at?: number;
    encryption_password?: string;
  }) => void;
  onSendVideoAttachment?: (file: File, options?: { consumption_policy?: "none" | "view_once" }) => void;
  onSendAudioRecording?: (file: File, options?: { consumption_policy?: "none" | "listen_once" }) => void;
  onSendGallery?: (params: {
    freeFiles: File[];
    lockedFiles: File[];
    text?: string;
    lock_price_cents?: number;
    lock_description?: string;
    expires_in_seconds?: number;
    send_at?: number;
    tip_amount_cents?: number;
    tip_payment_method_id?: string;
  }) => void;
  onSendFileShare?: (params: SendFileShareReq) => void;
  onSendVideoShare?: (params: { video_id: string; text?: string }) => void;
  onSendCalendarShare?: (params: SendCalendarShareReq) => void;
  onSendCalendarEvent?: (params: SendCalendarEventReq) => void;
  onSendMeetingPoll?: (params: SendMeetingPollReq) => void;
  onSendFindDateTime?: (params: SendFindDateTimeReq) => void;
  onSendCountdown?: (params: CountdownSubmitData) => void;
  onSendMarketCard?: (payload: MarketCardPayload) => void;
  onSendPositionCard?: (payload: PositionCardPayload) => void;
  onSendCryptoTransfer?: (payload: CryptoTransferPayload) => void;
  onSendProductCard?: (payload: ProductCardPayload) => void;
  onSendOrderCard?: (payload: OrderCardPayload) => void;
  /** DM partner display name for the send-crypto composer attribution. */
  recipientName?: string;
  currentUserName?: string;
  onSendLottery?: (params: Omit<CreateLotteryMessageReq, "conversation_id">) => void;
  onSendVoiceMessage?: (blob: Blob, meta: { duration: number; waveform: number[]; contentType: string; consumption_policy?: "none" | "listen_once"; reply_to_message_id?: string | null; send_at?: number | null }) => void;
  // MVA-010: synthesize the current draft text into a TTS voice message.
  onSendTtsVoice?: (text: string, opts: { reply_to_message_id?: string | null }) => Promise<void> | void;
  sending?: boolean;
  disabled?: boolean;
  onKeystroke?: () => void;
  replyingTo?: Message | null;
  onCancelReply?: () => void;
}

function assertComposeConversationId(conversationId: string): string {
  const normalized = conversationId.trim();
  if (!normalized) {
    throw new Error("ComposeBar requires a non-empty conversationId");
  }
  return normalized;
}

export function ComposeBar({
  conversationId,
  onSendText,
  onSendImage,
  onSendVideoAttachment,
  onSendAudioRecording,
  onSendGallery,
  onSendFileShare,
  onSendVideoShare,
  onSendCalendarShare,
  onSendCalendarEvent,
  onSendMeetingPoll,
  onSendFindDateTime,
  onSendCountdown,
  onSendMarketCard,
  onSendPositionCard,
  onSendCryptoTransfer,
  onSendProductCard,
  onSendOrderCard,
  recipientName,
  currentUserName,
  onSendLottery,
  onSendVoiceMessage,
  onSendTtsVoice,
  sending,
  disabled,
  onKeystroke,
  replyingTo,
  onCancelReply,
}: ComposeBarProps) {
  const normalizedConversationId = React.useMemo(
    () => assertComposeConversationId(conversationId),
    [conversationId],
  );
  const [text, setText] = React.useState("");
  const queryClient = useQueryClient();
  const [gifPickerOpen, setGifPickerOpen] = React.useState(false);
  const [stickerPickerOpen, setStickerPickerOpen] = React.useState(false);
  const [emojiPickerOpen, setEmojiPickerOpen] = React.useState(false);
  // "+" overflow menu that collects the secondary compose actions (MCM).
  const [moreOpen, setMoreOpen] = React.useState(false);

  const sendGifMut = useMutation({
    mutationFn: (gif: { url: string; alt_text: string; width: number; height: number }) =>
      sendGifMessage(normalizedConversationId, {
        gif_url: gif.url,
        gif_alt_text: gif.alt_text,
        gif_width: gif.width,
        gif_height: gif.height,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["messages", normalizedConversationId] });
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
    },
    onError: () => toast.error("Failed to send GIF"),
  });

  const sendStickerMut = useMutation({
    mutationFn: (sticker: { id: string; collection_id: string }) =>
      sendStickerMessage(normalizedConversationId, {
        sticker_id: sticker.id,
        sticker_collection_id: sticker.collection_id,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["messages", normalizedConversationId] });
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
    },
    onError: () => toast.error("Failed to send sticker"),
  });

  const [encryptEnabled, setEncryptEnabled] = React.useState(false);
  const [password, setPassword] = React.useState("");
  const [confirmPassword, setConfirmPassword] = React.useState("");
  const [showPassword, setShowPassword] = React.useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = React.useState(false);
  const [encrypting, setEncrypting] = React.useState(false);
  const [encryptError, setEncryptError] = React.useState<string | null>(null);
  const [viewOnceImage, setViewOnceImage] = React.useState(false);
  const [viewOnceVideo, setViewOnceVideo] = React.useState(false);
  const [listenOnceAudio, setListenOnceAudio] = React.useState(false);
  const [voiceRecording, setVoiceRecording] = React.useState(false);
  const [pendingFile, setPendingFile] = React.useState<{ file: File; previewUrl: string; kind: "image" | "video" | "audio" } | null>(null);
  const [lockEnabled, setLockEnabled] = React.useState(false);
  const [lockPrice, setLockPrice] = React.useState("");
  const [lockDescription, setLockDescription] = React.useState("");
  const [tipEnabled, setTipEnabled] = React.useState(false);
  const [tipAmount, setTipAmount] = React.useState("");
  const [tipPaymentMethodId, setTipPaymentMethodId] = React.useState<string | null>(null);
  const [scheduledInput, setScheduledInput] = React.useState<string>("");  // raw "YYYY-MM-DDTHH:mm"
  const [scheduledAt, setScheduledAt] = React.useState<Date | null>(null);
  const [scheduleOpen, setScheduleOpen] = React.useState(false);
  const [scheduleTimezone, setScheduleTimezone] = React.useState(() => Intl.DateTimeFormat().resolvedOptions().timeZone);
  const [viewOnceText, setViewOnceText] = React.useState(false);
  const [expiresEnabled, setExpiresEnabled] = React.useState(false);
  const [expiresDuration, setExpiresDuration] = React.useState("3600");
  // B-COUNTDOWN #31: attach a countdown + reveal payload to a normal message.
  const [countdownAttachEnabled, setCountdownAttachEnabled] = React.useState(false);
  const [countdownAttachTitle, setCountdownAttachTitle] = React.useState("");
  const [countdownAttachInput, setCountdownAttachInput] = React.useState<string>(""); // "YYYY-MM-DDTHH:mm"
  const [countdownAttachRevealText, setCountdownAttachRevealText] = React.useState("");
  // Gallery mode state
  const [galleryMode, setGalleryMode] = React.useState(false);
  const [lotteryMode, setLotteryMode] = React.useState(false);
  const [lotteryOutcomes, setLotteryOutcomes] = React.useState<Array<{
    id: string;
    label: string;
    payload_type: "text" | "image" | "video";
    text_content: string;
    media_asset_id: string;
    media_name?: string;
    uploading?: boolean;
    weight_bps: number;
    percent_input: string;
  }>>([
    { id: "lo-1", label: "Outcome 1", payload_type: "text", text_content: "", media_asset_id: "", weight_bps: 5000, percent_input: "50.00" },
    { id: "lo-2", label: "Outcome 2", payload_type: "text", text_content: "", media_asset_id: "", weight_bps: 5000, percent_input: "50.00" },
  ]);
  const [galleryFreeFiles, setGalleryFreeFiles] = React.useState<File[]>([]);
  const [galleryLockedFiles, setGalleryLockedFiles] = React.useState<File[]>([]);
  const galleryFreeInputRef = React.useRef<HTMLInputElement>(null);
  const galleryLockedInputRef = React.useRef<HTMLInputElement>(null);
  const textareaRef = React.useRef<HTMLTextAreaElement>(null);
  const fileInputRef = React.useRef<HTMLInputElement>(null);
  const [filePickerOpen, setFilePickerOpen] = React.useState(false);
  const [videoPickerOpen, setVideoPickerOpen] = React.useState(false);
  const [pendingFileShare, setPendingFileShare] = React.useState<{
    entry: FileEntry;
    permission: "read" | "write";
  } | null>(null);
  const [calendarPickerOpen, setCalendarPickerOpen] = React.useState(false);
  const [eventPickerOpen, setEventPickerOpen] = React.useState(false);
  const [meetingPollOpen, setMeetingPollOpen] = React.useState(false);
  const [findDateTimeOpen, setFindDateTimeOpen] = React.useState(false);
  const [countdownOpen, setCountdownOpen] = React.useState(false);
  const [marketCardOpen, setMarketCardOpen] = React.useState(false);
  const [positionCardOpen, setPositionCardOpen] = React.useState(false);
  const [cryptoSendOpen, setCryptoSendOpen] = React.useState(false);
  const [productCardOpen, setProductCardOpen] = React.useState(false);
  const [orderCardOpen, setOrderCardOpen] = React.useState(false);
  const [activeDraftId, setActiveDraftId] = React.useState<string | null>(null);
  const [draftDirty, setDraftDirty] = React.useState(false);
  const [lastDraftSavedAt, setLastDraftSavedAt] = React.useState<number | null>(null);
  const {
    drafts,
    saveDraft,
    saveExistingDraft,
    loadDraft,
    deleteDraft,
    refresh,
    syncIssue,
    requiresReauth,
    clearSyncIssue,
  } = useConversationDrafts(normalizedConversationId);
  const draftsEnabled = isMessagingDraftsEnabled();
  const ttsEnabled = isMessagingTtsEnabled();
  const [ttsSynthesizing, setTtsSynthesizing] = React.useState(false);
  // MVA-010: synthesize the current draft into a TTS voice message.
  const handleSpeakThis = React.useCallback(async () => {
    if (!onSendTtsVoice) return;
    const draft = text.trim();
    if (!draft) {
      toast.error("Type something to speak first");
      return;
    }
    setMoreOpen(false);
    setTtsSynthesizing(true);
    try {
      await onSendTtsVoice(draft, { reply_to_message_id: replyingTo?.message_id ?? null });
      // Only clear the draft once synthesis succeeded; errors keep the text.
      setText("");
    } finally {
      setTtsSynthesizing(false);
    }
  }, [onSendTtsVoice, text, replyingTo, setMoreOpen, setText]);
  const [retryingDraftSync, setRetryingDraftSync] = React.useState(false);
  const autosaveTimerRef = React.useRef<number | null>(null);
  const lastPersistedDraftTextRef = React.useRef("");
  const latestComposerTextRef = React.useRef("");
  const latestActiveDraftIdRef = React.useRef<string | null>(null);
  const latestDraftsEnabledRef = React.useRef(false);
  const galleryFreePreviews = React.useMemo(
    () => galleryFreeFiles.map((file) => ({ file, url: URL.createObjectURL(file) })),
    [galleryFreeFiles],
  );
  const galleryLockedPreviews = React.useMemo(
    () => galleryLockedFiles.map((file) => ({ file, url: URL.createObjectURL(file) })),
    [galleryLockedFiles],
  );

  React.useEffect(() => () => {
    galleryFreePreviews.forEach((preview) => URL.revokeObjectURL(preview.url));
  }, [galleryFreePreviews]);

  React.useEffect(() => () => {
    galleryLockedPreviews.forEach((preview) => URL.revokeObjectURL(preview.url));
  }, [galleryLockedPreviews]);

  // Parse a datetime-local string ("YYYY-MM-DDTHH:mm") as the given timezone,
  // returning the equivalent UTC Date.
  const parseDateTimeInTz = React.useCallback((localStr: string, tz: string): Date => {
    // Treat localStr as UTC first, then find the offset so that the UTC Date
    // maps back to exactly localStr when formatted in tz.
    const asUtc = new Date(localStr + ":00Z");
    // Format the guess in target TZ (sv locale gives "YYYY-MM-DD HH:mm:ss")
    const fmtResult = new Intl.DateTimeFormat("sv", {
      timeZone: tz,
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
      hour12: false,
    }).format(asUtc);
    // Parse that as UTC so we can diff
    const tzAsUtc = new Date(fmtResult.replace(" ", "T") + "Z");
    // diff = how many ms asUtc is ahead of what TZ actually shows
    const diff = asUtc.getTime() - tzAsUtc.getTime();
    return new Date(asUtc.getTime() + diff);
  }, []);

  const featureEnabled = isMessagingEncryptionEnabled();
  const onceImageEnabled = isMessagingViewOnceImageEnabled();
  const onceVideoEnabled = isMessagingViewOnceVideoEnabled();
  const onceAudioEnabled = isMessagingListenOnceAudioEnabled();

  const { data: paymentMethods = [] } = useQuery<PaymentMethod[]>({
    queryKey: ["billing", "payment-methods"],
    queryFn: getPaymentMethods,
    staleTime: 5 * 60 * 1000,
  });
  const hasPaymentMethods = paymentMethods.length > 0;
  const lotteryTotalBps = React.useMemo(
    () => lotteryOutcomes.reduce((sum, o) => sum + (Number.isFinite(o.weight_bps) ? Math.max(0, o.weight_bps) : 0), 0),
    [lotteryOutcomes],
  );
  const lotteryOutcomesValid = React.useMemo(() => {
    if (lotteryOutcomes.length < 2 || lotteryOutcomes.length > 10) return false;
    if (lotteryTotalBps !== 10_000) return false;
    if (lotteryOutcomes.some((o) => o.uploading)) return false;
    return lotteryOutcomes.every((o) =>
      o.weight_bps > 0 &&
      o.payload_type === "text"
        ? o.text_content.trim().length > 0
        : o.media_asset_id.trim().length > 0,
    );
  }, [lotteryOutcomes, lotteryTotalBps]);
  const lotteryFieldErrors = React.useMemo(() => {
    return lotteryOutcomes.map((o) => {
      const weightError = o.weight_bps <= 0
        ? "Weight must be at least 0.01% (1 bps)."
        : o.weight_bps > 10_000
        ? "Weight cannot exceed 100% (10,000 bps)."
        : undefined;
      const payloadError = o.payload_type === "text"
        ? (o.text_content.trim() ? undefined : "Text outcome cannot be empty.")
        : (o.uploading ? "Uploading…" : o.media_asset_id.trim() ? undefined : `Upload ${o.payload_type === "video" ? "a video" : "an image"} for this outcome.`);
      return { weightError, payloadError };
    });
  }, [lotteryOutcomes]);

  // Upload an image/video for a lottery outcome → store the returned S3 key as
  // the outcome's media_asset_id (the form the lottery API accepts).
  const handleLotteryMediaUpload = React.useCallback(
    async (outcomeId: string, file: File) => {
      setLotteryOutcomes((prev) =>
        prev.map((o) => (o.id === outcomeId ? { ...o, uploading: true, media_name: file.name } : o)),
      );
      try {
        const { key } = await uploadConversationMedia(conversationId, file);
        setLotteryOutcomes((prev) =>
          prev.map((o) => (o.id === outcomeId ? { ...o, uploading: false, media_asset_id: key } : o)),
        );
      } catch {
        toast.error("Failed to upload outcome media");
        setLotteryOutcomes((prev) =>
          prev.map((o) => (o.id === outcomeId ? { ...o, uploading: false, media_name: undefined } : o)),
        );
      }
    },
    [conversationId],
  );

  const resetTextArea = () => {
    if (textareaRef.current) {
      textareaRef.current.style.height = "auto";
    }
  };

  // MSG-006: Insert an emoji at the current caret position in the textarea.
  const insertEmoji = (emoji: string) => {
    const ta = textareaRef.current;
    if (!ta) {
      setText((prev) => prev + emoji);
      return;
    }
    const start = ta.selectionStart ?? text.length;
    const end = ta.selectionEnd ?? text.length;
    const next = text.slice(0, start) + emoji + text.slice(end);
    setText(next);
    if (draftsEnabled) {
      const trimmed = next.trim();
      setDraftDirty(trimmed.length > 0 && trimmed !== lastPersistedDraftTextRef.current);
    }
    // Restore focus + caret after React re-renders.
    requestAnimationFrame(() => {
      ta.focus();
      const pos = start + emoji.length;
      ta.setSelectionRange(pos, pos);
    });
  };

  const buildExtraPayload = (): Pick<SendTextMessageReq, "lock_price_cents" | "lock_description" | "send_at" | "view_once" | "expires_in_seconds" | "tip_amount_cents" | "tip_payment_method_id" | "countdown_target_datetime" | "countdown_title" | "countdown_reveal_text"> => {
    const extra: Pick<SendTextMessageReq, "lock_price_cents" | "lock_description" | "send_at" | "view_once" | "expires_in_seconds" | "tip_amount_cents" | "tip_payment_method_id" | "countdown_target_datetime" | "countdown_title" | "countdown_reveal_text"> = {};
    if (lockEnabled) {
      const cents = Math.round(parseFloat(lockPrice) * 100);
      if (!isNaN(cents) && cents > 0) extra.lock_price_cents = cents;
      if (lockDescription.trim()) extra.lock_description = lockDescription.trim();
    }
    if (tipEnabled) {
      const cents = Math.round(parseFloat(tipAmount) * 100);
      if (!isNaN(cents) && cents > 0) extra.tip_amount_cents = cents;
      if (tipPaymentMethodId) extra.tip_payment_method_id = tipPaymentMethodId;
    }
    if (scheduledAt) {
      extra.send_at = Math.floor(scheduledAt.getTime() / 1000);
    }
    if (viewOnceText) {
      extra.view_once = true;
    }
    if (expiresEnabled) {
      const secs = parseInt(expiresDuration, 10);
      if (!isNaN(secs) && secs >= 10) extra.expires_in_seconds = secs;
    }
    // B-COUNTDOWN #31: attach a countdown target + optional reveal to any message.
    if (countdownAttachEnabled && countdownAttachInput) {
      const targetMs = new Date(countdownAttachInput).getTime();
      if (!isNaN(targetMs)) {
        extra.countdown_target_datetime = Math.floor(targetMs / 1000);
        if (countdownAttachTitle.trim()) extra.countdown_title = countdownAttachTitle.trim();
        if (countdownAttachRevealText.trim()) extra.countdown_reveal_text = countdownAttachRevealText.trim();
      }
    }
    return extra;
  };

  const buildEncryptedPayload = async (trimmed: string): Promise<SendTextMessageReq | null> => {
    const extra = buildExtraPayload();
    if (!encryptEnabled) {
      return { text: trimmed, ...extra };
    }

    if (!featureEnabled) {
      setEncryptError("Encrypted messaging is disabled in this environment.");
      return null;
    }

    if (!password || password !== confirmPassword) {
      setEncryptError("Passwords must match to send encrypted messages.");
      return null;
    }

    setEncryptError(null);
    setEncrypting(true);
    try {
      const envelope: MessageEncryptionEnvelope = await encryptMessage(trimmed, password);
      return { encryption: envelope, ...extra };
    } catch (err) {
      console.error("[encryption] encryptMessage threw:", err);
      setEncryptError("Failed to encrypt message locally. Please try again.");
      return null;
    } finally {
      setEncrypting(false);
    }
  };

  const clearPendingFile = () => {
    if (pendingFile) {
      URL.revokeObjectURL(pendingFile.previewUrl);
      setPendingFile(null);
    }
  };

  const handleSaveDraft = React.useCallback(() => {
    if (!draftsEnabled) return;
    const saved = activeDraftId
      ? saveExistingDraft(activeDraftId, text)
      : saveDraft(text);
    if (!saved) {
      toast.error("Type a message before saving a draft");
      return;
    }
    if (!activeDraftId) {
      const latestLocal = drafts[0];
      if (latestLocal) setActiveDraftId(latestLocal.id);
    }
    setDraftDirty(false);
    setLastDraftSavedAt(Date.now());
    lastPersistedDraftTextRef.current = text.trim();
    toast.success("Draft saved");
  }, [activeDraftId, drafts, draftsEnabled, saveDraft, saveExistingDraft, text]);

  const handleLoadDraft = React.useCallback(async (draftId: string) => {
    if (!draftsEnabled) return;
    const draftText = await loadDraft(draftId);
    if (!draftText) {
      toast.error("Draft unavailable");
      return;
    }
    setText(draftText);
    setActiveDraftId(draftId);
    setDraftDirty(false);
    setLastDraftSavedAt(Date.now());
    lastPersistedDraftTextRef.current = draftText.trim();
    toast.success("Draft loaded");
    requestAnimationFrame(() => {
      textareaRef.current?.focus();
      handleInput();
    });
  }, [draftsEnabled, loadDraft]);

  const handleDeleteDraft = React.useCallback((draftId: string) => {
    if (!draftsEnabled) return;
    deleteDraft(draftId);
    if (activeDraftId === draftId) {
      setActiveDraftId(null);
    }
    toast.success("Draft removed");
  }, [activeDraftId, deleteDraft, draftsEnabled]);

  React.useEffect(() => {
    latestComposerTextRef.current = text;
    latestActiveDraftIdRef.current = activeDraftId;
    latestDraftsEnabledRef.current = draftsEnabled;
  }, [activeDraftId, draftsEnabled, text]);

  React.useEffect(() => () => {
    if (!latestDraftsEnabledRef.current) return;
    const trimmed = latestComposerTextRef.current.trim();
    if (!trimmed) return;
    const draftId = latestActiveDraftIdRef.current;
    if (draftId) {
      saveExistingDraft(draftId, trimmed);
      return;
    }
    saveDraft(trimmed);
  }, [saveDraft, saveExistingDraft]);

  React.useEffect(() => {
    if (!draftsEnabled || activeDraftId || !draftDirty) return;
    const trimmed = text.trim();
    if (!trimmed) return;
    const matchingDraft = drafts.find((draft) => draft.text === trimmed);
    if (matchingDraft) {
      setActiveDraftId(matchingDraft.id);
    }
  }, [activeDraftId, draftDirty, drafts, draftsEnabled, text]);

  React.useEffect(() => {
    if (!draftsEnabled || !draftDirty) return;
    if (sending || encrypting) return;
    const trimmed = text.trim();
    if (!trimmed) return;
    if (trimmed === lastPersistedDraftTextRef.current) {
      setDraftDirty(false);
      return;
    }

    if (autosaveTimerRef.current != null) {
      window.clearTimeout(autosaveTimerRef.current);
    }
    autosaveTimerRef.current = window.setTimeout(() => {
      const saved = activeDraftId
        ? saveExistingDraft(activeDraftId, trimmed)
        : saveDraft(trimmed);
      if (saved) {
        setDraftDirty(false);
        setLastDraftSavedAt(Date.now());
        lastPersistedDraftTextRef.current = trimmed;
      }
      autosaveTimerRef.current = null;
    }, 1200);

    return () => {
      if (autosaveTimerRef.current != null) {
        window.clearTimeout(autosaveTimerRef.current);
        autosaveTimerRef.current = null;
      }
    };
  }, [activeDraftId, draftDirty, draftsEnabled, encrypting, saveDraft, saveExistingDraft, sending, text]);

  React.useEffect(() => {
    if (!draftsEnabled || typeof window === "undefined") return;
    const onBeforeUnload = (event: BeforeUnloadEvent) => {
      if (!draftDirty) return;
      event.preventDefault();
      event.returnValue = "You have unsaved draft changes.";
    };
    window.addEventListener("beforeunload", onBeforeUnload);
    return () => {
      window.removeEventListener("beforeunload", onBeforeUnload);
    };
  }, [draftDirty, draftsEnabled]);

  React.useEffect(() => {
    if (!draftsEnabled || typeof document === "undefined") return;
    const onVisibilityChange = () => {
      if (document.visibilityState !== "hidden") return;
      if (!draftDirty) return;
      if (sending || encrypting) return;
      const trimmed = text.trim();
      if (!trimmed || trimmed === lastPersistedDraftTextRef.current) {
        setDraftDirty(false);
        return;
      }
      const saved = activeDraftId
        ? saveExistingDraft(activeDraftId, trimmed)
        : saveDraft(trimmed);
      if (saved) {
        setDraftDirty(false);
        setLastDraftSavedAt(Date.now());
        lastPersistedDraftTextRef.current = trimmed;
      }
    };
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => {
      document.removeEventListener("visibilitychange", onVisibilityChange);
    };
  }, [activeDraftId, draftDirty, draftsEnabled, encrypting, saveDraft, saveExistingDraft, sending, text]);

  const handleRetryDraftSync = React.useCallback(async () => {
    if (!draftsEnabled || retryingDraftSync) return;
    setRetryingDraftSync(true);
    try {
      await refresh();
      toast.success("Draft sync retried");
    } finally {
      setRetryingDraftSync(false);
    }
  }, [draftsEnabled, refresh, retryingDraftSync]);

  const handleSubmit = async () => {
    if (sending || encrypting) return;
    // MSG-006: Convert :shortcode: tokens to Unicode emoji before sending so the
    // backend only ever stores Unicode characters.
    const trimmed = replaceShortcodes(text.trim());

    // Gallery mode: submit gallery instead of normal message
    if (galleryMode && onSendGallery) {
      if (galleryFreeFiles.length === 0 && galleryLockedFiles.length === 0) return;
      const extraPayload = buildExtraPayload();
      onSendGallery({
        freeFiles: galleryFreeFiles,
        lockedFiles: galleryLockedFiles,
        text: trimmed || undefined,
        lock_price_cents: galleryLockedFiles.length > 0 ? extraPayload.lock_price_cents : undefined,
        lock_description: galleryLockedFiles.length > 0 ? extraPayload.lock_description : undefined,
        expires_in_seconds: extraPayload.expires_in_seconds,
        send_at: extraPayload.send_at,
        tip_amount_cents: extraPayload.tip_amount_cents,
        tip_payment_method_id: extraPayload.tip_payment_method_id,
      });
      setText("");
      setActiveDraftId(null);
      setDraftDirty(false);
      lastPersistedDraftTextRef.current = "";
      resetTextArea();
      setGalleryFreeFiles([]);
      setGalleryLockedFiles([]);
      setGalleryMode(false);
      if (lockEnabled) { setLockEnabled(false); setLockPrice(""); setLockDescription(""); }
      if (tipEnabled) { setTipEnabled(false); setTipAmount(""); setTipPaymentMethodId(null); }
      if (scheduledAt) { setScheduledAt(null); setScheduledInput(""); setScheduleOpen(false); }
      if (expiresEnabled) { setExpiresEnabled(false); setExpiresDuration("3600"); }
      return;
    }

    if (lotteryMode && onSendLottery) {
      if (!lotteryOutcomesValid) return;
      onSendLottery({
        message_type: "lottery_dm",
        lottery_config: {
          version: "v1",
          outcomes: lotteryOutcomes.map((o, idx) => ({
            outcome_id: `o_${idx + 1}`,
            display_label: o.label.trim() || undefined,
            payload_type: o.payload_type,
            weight_bps: Math.max(1, Math.floor(o.weight_bps)),
            text_content: o.payload_type === "text" ? o.text_content.trim() : undefined,
            media_asset_id: o.payload_type !== "text" ? o.media_asset_id.trim() : undefined,
          })),
        },
      });
      setLotteryMode(false);
      setLotteryOutcomes([
        { id: "lo-1", label: "Outcome 1", payload_type: "text", text_content: "", media_asset_id: "", weight_bps: 5000, percent_input: "50.00" },
        { id: "lo-2", label: "Outcome 2", payload_type: "text", text_content: "", media_asset_id: "", weight_bps: 5000, percent_input: "50.00" },
      ]);
      setText("");
      resetTextArea();
      return;
    }

    // File share mode: send file share message
    if (pendingFileShare && onSendFileShare) {
      const extraPayload = buildExtraPayload();
      onSendFileShare({
        file_path: pendingFileShare.entry.path,
        permission: pendingFileShare.permission,
        text: trimmed || undefined,
        send_at: extraPayload.send_at,
      });
      setPendingFileShare(null);
      setText("");
      setActiveDraftId(null);
      setDraftDirty(false);
      lastPersistedDraftTextRef.current = "";
      resetTextArea();
      if (scheduledAt) { setScheduledAt(null); setScheduledInput(""); setScheduleOpen(false); }
      return;
    }

    if (!trimmed && !pendingFile) return;

    const resetTextState = () => {
      setText("");
      setActiveDraftId(null);
      setDraftDirty(false);
      lastPersistedDraftTextRef.current = "";
      resetTextArea();
      if (encryptEnabled) { setPassword(""); setConfirmPassword(""); }
      if (lockEnabled) { setLockEnabled(false); setLockPrice(""); setLockDescription(""); }
      if (tipEnabled) { setTipEnabled(false); setTipAmount(""); setTipPaymentMethodId(null); }
      if (scheduledAt) { setScheduledAt(null); setScheduledInput(""); setScheduleOpen(false); }
      if (viewOnceText) setViewOnceText(false);
      if (expiresEnabled) { setExpiresEnabled(false); setExpiresDuration("3600"); }
      if (countdownAttachEnabled) {
        setCountdownAttachEnabled(false);
        setCountdownAttachTitle("");
        setCountdownAttachInput("");
        setCountdownAttachRevealText("");
      }
    };

    // For image/PDF: send image with text as caption in a single bubble
    if (pendingFile && (pendingFile.kind === "image") && onSendImage) {
      const extraPayload = buildExtraPayload();
      onSendImage(pendingFile.file, {
        consumption_policy: viewOnceImage ? "view_once" : "none",
        caption: trimmed || undefined,
        expires_in_seconds: extraPayload.expires_in_seconds,
        lock_price_cents: extraPayload.lock_price_cents,
        lock_description: extraPayload.lock_description,
        tip_amount_cents: extraPayload.tip_amount_cents,
        tip_payment_method_id: tipPaymentMethodId ?? undefined,
        send_at: extraPayload.send_at,
        encryption_password: encryptEnabled ? password : undefined,
      });
      clearPendingFile();
      resetTextState();
      return;
    }

    // For video/audio: send media first, then text separately
    if (pendingFile) {
      const { file, kind } = pendingFile;
      if (kind === "video" && onSendVideoAttachment) {
        onSendVideoAttachment(file, { consumption_policy: viewOnceVideo ? "view_once" : "none" });
      } else if (kind === "audio" && onSendAudioRecording) {
        onSendAudioRecording(file, { consumption_policy: listenOnceAudio ? "listen_once" : "none" });
      }
      clearPendingFile();
    }

    // Send text if present
    if (trimmed) {
      const payload = await buildEncryptedPayload(trimmed);
      if (!payload) return;
      onSendText(payload);
      resetTextState();
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      void handleSubmit();
    } else if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
      // Power-user shortcut: Ctrl+Enter (Win/Linux) / Cmd+Enter (macOS) sends
      // regardless of shift state.
      e.preventDefault();
      void handleSubmit();
    }
  };

  const handleInput = () => {
    const ta = textareaRef.current;
    if (!ta) return;
    ta.style.height = "auto";
    ta.style.height = Math.min(ta.scrollHeight, 120) + "px";
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;

    // Clear any existing pending file
    if (pendingFile) URL.revokeObjectURL(pendingFile.previewUrl);

    let kind: "image" | "video" | "audio" | null = null;
    if ((file.type.startsWith("image/") || file.type === "application/pdf") && onSendImage) kind = "image";
    else if (file.type.startsWith("video/") && onSendVideoAttachment) kind = "video";
    else if (file.type.startsWith("audio/") && onSendAudioRecording) kind = "audio";

    if (!kind) return;

    const previewUrl = URL.createObjectURL(file);
    setPendingFile({ file, previewUrl, kind });
  };

  const _anyToggleActive = encryptEnabled || viewOnceText || lockEnabled || tipEnabled || expiresEnabled;

  return (
    <div className="border-t border-border bg-card px-4 py-3">

      {encryptEnabled && (
        <div className="mb-2 rounded-md border border-amber-300 bg-amber-50 p-2 text-xs text-amber-900">
          <p className="font-medium">This message will be encrypted locally before sending.</p>
          <p className="mt-1">If password is lost, recipients cannot decrypt this message.</p>
          <>
            <div className="mt-2 grid gap-2 sm:grid-cols-2">
                <div className="relative">
                  <input
                    type={showPassword ? "text" : "password"}
                    placeholder="Encryption password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full rounded border border-input bg-background px-2 py-1 pr-7 text-xs"
                    autoComplete="new-password"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((v) => !v)}
                    className="absolute right-1.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                    tabIndex={-1}
                    aria-label={showPassword ? "Hide password" : "Show password"}
                  >
                    {showPassword ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                  </button>
                </div>
                <div className="relative">
                  <input
                    type={showConfirmPassword ? "text" : "password"}
                    placeholder="Confirm password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className={cn(
                      "w-full rounded border bg-background px-2 py-1 pr-7 text-xs",
                      confirmPassword && password
                        ? password === confirmPassword
                          ? "border-green-500"
                          : "border-red-400"
                        : "border-input",
                    )}
                    autoComplete="new-password"
                  />
                  <button
                    type="button"
                    onClick={() => setShowConfirmPassword((v) => !v)}
                    className="absolute right-1.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                    tabIndex={-1}
                    aria-label={showConfirmPassword ? "Hide password" : "Show password"}
                  >
                    {showConfirmPassword ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                  </button>
                </div>
              </div>
              {confirmPassword && password && password !== confirmPassword && (
                <p className="mt-1 text-[11px] text-red-700">Passwords do not match</p>
              )}
              {confirmPassword && password && password === confirmPassword && (
                <p className="mt-1 text-[11px] text-green-700">Passwords match</p>
              )}
            </>
          {encryptError && <p className="mt-2 text-[11px] text-red-700">{encryptError}</p>}
        </div>
      )}

      {/* Active-toggle indicator strip — only shown when options are on */}
      {_anyToggleActive && (
        <div className="mb-2 flex flex-wrap items-center gap-1.5 text-[11px]">
          {encryptEnabled && (
            <span className="inline-flex items-center gap-1 rounded-full bg-amber-100 px-2 py-0.5 font-medium text-amber-700">
              <Lock className="h-3 w-3" /> Encrypted
              <button type="button" onClick={() => { setEncryptEnabled(false); setEncryptError(null); }} className="ml-0.5 hover:text-amber-900" aria-label="Disable encryption">×</button>
            </span>
          )}
          {viewOnceText && (
            <span className="inline-flex items-center gap-1 rounded-full bg-blue-100 px-2 py-0.5 font-medium text-blue-700">
              <Eye className="h-3 w-3" /> View once
              <button type="button" onClick={() => setViewOnceText(false)} className="ml-0.5 hover:text-blue-900" aria-label="Disable view once">×</button>
            </span>
          )}
          {lockEnabled && (
            <span className="inline-flex items-center gap-1 rounded-full bg-purple-100 px-2 py-0.5 font-medium text-purple-700">
              <Lock className="h-3 w-3" /> Locked
              <button type="button" onClick={() => { setLockEnabled(false); setLockPrice(""); setLockDescription(""); }} className="ml-0.5 hover:text-purple-900" aria-label="Disable lock">×</button>
            </span>
          )}
          {tipEnabled && (
            <span className="inline-flex items-center gap-1 rounded-full bg-green-100 px-2 py-0.5 font-medium text-green-700">
              <DollarSign className="h-3 w-3" /> Tip attached
              <button type="button" onClick={() => { setTipEnabled(false); setTipAmount(""); setTipPaymentMethodId(null); }} className="ml-0.5 hover:text-green-900" aria-label="Disable tip">×</button>
            </span>
          )}
          {expiresEnabled && (
            <span className="inline-flex items-center gap-1 rounded-full bg-orange-100 px-2 py-0.5 font-medium text-orange-700">
              Expires
              <button type="button" onClick={() => { setExpiresEnabled(false); setExpiresDuration("3600"); }} className="ml-0.5 hover:text-orange-900" aria-label="Disable expiry">×</button>
            </span>
          )}
        </div>
      )}
      {expiresEnabled && (
        <div className="mb-2 flex items-center gap-2 text-xs text-muted-foreground">
          <span>Expires in:</span>
          <select
            value={expiresDuration}
            onChange={(e) => setExpiresDuration(e.target.value)}
            className="rounded border border-input bg-background px-1 py-0.5 text-xs"
            disabled={disabled || sending}
          >
            <option value="60">1 minute</option>
            <option value="300">5 minutes</option>
            <option value="3600">1 hour</option>
            <option value="86400">1 day</option>
            <option value="604800">7 days</option>
          </select>
        </div>
      )}
      {countdownAttachEnabled && (
        <div className="mb-2 rounded-md border border-border bg-muted/30 p-2 text-xs space-y-1.5">
          <div className="flex flex-col gap-1">
            <label className="text-muted-foreground">Countdown title (optional)</label>
            <input
              type="text"
              value={countdownAttachTitle}
              onChange={(e) => setCountdownAttachTitle(e.target.value)}
              placeholder="e.g. Doors open in…"
              className="rounded border border-input bg-background px-2 py-1"
              disabled={disabled || sending}
            />
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-muted-foreground">Counts down to</label>
            <input
              type="datetime-local"
              value={countdownAttachInput}
              onChange={(e) => setCountdownAttachInput(e.target.value)}
              className="rounded border border-input bg-background px-2 py-1"
              disabled={disabled || sending}
            />
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-muted-foreground">Reveal text when it ends (optional)</label>
            <input
              type="text"
              value={countdownAttachRevealText}
              onChange={(e) => setCountdownAttachRevealText(e.target.value)}
              placeholder="Shown once the countdown completes"
              className="rounded border border-input bg-background px-2 py-1"
              disabled={disabled || sending}
            />
          </div>
        </div>
      )}
      {lockEnabled && (
        <div className="mb-2 rounded-md border border-border bg-muted/30 p-2 text-xs space-y-1.5">
          <div className="flex items-center gap-2">
            <label className="text-muted-foreground shrink-0">Price ($)</label>
            <input
              type="number"
              min="0.01"
              step="0.01"
              value={lockPrice}
              onChange={(e) => setLockPrice(e.target.value)}
              placeholder="e.g. 1.00"
              className="flex-1 rounded border border-input bg-background px-2 py-1 text-xs"
              disabled={disabled || sending}
            />
          </div>
          <textarea
            value={lockDescription}
            onChange={(e) => setLockDescription(e.target.value)}
            placeholder="Lock description (optional)"
            rows={2}
            className="w-full resize-none rounded border border-input bg-background px-2 py-1 text-xs"
            disabled={disabled || sending}
          />
        </div>
      )}
      {tipEnabled && (
        <div className="mb-2 rounded-md border border-green-200 bg-green-50 p-2 text-xs space-y-2">
          <p className="font-medium text-green-800">Attach a tip to this message</p>
          <div className="flex items-center gap-2">
            <label className="shrink-0 text-green-700">Amount ($)</label>
            <input
              type="number"
              min="0.01"
              step="0.01"
              value={tipAmount}
              onChange={(e) => setTipAmount(e.target.value)}
              placeholder="e.g. 5.00"
              className="flex-1 rounded border border-input bg-background px-2 py-1 text-xs"
              disabled={disabled || sending}
            />
          </div>
          {paymentMethods.length > 0 && (
            <div className="space-y-1">
              <p className="text-green-700">Pay with:</p>
              <div className="space-y-1">
                {paymentMethods.map((pm) => {
                  const label = pm.brand
                    ? `${pm.brand.charAt(0).toUpperCase() + pm.brand.slice(1)} •••• ${pm.last4}`
                    : (pm.label ?? pm.method_type);
                  const isSelected = tipPaymentMethodId === pm.payment_method_id;
                  return (
                    <button
                      key={pm.payment_method_id}
                      type="button"
                      onClick={() => setTipPaymentMethodId(pm.payment_method_id)}
                      className={cn(
                        "flex w-full items-center gap-2 rounded border px-2 py-1 text-xs transition-colors hover:bg-green-100",
                        isSelected ? "border-green-500 bg-green-100" : "border-green-200 bg-white",
                      )}
                    >
                      <span className="flex-1 text-left">{label}</span>
                      {pm.is_default && <span className="text-[10px] text-green-600">Default</span>}
                      {isSelected && <span className="text-[10px] font-bold text-green-700">✓</span>}
                    </button>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Gallery mode UI */}
      {galleryMode && onSendGallery && (
        <div className="mb-2 rounded-md border border-border bg-muted/30 p-2 text-xs space-y-2">
          <div className="flex items-center justify-between">
            <span className="font-medium text-foreground">Gallery message</span>
            <button
              type="button"
              onClick={() => { setGalleryMode(false); setGalleryFreeFiles([]); setGalleryLockedFiles([]); }}
              className="text-muted-foreground hover:text-foreground"
              aria-label="Exit gallery mode"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>

          {/* Free items zone (images + videos) */}
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Free items ({galleryFreeFiles.length}/20)</span>
              <button
                type="button"
                onClick={() => galleryFreeInputRef.current?.click()}
                disabled={disabled || sending || galleryFreeFiles.length >= 20}
                className="inline-flex items-center gap-1 rounded border border-input bg-background px-2 py-0.5 text-xs hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ImageIcon className="h-3 w-3" /> Add
              </button>
            </div>
            <input
              ref={galleryFreeInputRef}
              type="file"
              accept="image/*,video/*"
              multiple
              className="hidden"
              onChange={(e) => {
                const files = Array.from(e.target.files ?? []);
                e.target.value = "";
                setGalleryFreeFiles((prev) => [...prev, ...files].slice(0, 20));
              }}
            />
            {galleryFreePreviews.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {galleryFreePreviews.map(({ file, url }, i) => (
                  <div key={i} className="group relative">
                    {file.type.startsWith("video/") ? (
                      <video
                        src={url}
                        className="h-12 w-12 rounded object-cover"
                        muted
                        playsInline
                        preload="metadata"
                      />
                    ) : (
                      <img
                        src={url}
                        alt={file.name}
                        className="h-12 w-12 rounded object-cover"
                      />
                    )}
                    <button
                      type="button"
                      onClick={() => setGalleryFreeFiles((prev) => prev.filter((_, j) => j !== i))}
                      className="absolute -right-1 -top-1 hidden h-4 w-4 items-center justify-center rounded-full bg-destructive text-white group-hover:flex"
                      aria-label="Remove"
                    >
                      <X className="h-2.5 w-2.5" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Locked items zone (images + videos) */}
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">
                <Lock className="inline h-3 w-3 mr-0.5" />
                Locked items ({galleryLockedFiles.length}/30)
              </span>
              <button
                type="button"
                onClick={() => galleryLockedInputRef.current?.click()}
                disabled={disabled || sending || galleryLockedFiles.length >= 30}
                className="inline-flex items-center gap-1 rounded border border-input bg-background px-2 py-0.5 text-xs hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ImageIcon className="h-3 w-3" /> Add
              </button>
            </div>
            <input
              ref={galleryLockedInputRef}
              type="file"
              accept="image/*,video/*"
              multiple
              className="hidden"
              onChange={(e) => {
                const files = Array.from(e.target.files ?? []);
                e.target.value = "";
                setGalleryLockedFiles((prev) => [...prev, ...files].slice(0, 30));
              }}
            />
            {galleryLockedPreviews.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {galleryLockedPreviews.map(({ file, url }, i) => (
                  <div key={i} className="group relative">
                    {file.type.startsWith("video/") ? (
                      <video
                        src={url}
                        className="h-12 w-12 rounded object-cover opacity-70"
                        muted
                        playsInline
                        preload="metadata"
                      />
                    ) : (
                      <img
                        src={url}
                        alt={file.name}
                        className="h-12 w-12 rounded object-cover opacity-70"
                      />
                    )}
                    <Lock className="absolute bottom-0.5 right-0.5 h-3 w-3 text-white drop-shadow" />
                    <button
                      type="button"
                      onClick={() => setGalleryLockedFiles((prev) => prev.filter((_, j) => j !== i))}
                      className="absolute -right-1 -top-1 hidden h-4 w-4 items-center justify-center rounded-full bg-destructive text-white group-hover:flex"
                      aria-label="Remove"
                    >
                      <X className="h-2.5 w-2.5" />
                    </button>
                  </div>
                ))}
              </div>
            )}
            {galleryLockedFiles.length > 0 && !lockEnabled && (
              <p className="text-[10px] text-amber-600">Set a lock price below to require payment for locked items.</p>
            )}
          </div>
        </div>
      )}

      {draftsEnabled && syncIssue !== "none" && (
        <div
          className="mb-2 flex items-start justify-between gap-2 rounded-lg border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900"
          role="status"
          aria-live="polite"
        >
          <div className="min-w-0 flex-1">
            <p className="font-medium">Draft sync issue</p>
            <p className="text-[11px] text-amber-800">
              {requiresReauth
                ? "Please sign in again to sync drafts with the server."
                : syncIssue === "network"
                ? "You are offline or the drafts service is unavailable. Local drafts are still saved."
                : "Server sync failed. Local drafts are still saved and will retry when available."}
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-1">
            {!requiresReauth && (
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="h-6 px-2 text-[11px] text-amber-900 hover:bg-amber-100"
                onClick={() => void handleRetryDraftSync()}
                disabled={retryingDraftSync}
              >
                {retryingDraftSync ? "Retrying..." : "Retry sync"}
              </Button>
            )}
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="h-6 px-2 text-[11px] text-amber-900 hover:bg-amber-100"
              onClick={clearSyncIssue}
            >
              Dismiss
            </Button>
          </div>
        </div>
      )}

      {lotteryMode && onSendLottery && (
        <div className="mb-2 rounded-md border border-border bg-muted/30 p-2 text-xs space-y-2">
          <div className="flex items-center justify-between">
            <span className="font-medium text-foreground">Lottery message</span>
            <button
              type="button"
              onClick={() => setLotteryMode(false)}
              className="text-muted-foreground hover:text-foreground"
              aria-label="Exit lottery mode"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>

          <div className="text-[11px] text-muted-foreground">
            Configure 2-10 outcomes. Total weight must equal 10,000 bps (100%).
          </div>
          <div className="text-[10px] text-muted-foreground">
            Percentage is deterministically converted using: <span className="font-mono">bps = round(percent × 100)</span>.
          </div>

          {lotteryOutcomes.map((row, idx) => (
            <div key={row.id} className="rounded border border-border bg-background p-2 space-y-2">
              <div className="flex items-center gap-2">
                <input
                  value={row.label}
                  onChange={(e) =>
                    setLotteryOutcomes((prev) => prev.map((o) => o.id === row.id ? { ...o, label: e.target.value } : o))
                  }
                  placeholder={`Outcome ${idx + 1} label`}
                  className="flex-1 rounded border border-input px-2 py-1 text-xs"
                />
                <select
                  value={row.payload_type}
                  onChange={(e) =>
                    setLotteryOutcomes((prev) => prev.map((o) => o.id === row.id ? { ...o, payload_type: e.target.value as "text" | "image" | "video" } : o))
                  }
                  className="rounded border border-input bg-background px-2 py-1 text-xs"
                >
                  <option value="text">Text</option>
                  <option value="image">Image</option>
                  <option value="video">Video</option>
                </select>
                <input
                  type="number"
                  min={0}
                  max={100}
                  step="0.01"
                  value={row.percent_input}
                  onChange={(e) => {
                    const raw = e.target.value;
                    setLotteryOutcomes((prev) => prev.map((o) => {
                      if (o.id !== row.id) return o;
                      const parsed = Number(raw);
                      if (!Number.isFinite(parsed)) return { ...o, percent_input: raw, weight_bps: 0 };
                      const clamped = Math.max(0, Math.min(100, parsed));
                      const bps = Math.round(clamped * 100);
                      return { ...o, percent_input: raw, weight_bps: bps };
                    }));
                  }}
                  onBlur={() => {
                    setLotteryOutcomes((prev) => prev.map((o) => {
                      if (o.id !== row.id) return o;
                      if (!o.percent_input.trim()) return { ...o, percent_input: "0.00", weight_bps: 0 };
                      const parsed = Number(o.percent_input);
                      const clamped = Number.isFinite(parsed) ? Math.max(0, Math.min(100, parsed)) : 0;
                      const bps = Math.round(clamped * 100);
                      return { ...o, weight_bps: bps, percent_input: (bps / 100).toFixed(2) };
                    }));
                  }}
                  className="w-24 rounded border border-input px-2 py-1 text-xs"
                  aria-label="Weight percent"
                />
                <span className="text-[10px] text-muted-foreground">%</span>
                <input
                  type="number"
                  min={0}
                  max={10000}
                  value={row.weight_bps}
                  onChange={(e) =>
                    setLotteryOutcomes((prev) => prev.map((o) => {
                      if (o.id !== row.id) return o;
                      const parsed = Number(e.target.value || 0);
                      const bps = Number.isFinite(parsed) ? Math.max(0, Math.min(10_000, Math.round(parsed))) : 0;
                      return { ...o, weight_bps: bps, percent_input: (bps / 100).toFixed(2) };
                    }))
                  }
                  className="w-24 rounded border border-input px-2 py-1 text-xs"
                  aria-label="Weight bps"
                />
                <span className="text-[10px] text-muted-foreground">bps</span>
                <button
                  type="button"
                  onClick={() => setLotteryOutcomes((prev) => prev.filter((o) => o.id !== row.id))}
                  disabled={lotteryOutcomes.length <= 2}
                  className="rounded border border-input px-2 py-1 text-[10px] disabled:opacity-50"
                >
                  Remove
                </button>
              </div>
              {lotteryFieldErrors[idx]?.weightError && (
                <p className="text-[10px] text-red-600">{lotteryFieldErrors[idx]?.weightError}</p>
              )}
              {row.payload_type === "text" ? (
                <textarea
                  value={row.text_content}
                  onChange={(e) =>
                    setLotteryOutcomes((prev) => prev.map((o) => o.id === row.id ? { ...o, text_content: e.target.value } : o))
                  }
                  placeholder="Text outcome content"
                  rows={2}
                  className="w-full rounded border border-input px-2 py-1 text-xs"
                />
              ) : (
                <div className="flex items-center gap-2">
                  <label className="inline-flex cursor-pointer items-center gap-1 rounded border border-input bg-background px-2 py-1 text-xs hover:bg-accent">
                    {row.payload_type === "video" ? <Video className="h-3.5 w-3.5" /> : <ImageIcon className="h-3.5 w-3.5" />}
                    {row.uploading ? "Uploading…" : row.media_asset_id ? "Replace" : `Upload ${row.payload_type === "video" ? "video" : "image"}`}
                    <input
                      type="file"
                      accept={row.payload_type === "video" ? "video/*" : "image/*"}
                      className="hidden"
                      disabled={row.uploading}
                      onChange={(e) => {
                        const file = e.target.files?.[0];
                        if (file) void handleLotteryMediaUpload(row.id, file);
                        e.target.value = "";
                      }}
                    />
                  </label>
                  {row.media_asset_id && !row.uploading && (
                    <span className="inline-flex items-center gap-1 truncate text-[10px] text-muted-foreground">
                      <Check className="h-3 w-3 text-green-600" />
                      {row.media_name ?? "Uploaded"}
                    </span>
                  )}
                </div>
              )}
              {lotteryFieldErrors[idx]?.payloadError && (
                <p className="text-[10px] text-red-600">{lotteryFieldErrors[idx]?.payloadError}</p>
              )}
            </div>
          ))}

          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() =>
                  setLotteryOutcomes((prev) => [
                    ...prev,
                    { id: `lo-${Date.now()}`, label: `Outcome ${prev.length + 1}`, payload_type: "text" as const, text_content: "", media_asset_id: "", weight_bps: 1000, percent_input: "10.00" },
                  ].slice(0, 10))
                }
                disabled={lotteryOutcomes.length >= 10}
              >
                Add outcome
              </Button>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => {
                  const n = lotteryOutcomes.length;
                  if (n <= 0) return;
                  const base = Math.floor(10_000 / n);
                  const remainder = 10_000 - (base * n);
                  setLotteryOutcomes((prev) => prev.map((o, i) => {
                    const bps = base + (i < remainder ? 1 : 0);
                    return { ...o, weight_bps: bps, percent_input: (bps / 100).toFixed(2) };
                  }));
                }}
              >
                Auto-balance
              </Button>
            </div>
            <span className={cn("text-[11px]", lotteryTotalBps === 10_000 ? "text-emerald-600" : "text-amber-600")}>
              Total: {(lotteryTotalBps / 100).toFixed(2)}% ({lotteryTotalBps}/10000 bps)
            </span>
          </div>
          {lotteryTotalBps !== 10_000 && (
            <p className="text-[10px] text-amber-600">
              Total must equal exactly 100.00% (10,000 bps) before you can send.
            </p>
          )}
        </div>
      )}

      {/* Reply context */}
      {draftsEnabled && drafts.length > 0 && (
        <div className="mb-2 rounded-lg border border-border bg-muted/20 px-3 py-2">
          <p className="mb-2 text-xs font-medium text-muted-foreground">Saved drafts</p>
          <div className="space-y-1.5">
            {drafts.slice(0, 3).map((draft) => (
              <div key={draft.id} className="flex items-center gap-2 rounded border border-border bg-background px-2 py-1.5">
                <p className="line-clamp-1 flex-1 text-xs text-foreground">{draft.text}</p>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-6 px-2 text-[11px]"
                  onClick={() => handleLoadDraft(draft.id)}
                >
                  Load
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-6 px-2 text-[11px] text-destructive"
                  onClick={() => handleDeleteDraft(draft.id)}
                >
                  Remove
                </Button>
              </div>
            ))}
          </div>
        </div>
      )}

      {replyingTo && (
        <div className="mb-2 flex items-start gap-2 rounded-lg border border-border bg-muted/40 px-3 py-2">
          <Reply className="mt-0.5 h-3.5 w-3.5 shrink-0 text-primary" />
          <div className="min-w-0 flex-1 text-xs">
            <p className="font-semibold text-primary">{replyingTo.sender_id}</p>
            <p className="truncate text-muted-foreground">
              {replyingTo.kind === "image" ? "[Image]"
               : replyingTo.kind === "video" ? "[Video]"
               : replyingTo.kind === "audio" ? "[Audio]"
               : replyingTo.kind === "file" ? (replyingTo.file?.name ?? "[File]")
               : replyingTo.is_encrypted ? "[Encrypted message]"
               : (replyingTo.text ?? "").slice(0, 100) || "[Message]"}
            </p>
          </div>
          <button
            type="button"
            onClick={onCancelReply}
            className="shrink-0 text-muted-foreground hover:text-foreground"
            aria-label="Cancel reply"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      )}

      {/* Scheduled pill */}
      {scheduledAt && (
        <div className="mb-2 flex items-center gap-2">
          <span className="inline-flex items-center gap-1.5 rounded-full bg-blue-100 px-2.5 py-1 text-[11px] font-medium text-blue-800">
            <Clock className="h-3 w-3" />
            Scheduled: {scheduledAt.toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" })}
          </span>
          <button
            type="button"
            onClick={() => setScheduledAt(null)}
            className="text-muted-foreground hover:text-foreground"
            aria-label="Remove schedule"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      )}

      {/* Pending file share preview */}
      {pendingFileShare && (
        <div className="mb-2 rounded-lg border border-border bg-muted/40 p-3 space-y-2">
          <div className="flex items-start gap-3">
            <FileText className="h-8 w-8 shrink-0 text-muted-foreground mt-0.5" />
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm font-medium">{pendingFileShare.entry.name}</p>
              {pendingFileShare.entry.size != null && (
                <p className="text-xs text-muted-foreground">
                  {pendingFileShare.entry.size < 1024
                    ? `${pendingFileShare.entry.size} B`
                    : pendingFileShare.entry.size < 1024 ** 2
                    ? `${(pendingFileShare.entry.size / 1024).toFixed(1)} KB`
                    : `${(pendingFileShare.entry.size / 1024 ** 2).toFixed(1)} MB`}
                </p>
              )}
              {pendingFileShare.entry.is_encrypted && (
                <p className="flex items-center gap-1 text-xs text-amber-600 mt-0.5">
                  <Lock className="h-3 w-3" /> Encrypted
                </p>
              )}
            </div>
            <button
              type="button"
              onClick={() => setPendingFileShare(null)}
              className="shrink-0 rounded-full p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
              aria-label="Remove file share"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground shrink-0">Permission:</span>
            <div className="flex rounded border border-input overflow-hidden text-xs">
              <button
                type="button"
                onClick={() => setPendingFileShare((prev) => prev ? { ...prev, permission: "read" } : prev)}
                className={cn(
                  "px-2.5 py-0.5 transition-colors",
                  pendingFileShare.permission === "read"
                    ? "bg-primary text-primary-foreground"
                    : "bg-background text-muted-foreground hover:bg-muted",
                )}
              >
                View only
              </button>
              <button
                type="button"
                onClick={() => setPendingFileShare((prev) => prev ? { ...prev, permission: "write" } : prev)}
                className={cn(
                  "px-2.5 py-0.5 border-l border-input transition-colors",
                  pendingFileShare.permission === "write"
                    ? "bg-primary text-primary-foreground"
                    : "bg-background text-muted-foreground hover:bg-muted",
                )}
              >
                View + Edit
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Pending file preview */}
      {pendingFile && (
        <div className="mb-2 flex flex-col gap-2 rounded-lg border border-border bg-muted/40 p-2">
          <div className="flex items-center gap-2">
            {pendingFile.kind === "image" && !pendingFile.file.type.includes("pdf") ? (
              <img
                src={pendingFile.previewUrl}
                alt="Attachment preview"
                className="h-16 w-16 rounded-md object-cover shrink-0"
              />
            ) : (
              <div className="flex h-16 w-16 shrink-0 items-center justify-center rounded-md bg-muted">
                {pendingFile.file.type.includes("pdf") ? (
                  <FileText className="h-6 w-6 text-red-500" />
                ) : (
                  <ImageIcon className="h-6 w-6 text-muted-foreground" />
                )}
              </div>
            )}
            <div className="min-w-0 flex-1">
              <p className="truncate text-xs font-medium">{pendingFile.file.name}</p>
              <p className="text-xs text-muted-foreground capitalize">{pendingFile.kind} • ready to send</p>
            </div>
            <button
              type="button"
              onClick={clearPendingFile}
              className="shrink-0 rounded-full p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
              aria-label="Remove attachment"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
          {/* View-once option inside file preview */}
          {pendingFile.kind === "image" && onceImageEnabled && onSendImage && (
            <label className="inline-flex items-center gap-2 text-xs text-muted-foreground">
              <input
                type="checkbox"
                checked={viewOnceImage}
                onChange={(e) => setViewOnceImage(e.target.checked)}
                disabled={disabled || sending || encrypting}
              />
              <EyeSlash className="h-3.5 w-3.5" />
              Recipient can only view once
            </label>
          )}
          {pendingFile.kind === "video" && onceVideoEnabled && onSendVideoAttachment && (
            <label className="inline-flex items-center gap-2 text-xs text-muted-foreground">
              <input
                type="checkbox"
                checked={viewOnceVideo}
                onChange={(e) => setViewOnceVideo(e.target.checked)}
                disabled={disabled || sending || encrypting}
              />
              <EyeSlash className="h-3.5 w-3.5" />
              Recipient can only view once
            </label>
          )}
          {pendingFile.kind === "audio" && onceAudioEnabled && onSendAudioRecording && (
            <label className="inline-flex items-center gap-2 text-xs text-muted-foreground">
              <input
                type="checkbox"
                checked={listenOnceAudio}
                onChange={(e) => setListenOnceAudio(e.target.checked)}
                disabled={disabled || sending || encrypting}
              />
              <Headphones className="h-3.5 w-3.5" />
              Recipient can only listen once
            </label>
          )}
        </div>
      )}

      <div className="flex items-end gap-2">
        {(onSendVoiceMessage || onSendGallery || onSendLottery || onSendFileShare || onSendVideoShare ||
          onSendCalendarShare || onSendCalendarEvent || onSendMeetingPoll || onSendFindDateTime ||
          onSendCountdown || onSendMarketCard || onSendPositionCard || onSendCryptoTransfer || onSendProductCard || onSendOrderCard || draftsEnabled || (onSendTtsVoice && ttsEnabled)) && (
          <Popover open={moreOpen} onOpenChange={setMoreOpen}>
            <PopoverTrigger asChild>
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="relative h-9 w-9 shrink-0"
                aria-label="More compose options"
                data-testid="compose-more"
                disabled={disabled || sending || encrypting}
              >
                <Plus className="h-4 w-4" />
                {_anyToggleActive && (
                  <span className="absolute right-1 top-1 h-2 w-2 rounded-full bg-primary" aria-hidden="true" />
                )}
              </Button>
            </PopoverTrigger>
            <PopoverContent side="top" align="start" className="w-64 p-1">
              <div className="grid">
                {/* Message option toggles */}
                {featureEnabled && (
                  <Button
                    type="button"
                    variant={encryptEnabled ? "secondary" : "ghost"}
                    className="h-9 justify-start gap-2 px-2"
                    onClick={() => { setEncryptEnabled((v) => { if (v) setEncryptError(null); return !v; }); setMoreOpen(false); }}
                    disabled={disabled || sending || encrypting}
                    aria-label="Toggle message encryption"
                    data-testid="compose-toggle-encrypt"
                  >
                    <Lock className="h-4 w-4" /> Encrypt message
                  </Button>
                )}
                {!pendingFile && (
                  <Button
                    type="button"
                    variant={viewOnceText ? "secondary" : "ghost"}
                    className="h-9 justify-start gap-2 px-2"
                    onClick={() => { setViewOnceText((v) => !v); setMoreOpen(false); }}
                    disabled={disabled || sending || encrypting}
                    aria-label="Toggle view once"
                    data-testid="compose-toggle-view-once"
                  >
                    <Eye className="h-4 w-4" /> View once
                  </Button>
                )}
                <Button
                  type="button"
                  variant={lockEnabled ? "secondary" : "ghost"}
                  className="h-9 justify-start gap-2 px-2"
                  onClick={() => { setLockEnabled((v) => { if (!v) setTipEnabled(false); return !v; }); setMoreOpen(false); }}
                  disabled={disabled || sending || encrypting}
                  aria-label="Toggle message lock"
                  data-testid="compose-toggle-lock"
                >
                  <Lock className="h-4 w-4" /> Require tip to unlock
                </Button>
                <TooltipProvider delayDuration={0}>
                  <Tooltip>
                    {/* Span trigger: a disabled <button> suppresses pointer events in
                        Chromium, so the tooltip would never open. Wrapping in a span
                        keeps the hover target alive even when the button is disabled. */}
                    <TooltipTrigger asChild>
                      <span className="block w-full">
                        <Button
                          type="button"
                          variant={tipEnabled ? "secondary" : "ghost"}
                          className={cn("h-9 w-full justify-start gap-2 px-2", !hasPaymentMethods && "opacity-50 cursor-not-allowed")}
                          onClick={() => { if (!hasPaymentMethods) return; setTipEnabled((v) => { if (!v) setLockEnabled(false); return !v; }); setMoreOpen(false); }}
                          disabled={disabled || sending || encrypting || !hasPaymentMethods}
                          aria-label="Toggle attach tip"
                          data-testid="compose-toggle-tip"
                        >
                          <DollarSign className="h-4 w-4" /> Attach tip
                        </Button>
                      </span>
                    </TooltipTrigger>
                    {!hasPaymentMethods && (
                      <TooltipContent>Add a payment method in Billing to attach tips</TooltipContent>
                    )}
                  </Tooltip>
                </TooltipProvider>
                <Button
                  type="button"
                  variant={expiresEnabled ? "secondary" : "ghost"}
                  className="h-9 justify-start gap-2 px-2"
                  onClick={() => { setExpiresEnabled((v) => !v); setMoreOpen(false); }}
                  disabled={disabled || sending || encrypting}
                  aria-label="Toggle message expiry"
                  data-testid="compose-toggle-expires"
                >
                  <Clock className="h-4 w-4" /> Message expires
                </Button>
                <Button
                  type="button"
                  variant={countdownAttachEnabled ? "secondary" : "ghost"}
                  className="h-9 justify-start gap-2 px-2"
                  onClick={() => { setCountdownAttachEnabled((v) => !v); setMoreOpen(false); }}
                  disabled={disabled || sending || encrypting}
                  aria-label="Toggle attach countdown"
                  data-testid="compose-toggle-countdown-attach"
                >
                  <Timer className="h-4 w-4" /> Attach countdown
                </Button>
                <div className="my-1 border-t border-border" />
                {onSendVoiceMessage && !voiceRecording && (
                  <Button variant="ghost" className="h-9 justify-start gap-2 px-2"
                    onClick={() => { setVoiceRecording(true); setMoreOpen(false); }}
                    disabled={disabled || sending || encrypting || !!pendingFile || galleryMode || lotteryMode}
                    aria-label="Record voice message">
                    <Mic className="h-4 w-4" /> Voice message
                  </Button>
                )}
                {onSendTtsVoice && ttsEnabled && (
                  <Button variant="ghost" className="h-9 justify-start gap-2 px-2"
                    onClick={() => { void handleSpeakThis(); }}
                    disabled={disabled || sending || encrypting || ttsSynthesizing || !text.trim()}
                    aria-label="Speak this draft as a voice message">
                    {ttsSynthesizing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Headphones className="h-4 w-4" />} Speak this
                  </Button>
                )}
                {onSendGallery && (
                  <Button variant={galleryMode ? "secondary" : "ghost"} className="h-9 justify-start gap-2 px-2"
                    onClick={() => { setGalleryMode((v) => !v); setLotteryMode(false); setPendingFile(null); setMoreOpen(false); }}
                    disabled={disabled || sending || encrypting}
                    aria-label="Gallery message">
                    <Images className="h-4 w-4" /> Gallery
                  </Button>
                )}
                {onSendLottery && (
                  <Button variant={lotteryMode ? "secondary" : "ghost"} className="h-9 justify-start gap-2 px-2"
                    onClick={() => { setLotteryMode((v) => !v); setGalleryMode(false); setPendingFile(null); setMoreOpen(false); }}
                    disabled={disabled || sending || encrypting}
                    aria-label="Lottery message">
                    <Dices className="h-4 w-4" /> Lottery
                  </Button>
                )}
                {onSendFileShare && (
                  <Button variant={pendingFileShare ? "secondary" : "ghost"} className="h-9 justify-start gap-2 px-2"
                    onClick={() => { setFilePickerOpen(true); setMoreOpen(false); }}
                    disabled={disabled || sending || encrypting}
                    aria-label="Share file from Files">
                    <FolderOpen className="h-4 w-4" /> Share a file
                  </Button>
                )}
                {onSendVideoShare && (
                  <Button type="button" variant="ghost" className="h-9 justify-start gap-2 px-2"
                    onClick={() => { setVideoPickerOpen(true); setMoreOpen(false); }}
                    disabled={disabled || sending}
                    aria-label="Share video">
                    <Video className="h-4 w-4" /> Share a video
                  </Button>
                )}
                {onSendCalendarShare && (
                  <Button variant="ghost" className="h-9 justify-start gap-2 px-2"
                    onClick={() => { setCalendarPickerOpen(true); setMoreOpen(false); }} aria-label="Share my calendar">
                    <CalendarDays className="h-4 w-4" /> Share my calendar
                  </Button>
                )}
                {onSendCalendarEvent && (
                  <Button variant="ghost" className="h-9 justify-start gap-2 px-2"
                    onClick={() => { setEventPickerOpen(true); setMoreOpen(false); }} aria-label="Share an event">
                    <CalendarCheck className="h-4 w-4" /> Share an event
                  </Button>
                )}
                {onSendMeetingPoll && (
                  <Button variant="ghost" className="h-9 justify-start gap-2 px-2"
                    onClick={() => { setMeetingPollOpen(true); setMoreOpen(false); }} aria-label="Schedule a meeting">
                    <Users className="h-4 w-4" /> Schedule a meeting
                  </Button>
                )}
                {onSendFindDateTime && (
                  <Button variant="ghost" className="h-9 justify-start gap-2 px-2"
                    onClick={() => { setFindDateTimeOpen(true); setMoreOpen(false); }} aria-label="Find a Time">
                    <Clock className="h-4 w-4" /> Find a Time
                  </Button>
                )}
                {onSendCountdown && (
                  <Button variant="ghost" className="h-9 justify-start gap-2 px-2"
                    onClick={() => { setCountdownOpen(true); setMoreOpen(false); }} aria-label="Create a countdown">
                    <Timer className="h-4 w-4" /> Create a countdown
                  </Button>
                )}
                {onSendMarketCard && (
                  <Button variant="ghost" className="h-9 justify-start gap-2 px-2"
                    onClick={() => { setMarketCardOpen(true); setMoreOpen(false); }} aria-label="Share market">
                    <TrendingUp className="h-4 w-4" /> Share market
                  </Button>
                )}
                {onSendPositionCard && (
                  <Button variant="ghost" className="h-9 justify-start gap-2 px-2"
                    onClick={() => { setPositionCardOpen(true); setMoreOpen(false); }} aria-label="Share position">
                    <Activity className="h-4 w-4" /> Share position
                  </Button>
                )}
                {onSendCryptoTransfer && (
                  <Button variant="ghost" className="h-9 justify-start gap-2 px-2"
                    onClick={() => { setCryptoSendOpen(true); setMoreOpen(false); }} aria-label="Send crypto"
                    data-testid="compose-send-crypto">
                    <DollarSign className="h-4 w-4" /> Send crypto
                  </Button>
                )}
                {onSendProductCard && (
                  <Button variant="ghost" className="h-9 justify-start gap-2 px-2"
                    onClick={() => { setProductCardOpen(true); setMoreOpen(false); }} aria-label="Share product"
                    data-testid="compose-share-product">
                    <Package className="h-4 w-4" /> Share product
                  </Button>
                )}
                {onSendOrderCard && (
                  <Button variant="ghost" className="h-9 justify-start gap-2 px-2"
                    onClick={() => { setOrderCardOpen(true); setMoreOpen(false); }} aria-label="Share purchase"
                    data-testid="compose-share-purchase">
                    <ShoppingBag className="h-4 w-4" /> Share purchase
                  </Button>
                )}
                {draftsEnabled && (
                  <Button type="button" variant="ghost" className="h-9 justify-start gap-2 px-2"
                    onClick={() => { handleSaveDraft(); setMoreOpen(false); }}
                    disabled={disabled || sending || encrypting}
                    aria-label="Save draft">
                    <FileText className="h-4 w-4" /> Save draft
                  </Button>
                )}
              </div>
            </PopoverContent>
          </Popover>
        )}
        {onSendImage && (
          <>
            <Button
              variant="ghost"
              size="icon"
              className="h-9 w-9 shrink-0"
              onClick={() => fileInputRef.current?.click()}
              disabled={disabled || sending || encrypting || !!pendingFile || galleryMode || lotteryMode}
              aria-label="Attach file"
            >
              <Paperclip className="h-4 w-4" />
            </Button>
            <input
              ref={fileInputRef}
              type="file"
              accept="image/*,video/*,audio/*,application/pdf"
              className="hidden"
              onChange={handleFileChange}
            />
          </>
        )}
        <Popover open={emojiPickerOpen} onOpenChange={setEmojiPickerOpen}>
          <PopoverTrigger asChild>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="h-9 w-9 shrink-0"
              aria-label="Insert emoji"
              data-testid="emoji-button"
              disabled={disabled || sending}
            >
              <Smile className="h-4 w-4" />
            </Button>
          </PopoverTrigger>
          <PopoverContent side="top" align="start" className="w-auto p-0">
            <EmojiPicker
              onSelect={(emoji) => insertEmoji(emoji)}
              onClose={() => setEmojiPickerOpen(false)}
            />
          </PopoverContent>
        </Popover>

        <Popover open={gifPickerOpen} onOpenChange={setGifPickerOpen}>
          <PopoverTrigger asChild>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="h-9 w-9 shrink-0"
              aria-label="Send a GIF"
              disabled={disabled || sending}
            >
              <Images className="h-4 w-4" />
            </Button>
          </PopoverTrigger>
          <PopoverContent side="top" align="start" className="w-auto p-2">
            <GifPicker
              onSelect={(gif) => {
                sendGifMut.mutate(gif);
                setGifPickerOpen(false);
              }}
            />
          </PopoverContent>
        </Popover>

        <Popover open={stickerPickerOpen} onOpenChange={setStickerPickerOpen}>
          <PopoverTrigger asChild>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="h-9 w-9 shrink-0"
              aria-label="Send a sticker"
              disabled={disabled || sending}
            >
              <StickerIcon className="h-4 w-4" />
            </Button>
          </PopoverTrigger>
          <PopoverContent side="top" align="start" className="w-auto p-2">
            <StickerPicker
              onSelect={(sticker) => {
                sendStickerMut.mutate({ id: sticker.id, collection_id: sticker.collection_id });
                setStickerPickerOpen(false);
              }}
            />
          </PopoverContent>
        </Popover>

        {draftsEnabled && (
          <span
            className="shrink-0 text-[11px] text-muted-foreground"
            aria-live="polite"
          >
            {draftDirty
              ? "Unsaved draft"
              : lastDraftSavedAt
              ? "Draft saved"
              : "No draft changes"}
          </span>
        )}

        {voiceRecording && onSendVoiceMessage ? (
          <div className="flex-1">
            <VoiceRecorder
              onComplete={(blob, meta) => {
                setVoiceRecording(false);
                onSendVoiceMessage(blob, {
                  ...meta,
                  consumption_policy: listenOnceAudio ? "listen_once" : "none",
                  reply_to_message_id: replyingTo?.message_id ?? null,
                  send_at: scheduledAt ? Math.floor(scheduledAt.getTime() / 1000) : null,
                });
                onCancelReply?.();
              }}
              onCancel={() => setVoiceRecording(false)}
            />
          </div>
        ) : (
          <textarea
            ref={textareaRef}
            value={text}
            onChange={(e) => {
              setText(e.target.value);
              if (draftsEnabled) {
                const trimmed = e.target.value.trim();
                setDraftDirty(trimmed.length > 0 && trimmed !== lastPersistedDraftTextRef.current);
              }
              onKeystroke?.();
            }}
            onKeyDown={handleKeyDown}
            onInput={handleInput}
            placeholder={
              lotteryMode
                ? "Lottery mode enabled — configure outcomes above"
                : (encryptEnabled ? "Type an encrypted message..." : "Type a message...")
            }
            rows={1}
            disabled={disabled || sending || encrypting}
            className={cn(
              "flex-1 resize-none rounded-xl border border-input bg-transparent px-4 py-2 text-sm",
              "placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
              "disabled:cursor-not-allowed disabled:opacity-50",
              "max-h-[120px]",
            )}
          />
        )}

        <div className="relative">
          <Button
            variant="ghost"
            size="icon"
            className="h-9 w-9 shrink-0"
            onClick={() => setScheduleOpen((v) => !v)}
            disabled={disabled || sending || encrypting}
            aria-label="Schedule send"
          >
            <Clock className="h-4 w-4" />
          </Button>
          {scheduleOpen && (
            <div className="absolute bottom-full right-0 mb-2 min-w-[260px] rounded-lg border border-border bg-card p-3 shadow-lg">
              <p className="mb-2 text-xs font-medium">Schedule send</p>
              <input
                type="datetime-local"
                value={scheduledInput}
                className="mb-2 w-full rounded border border-input bg-background px-2 py-1 text-xs"
                onChange={(e) => {
                  const val = e.target.value;
                  setScheduledInput(val);
                  if (val) {
                    setScheduledAt(parseDateTimeInTz(val, scheduleTimezone));
                  } else {
                    setScheduledAt(null);
                  }
                }}
              />
              <div className="flex items-center gap-1.5">
                <Globe className="h-3 w-3 shrink-0 text-muted-foreground" />
                <select
                  value={scheduleTimezone}
                  onChange={(e) => {
                    const tz = e.target.value;
                    setScheduleTimezone(tz);
                    // Re-parse the existing input with the new timezone
                    if (scheduledInput) setScheduledAt(parseDateTimeInTz(scheduledInput, tz));
                  }}
                  className="flex-1 rounded border border-input bg-background px-1 py-0.5 text-xs"
                >
                  {[
                    "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles",
                    "America/Anchorage", "Pacific/Honolulu",
                    "Europe/London", "Europe/Paris", "Europe/Berlin", "Europe/Moscow",
                    "Asia/Dubai", "Asia/Kolkata", "Asia/Singapore", "Asia/Tokyo",
                    "Australia/Sydney", "Pacific/Auckland",
                    "UTC",
                  ].map((tz) => (
                    <option key={tz} value={tz}>{tz.replace("_", " ")}</option>
                  ))}
                </select>
              </div>
              {scheduledAt && (
                <p className="mt-1.5 text-[11px] text-muted-foreground">
                  Sends: {scheduledAt.toLocaleString(undefined, { timeZoneName: "short" })}
                </p>
              )}
              {scheduledAt && (
                <button
                  type="button"
                  className="mt-2 w-full rounded bg-primary px-2 py-1 text-xs font-medium text-primary-foreground"
                  onClick={() => setScheduleOpen(false)}
                >
                  Confirm
                </button>
              )}
            </div>
          )}
        </div>
        <Button
          size="icon"
          className="h-9 w-9 shrink-0 rounded-full"
          onClick={() => void handleSubmit()}
          disabled={
            disabled || sending || encrypting ||
            (pendingFileShare
              ? false
              : galleryMode
              ? (galleryFreeFiles.length === 0 && galleryLockedFiles.length === 0) ||
                (galleryLockedFiles.length > 0 && lockEnabled && (!lockPrice || parseFloat(lockPrice) < 0.01))
              : lotteryMode
              ? !lotteryOutcomesValid
              : (!text.trim() && !pendingFile)
            ) ||
            (tipEnabled && (!tipAmount || !tipPaymentMethodId))
          }
          aria-label="Send message"
        >
          {sending || encrypting ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Send className="h-4 w-4" />
          )}
        </Button>
      </div>

      <FilePickerDialog
        open={filePickerOpen}
        onClose={() => setFilePickerOpen(false)}
        onSelect={(entry, perm) => {
          setPendingFileShare({ entry, permission: perm });
          setFilePickerOpen(false);
        }}
      />
      <VideoPickerDialog
        open={videoPickerOpen}
        onClose={() => setVideoPickerOpen(false)}
        onSelect={(video) => {
          onSendVideoShare?.({ video_id: video.video_id, text: text.trim() || undefined });
          setText("");
          setVideoPickerOpen(false);
        }}
      />
      {onSendCalendarShare && (
        <CalendarPickerDialog
          open={calendarPickerOpen}
          onClose={() => setCalendarPickerOpen(false)}
          onSelect={(params) => {
            onSendCalendarShare(params);
          }}
        />
      )}
      {onSendCalendarEvent && (
        <EventPickerDialog
          open={eventPickerOpen}
          onClose={() => setEventPickerOpen(false)}
          onSelect={(params) => {
            onSendCalendarEvent(params);
          }}
        />
      )}
      {onSendMeetingPoll && (
        <MeetingPollComposer
          open={meetingPollOpen}
          onClose={() => setMeetingPollOpen(false)}
          onSend={(params) => {
            onSendMeetingPoll(params);
          }}
        />
      )}

      {onSendFindDateTime && (
        <FindDateTimeComposer
          open={findDateTimeOpen}
          onClose={() => setFindDateTimeOpen(false)}
          onSend={(params) => {
            onSendFindDateTime(params);
          }}
        />
      )}

      {onSendMarketCard && (
        <MarketCardComposerDialog
          open={marketCardOpen}
          onClose={() => setMarketCardOpen(false)}
          onSubmit={(payload) => {
            onSendMarketCard(payload);
            setMarketCardOpen(false);
          }}
        />
      )}
      {onSendPositionCard && (
        <PositionCardComposerDialog
          open={positionCardOpen}
          onClose={() => setPositionCardOpen(false)}
          ownerName={currentUserName}
          onSubmit={(payload) => {
            onSendPositionCard(payload);
            setPositionCardOpen(false);
          }}
        />
      )}
      {onSendCryptoTransfer && (
        <CryptoSendComposerDialog
          open={cryptoSendOpen}
          onClose={() => setCryptoSendOpen(false)}
          recipientName={recipientName}
          senderName={currentUserName}
          onSubmit={(payload) => {
            onSendCryptoTransfer(payload);
            setCryptoSendOpen(false);
          }}
        />
      )}
      {onSendCountdown && (
        <CountdownComposerDialog
          open={countdownOpen}
          onClose={() => setCountdownOpen(false)}
          onSubmit={(data) => {
            onSendCountdown(data);
            setCountdownOpen(false);
          }}
        />
      )}
      {onSendProductCard && (
        <ProductCardComposerDialog
          open={productCardOpen}
          onClose={() => setProductCardOpen(false)}
          onSubmit={(payload) => {
            onSendProductCard(payload);
            setProductCardOpen(false);
          }}
        />
      )}
      {onSendOrderCard && (
        <OrderShareComposerDialog
          open={orderCardOpen}
          onClose={() => setOrderCardOpen(false)}
          onSubmit={(payload) => {
            onSendOrderCard(payload);
            setOrderCardOpen(false);
          }}
        />
      )}
    </div>
  );
}
