import * as React from "react";
import { Send, Paperclip, Loader2, Lock, Eye, EyeOff, EyeOff as EyeSlash, Headphones, X, ImageIcon, Clock, Reply, Globe, DollarSign, FileText } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import {
  isMessagingEncryptionEnabled,
  isMessagingListenOnceAudioEnabled,
  isMessagingViewOnceImageEnabled,
  isMessagingViewOnceVideoEnabled,
} from "@/lib/featureFlags";
import { encryptMessage, type MessageEncryptionEnvelope } from "@/lib/messageEncryption";
import type { Message, PaymentMethod, SendTextMessageReq } from "@/api/types";
import { getPaymentMethods } from "@/api/endpoints/billing";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

interface ComposeBarProps {
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
  }) => void;
  onSendVideoAttachment?: (file: File, options?: { consumption_policy?: "none" | "view_once" }) => void;
  onSendAudioRecording?: (file: File, options?: { consumption_policy?: "none" | "listen_once" }) => void;
  sending?: boolean;
  disabled?: boolean;
  onKeystroke?: () => void;
  replyingTo?: Message | null;
  onCancelReply?: () => void;
}

export function ComposeBar({
  onSendText,
  onSendImage,
  onSendVideoAttachment,
  onSendAudioRecording,
  sending,
  disabled,
  onKeystroke,
  replyingTo,
  onCancelReply,
}: ComposeBarProps) {
  const [text, setText] = React.useState("");
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
  const textareaRef = React.useRef<HTMLTextAreaElement>(null);
  const fileInputRef = React.useRef<HTMLInputElement>(null);

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

  const resetTextArea = () => {
    if (textareaRef.current) {
      textareaRef.current.style.height = "auto";
    }
  };

  const buildExtraPayload = (): Pick<SendTextMessageReq, "lock_price_cents" | "lock_description" | "send_at" | "view_once" | "expires_in_seconds" | "tip_amount_cents" | "tip_payment_method_id"> => {
    const extra: Pick<SendTextMessageReq, "lock_price_cents" | "lock_description" | "send_at" | "view_once" | "expires_in_seconds" | "tip_amount_cents" | "tip_payment_method_id"> = {};
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

  const handleSubmit = async () => {
    if (sending || encrypting) return;
    const trimmed = text.trim();
    if (!trimmed && !pendingFile) return;

    const resetTextState = () => {
      setText("");
      resetTextArea();
      if (encryptEnabled) { setPassword(""); setConfirmPassword(""); }
      if (lockEnabled) { setLockEnabled(false); setLockPrice(""); setLockDescription(""); }
      if (tipEnabled) { setTipEnabled(false); setTipAmount(""); setTipPaymentMethodId(null); }
      if (scheduledAt) { setScheduledAt(null); setScheduledInput(""); setScheduleOpen(false); }
      if (viewOnceText) setViewOnceText(false);
      if (expiresEnabled) { setExpiresEnabled(false); setExpiresDuration("3600"); }
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

  return (
    <div className="border-t border-border bg-card px-4 py-3">
      <div className="mb-2 flex items-center justify-between">
        <TooltipProvider delayDuration={0}>
          <Tooltip>
            <TooltipTrigger asChild>
              <label className={cn("inline-flex items-center gap-2 text-xs text-muted-foreground", !!pendingFile && "cursor-not-allowed opacity-50")}>
                <input
                  type="checkbox"
                  checked={encryptEnabled}
                  onChange={(e) => {
                    setEncryptEnabled(e.target.checked);
                    setEncryptError(null);
                  }}
                  disabled={disabled || sending || encrypting || !featureEnabled || !!pendingFile}
                  className={cn(!!pendingFile && "pointer-events-none")}
                />
                <Lock className="h-3.5 w-3.5" />
                Encrypt message
              </label>
            </TooltipTrigger>
            {!!pendingFile && (
              <TooltipContent>Encryption applies to text messages only</TooltipContent>
            )}
          </Tooltip>
        </TooltipProvider>
        {encryptEnabled && (
          <span className="rounded-full bg-amber-100 px-2 py-0.5 text-[10px] font-medium text-amber-700">
            Encrypted send enabled
          </span>
        )}
      </div>

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

      {/* View-once text + Lock + Tip + Expiry controls row */}
      <div className="mb-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
        {!pendingFile && (
          <label className="inline-flex items-center gap-1.5">
            <input
              type="checkbox"
              checked={viewOnceText}
              onChange={(e) => setViewOnceText(e.target.checked)}
              disabled={disabled || sending || encrypting}
            />
            <Eye className="h-3.5 w-3.5" />
            View once
          </label>
        )}
        <label className="inline-flex items-center gap-1.5">
          <input
            type="checkbox"
            checked={lockEnabled}
            onChange={(e) => {
              setLockEnabled(e.target.checked);
              if (e.target.checked) setTipEnabled(false);
            }}
            disabled={disabled || sending || encrypting}
          />
          <Lock className="h-3.5 w-3.5" />
          Require tip to unlock
        </label>
        <TooltipProvider delayDuration={0}>
          <Tooltip>
            <TooltipTrigger asChild>
              <label className={cn("inline-flex items-center gap-1.5", !hasPaymentMethods && "cursor-not-allowed opacity-50")}>
                <input
                  type="checkbox"
                  checked={tipEnabled}
                  onChange={(e) => {
                    if (!hasPaymentMethods) return;
                    setTipEnabled(e.target.checked);
                    if (e.target.checked) setLockEnabled(false);
                  }}
                  disabled={disabled || sending || encrypting || !hasPaymentMethods}
                  className={cn(!hasPaymentMethods && "pointer-events-none")}
                />
                <DollarSign className="h-3.5 w-3.5" />
                Attach tip
              </label>
            </TooltipTrigger>
            {!hasPaymentMethods && (
              <TooltipContent>Add a payment method in Billing to attach tips</TooltipContent>
            )}
          </Tooltip>
        </TooltipProvider>
        <label className="inline-flex items-center gap-1.5">
          <input
            type="checkbox"
            checked={expiresEnabled}
            onChange={(e) => setExpiresEnabled(e.target.checked)}
            disabled={disabled || sending || encrypting}
          />
          Message expires
        </label>
        {expiresEnabled && (
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
        )}
      </div>
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

      {/* Reply context */}
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
        {onSendImage && (
          <>
            <Button
              variant="ghost"
              size="icon"
              className="h-9 w-9 shrink-0"
              onClick={() => fileInputRef.current?.click()}
              disabled={disabled || sending || encrypting || !!pendingFile}
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

        <textarea
          ref={textareaRef}
          value={text}
          onChange={(e) => {
            setText(e.target.value);
            onKeystroke?.();
          }}
          onKeyDown={handleKeyDown}
          onInput={handleInput}
          placeholder={encryptEnabled ? "Type an encrypted message..." : "Type a message..."}
          rows={1}
          disabled={disabled || sending || encrypting}
          className={cn(
            "flex-1 resize-none rounded-xl border border-input bg-transparent px-4 py-2 text-sm",
            "placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
            "disabled:cursor-not-allowed disabled:opacity-50",
            "max-h-[120px]",
          )}
        />

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
          disabled={disabled || sending || encrypting || (!text.trim() && !pendingFile) || (tipEnabled && (!tipAmount || !tipPaymentMethodId))}
          aria-label="Send message"
        >
          {sending || encrypting ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Send className="h-4 w-4" />
          )}
        </Button>
      </div>
    </div>
  );
}
