import * as React from "react";
import { Send, Paperclip, Loader2, Lock, Eye, EyeOff, Headphones, X, ImageIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import {
  isMessagingEncryptionEnabled,
  isMessagingListenOnceAudioEnabled,
  isMessagingViewOnceImageEnabled,
  isMessagingViewOnceVideoEnabled,
} from "@/lib/featureFlags";
import { encryptMessage, type MessageEncryptionEnvelope } from "@/lib/messageEncryption";
import type { SendTextMessageReq } from "@/api/types";

interface ComposeBarProps {
  onSendText: (payload: SendTextMessageReq) => void;
  onSendImage?: (file: File, options?: { consumption_policy?: "none" | "view_once" }) => void;
  onSendVideoAttachment?: (file: File, options?: { consumption_policy?: "none" | "view_once" }) => void;
  onSendAudioRecording?: (file: File, options?: { consumption_policy?: "none" | "listen_once" }) => void;
  sending?: boolean;
  disabled?: boolean;
  onKeystroke?: () => void;
}

export function ComposeBar({
  onSendText,
  onSendImage,
  onSendVideoAttachment,
  onSendAudioRecording,
  sending,
  disabled,
  onKeystroke,
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
  const textareaRef = React.useRef<HTMLTextAreaElement>(null);
  const fileInputRef = React.useRef<HTMLInputElement>(null);

  const featureEnabled = isMessagingEncryptionEnabled();
  const onceImageEnabled = isMessagingViewOnceImageEnabled();
  const onceVideoEnabled = isMessagingViewOnceVideoEnabled();
  const onceAudioEnabled = isMessagingListenOnceAudioEnabled();

  const resetTextArea = () => {
    if (textareaRef.current) {
      textareaRef.current.style.height = "auto";
    }
  };

  const buildEncryptedPayload = async (trimmed: string): Promise<SendTextMessageReq | null> => {
    if (!encryptEnabled) {
      return { text: trimmed };
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
      return { encryption: envelope };
    } catch {
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

    // Send pending image/video/audio first
    if (pendingFile) {
      const { file, kind } = pendingFile;
      if (kind === "image" && onSendImage) {
        onSendImage(file, { consumption_policy: viewOnceImage ? "view_once" : "none" });
      } else if (kind === "video" && onSendVideoAttachment) {
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
      setText("");
      resetTextArea();
      if (encryptEnabled) {
        setPassword("");
        setConfirmPassword("");
      }
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
    if (file.type.startsWith("image/") && onSendImage) kind = "image";
    else if (file.type.startsWith("video/") && onSendVideoAttachment) kind = "video";
    else if (file.type.startsWith("audio/") && onSendAudioRecording) kind = "audio";

    if (!kind) return;

    const previewUrl = URL.createObjectURL(file);
    setPendingFile({ file, previewUrl, kind });
  };

  return (
    <div className="border-t border-border bg-card px-4 py-3">
      <div className="mb-2 flex items-center justify-between">
        <label className="inline-flex items-center gap-2 text-xs text-muted-foreground">
          <input
            type="checkbox"
            checked={encryptEnabled}
            onChange={(e) => {
              setEncryptEnabled(e.target.checked);
              setEncryptError(null);
            }}
            disabled={disabled || sending || encrypting || !featureEnabled}
          />
          <Lock className="h-3.5 w-3.5" />
          Encrypt message
        </label>
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
          {encryptError && <p className="mt-2 text-[11px] text-red-700">{encryptError}</p>}
        </div>
      )}

      {(onceImageEnabled || onceVideoEnabled || onceAudioEnabled) && (
        <div className="mb-2 flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
          {onceImageEnabled && onSendImage && (
            <label className="inline-flex items-center gap-2">
              <input
                type="checkbox"
                checked={viewOnceImage}
                onChange={(e) => setViewOnceImage(e.target.checked)}
                disabled={disabled || sending || encrypting}
              />
              <Eye className="h-3.5 w-3.5" />
              View once (image)
            </label>
          )}
          {onceVideoEnabled && onSendVideoAttachment && (
            <label className="inline-flex items-center gap-2">
              <input
                type="checkbox"
                checked={viewOnceVideo}
                onChange={(e) => setViewOnceVideo(e.target.checked)}
                disabled={disabled || sending || encrypting}
              />
              <Eye className="h-3.5 w-3.5" />
              View once (video)
            </label>
          )}
          {onceAudioEnabled && onSendAudioRecording && (
            <label className="inline-flex items-center gap-2">
              <input
                type="checkbox"
                checked={listenOnceAudio}
                onChange={(e) => setListenOnceAudio(e.target.checked)}
                disabled={disabled || sending || encrypting}
              />
              <Headphones className="h-3.5 w-3.5" />
              Listen once (audio)
            </label>
          )}
        </div>
      )}

      {/* Pending file preview */}
      {pendingFile && (
        <div className="mb-2 flex items-center gap-2 rounded-lg border border-border bg-muted/40 p-2">
          {pendingFile.kind === "image" ? (
            <img
              src={pendingFile.previewUrl}
              alt="Attachment preview"
              className="h-16 w-16 rounded-md object-cover shrink-0"
            />
          ) : (
            <div className="flex h-16 w-16 shrink-0 items-center justify-center rounded-md bg-muted">
              <ImageIcon className="h-6 w-6 text-muted-foreground" />
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
              accept="image/*,video/*,audio/*"
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

        <Button
          size="icon"
          className="h-9 w-9 shrink-0 rounded-full"
          onClick={() => void handleSubmit()}
          disabled={disabled || sending || encrypting || (!text.trim() && !pendingFile)}
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
