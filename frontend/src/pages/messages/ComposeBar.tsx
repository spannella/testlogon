import * as React from "react";
import { Send, Paperclip, Loader2, Lock, Eye, Headphones } from "lucide-react";
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
  const [encrypting, setEncrypting] = React.useState(false);
  const [encryptError, setEncryptError] = React.useState<string | null>(null);
  const [viewOnceImage, setViewOnceImage] = React.useState(false);
  const [viewOnceVideo, setViewOnceVideo] = React.useState(false);
  const [listenOnceAudio, setListenOnceAudio] = React.useState(false);
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

  const handleSubmit = async () => {
    const trimmed = text.trim();
    if (!trimmed || sending || encrypting) return;

    const payload = await buildEncryptedPayload(trimmed);
    if (!payload) return;

    onSendText(payload);
    setText("");
    resetTextArea();
    if (encryptEnabled) {
      setPassword("");
      setConfirmPassword("");
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
    if (!file) {
      e.target.value = "";
      return;
    }

    if (file.type.startsWith("image/") && onSendImage) {
      onSendImage(file, { consumption_policy: viewOnceImage ? "view_once" : "none" });
    } else if (file.type.startsWith("video/") && onSendVideoAttachment) {
      onSendVideoAttachment(file, { consumption_policy: viewOnceVideo ? "view_once" : "none" });
    } else if (file.type.startsWith("audio/") && onSendAudioRecording) {
      onSendAudioRecording(file, { consumption_policy: listenOnceAudio ? "listen_once" : "none" });
    }

    e.target.value = "";
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
            <input
              type="password"
              placeholder="Encryption password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="rounded border border-input bg-background px-2 py-1 text-xs"
              autoComplete="new-password"
            />
            <input
              type="password"
              placeholder="Confirm password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="rounded border border-input bg-background px-2 py-1 text-xs"
              autoComplete="new-password"
            />
          </div>
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

      <div className="flex items-end gap-2">
        {onSendImage && (
          <>
            <Button
              variant="ghost"
              size="icon"
              className="h-9 w-9 shrink-0"
              onClick={() => fileInputRef.current?.click()}
              disabled={disabled || sending || encrypting}
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
          disabled={disabled || sending || encrypting || !text.trim()}
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
