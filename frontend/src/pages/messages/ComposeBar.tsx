import * as React from "react";
import { Send, Paperclip, Loader2, Lock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { isMessagingEncryptionEnabled } from "@/lib/featureFlags";
import { encryptMessage, type MessageEncryptionEnvelope } from "@/lib/messageEncryption";
import type { SendTextMessageReq } from "@/api/types";

interface ComposeBarProps {
  onSendText: (payload: SendTextMessageReq) => void;
  onSendImage?: (file: File) => void;
  sending?: boolean;
  disabled?: boolean;
  onKeystroke?: () => void;
}

export function ComposeBar({ onSendText, onSendImage, sending, disabled, onKeystroke }: ComposeBarProps) {
  const [text, setText] = React.useState("");
  const [encryptEnabled, setEncryptEnabled] = React.useState(false);
  const [password, setPassword] = React.useState("");
  const [confirmPassword, setConfirmPassword] = React.useState("");
  const [encrypting, setEncrypting] = React.useState(false);
  const [encryptError, setEncryptError] = React.useState<string | null>(null);
  const textareaRef = React.useRef<HTMLTextAreaElement>(null);
  const fileInputRef = React.useRef<HTMLInputElement>(null);

  const featureEnabled = isMessagingEncryptionEnabled();

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
    if (file && onSendImage) {
      onSendImage(file);
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
              accept="image/*"
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
