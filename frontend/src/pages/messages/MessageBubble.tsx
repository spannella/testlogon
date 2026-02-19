import { useState } from "react";
import { MoreHorizontal, Forward, Trash2, Lock, Loader2 } from "lucide-react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { isMessagingEncryptionEnabled } from "@/lib/featureFlags";
import {
  decryptMessage,
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
} from "@/api/endpoints/messaging";
import { ApiError } from "@/api/client";
import type { Message } from "@/api/types";
import { FileMessageCard } from "./FileMessageCard";
import { ReadReceipts, ViewTracker } from "./ReadReceipts";
import { ForwardDialog } from "./ForwardDialog";

interface MessageBubbleProps {
  message: Message;
  isOwn: boolean;
  showSender?: boolean;
  conversationId: string;
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

const openBlobInEphemeralWindow = (blob: Blob) => {
  const objectUrl = URL.createObjectURL(blob);
  const opened = window.open(objectUrl, "_blank", "noopener,noreferrer");

  // Revoke quickly to reduce in-memory persistence; delay allows the new tab to read it.
  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 60_000);
  if (!opened) {
    URL.revokeObjectURL(objectUrl);
  }
};

export function MessageBubble({ message, isOwn, showSender, conversationId }: MessageBubbleProps) {
  const queryClient = useQueryClient();
  const [forwardOpen, setForwardOpen] = useState(false);
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  const [decryptOpen, setDecryptOpen] = useState(false);
  const [decrypting, setDecrypting] = useState(false);
  const [decryptPassword, setDecryptPassword] = useState("");
  const [decryptError, setDecryptError] = useState<string | null>(null);
  const [decryptedText, setDecryptedText] = useState<string | null>(null);
  const [openingOnce, setOpeningOnce] = useState(false);
  const [onceError, setOnceError] = useState<string | null>(null);

  const deleteMut = useMutation({
    mutationFn: () => deleteMessage(conversationId, message.message_id),
    onSuccess: () => {
      toast.success("Message deleted");
      void queryClient.invalidateQueries({ queryKey: ["messages", conversationId] });
      setDeleteConfirmOpen(false);
    },
    onError: () => toast.error("Failed to delete message"),
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
      const decrypted = await decryptMessage(message.encryption as MessageEncryptionEnvelope, decryptPassword);
      setDecryptedText(decrypted);
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
      const grant = await createOnceMediaAttachmentGrant(conversationId, message.message_id);
      const trigger = consumeTrigger(message);
      await consumeOnceMediaAttachment(conversationId, message.message_id, grant.grant_token, {
        consumption_attempt_id: `attempt-${message.message_id}-${Date.now()}`,
        trigger,
        playback_seconds: playbackThresholdSeconds(message),
      });
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
            "absolute -top-2 opacity-0 transition-opacity group-hover:opacity-100",
            isOwn ? "left-0 -translate-x-full pr-1" : "right-0 translate-x-full pl-1",
          )}>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon" className="h-7 w-7 rounded-full bg-background shadow-sm">
                  <MoreHorizontal className="h-3.5 w-3.5" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align={isOwn ? "start" : "end"}>
                {canForward && (
                  <DropdownMenuItem onClick={() => setForwardOpen(true)}>
                    <Forward className="mr-2 h-4 w-4" /> Forward
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

          {showSender && !isOwn && (
            <p className="mb-0.5 text-xs font-semibold text-primary">
              {message.sender_id}
            </p>
          )}

          {onceMediaLabel && (
            <div className="mb-1 text-[10px] uppercase tracking-wide">
              <span className="rounded-full bg-background/70 px-2 py-0.5 font-semibold">{onceMediaLabel}</span>
              {message.consumption_state && (
                <span className="ml-2 text-muted-foreground">{message.consumption_state}</span>
              )}
            </div>
          )}

          {message.is_encrypted ? (
            <div className="space-y-1">
              <span className="inline-flex items-center gap-1 rounded-full bg-background/60 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide">
                <Lock className="h-3 w-3" /> Encrypted
              </span>
              {decryptedText ? (
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
          ) : message.text ? (
            <p className="whitespace-pre-wrap break-words text-sm">{message.text}</p>
          ) : null}

          {message.kind === "image" && typeof message.image?.url === "string" && (
            <button
              type="button"
              disabled={message.consumption_state === "consumed" || openingOnce}
              onClick={() => {
                if (message.consumption_policy) {
                  void handleOpenOnceAttachment();
                } else {
                  window.open(message.image?.url, "_blank", "noopener,noreferrer");
                }
              }}
              className={cn("mt-1 block", message.consumption_state === "consumed" && "opacity-60 cursor-not-allowed")}
            >
              <img
                src={message.image.url}
                alt="Shared image"
                className="max-h-64 rounded-lg object-cover"
              />
            </button>
          )}

          {isFileKind && typeof message.file?.name === "string" && (
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
                if (message.file?.url) {
                  window.open(message.file.url, "_blank", "noopener,noreferrer");
                }
              }}
            />
          )}

          {message.reactions_counts && Object.keys(message.reactions_counts).length > 0 && (
            <div className="mt-1 flex flex-wrap gap-1">
              {Object.entries(message.reactions_counts).map(([emoji, count]) => (
                <span
                  key={emoji}
                  className="inline-flex items-center rounded-full bg-background/80 px-1.5 py-0.5 text-xs"
                >
                  {emoji} {count > 1 && count}
                </span>
              ))}
            </div>
          )}

          <div className={cn(
            "mt-1 flex items-center gap-1 text-[10px]",
            isOwn ? "text-primary-foreground/60 justify-end" : "text-muted-foreground",
          )}>
            {(message.edited_at || message.edited) && <span>edited</span>}
            <span>{time}</span>
          </div>
        </div>
      </div>

      <ReadReceipts conversationId={conversationId} messageId={message.message_id} isOwn={isOwn} />

      <ViewTracker conversationId={conversationId} messageId={message.message_id} isOwn={isOwn} />

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
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Decrypt message</DialogTitle>
            <DialogDescription>
              Enter the shared password to decrypt this message locally on your device.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-2">
            <input
              type="password"
              value={decryptPassword}
              onChange={(e) => setDecryptPassword(e.target.value)}
              placeholder="Password"
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
              autoComplete="off"
            />
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
    </>
  );
}
