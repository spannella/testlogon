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
import { deleteMessage } from "@/api/endpoints/messaging";
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

export function MessageBubble({ message, isOwn, showSender, conversationId }: MessageBubbleProps) {
  const queryClient = useQueryClient();
  const [forwardOpen, setForwardOpen] = useState(false);
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  const [decryptOpen, setDecryptOpen] = useState(false);
  const [decrypting, setDecrypting] = useState(false);
  const [decryptPassword, setDecryptPassword] = useState("");
  const [decryptError, setDecryptError] = useState<string | null>(null);
  const [decryptedText, setDecryptedText] = useState<string | null>(null);

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

  const encryptedEnabled = isMessagingEncryptionEnabled();
  const encryptedSupported = encryptedEnabled && isMessageCryptoSupported();
  const hasDecryptableEnvelope = Boolean(message.encryption);
  const showUnsupportedEncryptedState = message.is_encrypted && (!encryptedSupported || !hasDecryptableEnvelope);

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
          {/* Actions menu */}
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
                <DropdownMenuItem onClick={() => setForwardOpen(true)}>
                  <Forward className="mr-2 h-4 w-4" /> Forward
                </DropdownMenuItem>
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

          {/* Text / encrypted placeholder */}
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
            <img
              src={message.image.url}
              alt="Shared image"
              className="mt-1 max-h-64 rounded-lg object-cover"
            />
          )}

          {isFileKind && typeof message.file?.name === "string" && (
            <FileMessageCard
              fileName={message.file.name}
              fileUrl={typeof message.file?.url === "string" ? message.file.url : undefined}
              kind={message.kind}
              isOwn={isOwn}
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

      <ReadReceipts
        conversationId={conversationId}
        messageId={message.message_id}
        isOwn={isOwn}
      />

      <ViewTracker
        conversationId={conversationId}
        messageId={message.message_id}
        isOwn={isOwn}
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
            <Button
              variant="outline"
              onClick={() => setDecryptOpen(false)}
              disabled={decrypting}
            >
              Cancel
            </Button>
            <Button
              onClick={() => void handleDecrypt()}
              disabled={decrypting || !decryptPassword}
            >
              {decrypting ? <Loader2 className="h-4 w-4 animate-spin" /> : "Decrypt"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
