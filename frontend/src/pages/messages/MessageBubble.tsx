import { useState } from "react";
import { MoreHorizontal, Forward, Trash2 } from "lucide-react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
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

  const deleteMut = useMutation({
    mutationFn: () => deleteMessage(conversationId, message.message_id),
    onSuccess: () => {
      toast.success("Message deleted");
      void queryClient.invalidateQueries({ queryKey: ["messages", conversationId] });
      setDeleteConfirmOpen(false);
    },
    onError: () => toast.error("Failed to delete message"),
  });

  const time = new Date(message.created_at).toLocaleTimeString(undefined, {
    hour: "numeric",
    minute: "2-digit",
  });

  if (message.revoked) {
    return (
      <div className={cn("flex", isOwn ? "justify-end" : "justify-start")}>
        <div className="max-w-[75%] rounded-2xl px-4 py-2 text-sm italic text-muted-foreground bg-muted/50">
          Message deleted
        </div>
      </div>
    );
  }

  const isFileKind = message.kind === "file" || message.kind === "audio" || message.kind === "video";

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

          {/* Sender name (group chats only) */}
          {showSender && !isOwn && (
            <p className="mb-0.5 text-xs font-semibold text-primary">
              {message.sender_id}
            </p>
          )}

          {/* Text content */}
          {message.body && (
            <p className="whitespace-pre-wrap break-words text-sm">{message.body}</p>
          )}

          {/* Image content */}
          {message.kind === "image" && message.image_url && (
            <img
              src={message.image_url}
              alt="Shared image"
              className="mt-1 max-h-64 rounded-lg object-cover"
            />
          )}

          {/* File / audio / video attachment */}
          {isFileKind && message.file_name && (
            <FileMessageCard
              fileName={message.file_name}
              fileUrl={message.file_url}
              kind={message.kind}
              isOwn={isOwn}
            />
          )}

          {/* Reactions */}
          {message.reactions && Object.keys(message.reactions).length > 0 && (
            <div className="mt-1 flex flex-wrap gap-1">
              {Object.entries(message.reactions).map(([emoji, users]) => (
                <span
                  key={emoji}
                  className="inline-flex items-center rounded-full bg-background/80 px-1.5 py-0.5 text-xs"
                >
                  {emoji} {users.length > 1 && users.length}
                </span>
              ))}
            </div>
          )}

          {/* Timestamp + edited */}
          <div className={cn(
            "mt-1 flex items-center gap-1 text-[10px]",
            isOwn ? "text-primary-foreground/60 justify-end" : "text-muted-foreground",
          )}>
            {message.edited && <span>edited</span>}
            <span>{time}</span>
          </div>
        </div>
      </div>

      {/* Read receipts — only on own messages */}
      <ReadReceipts
        conversationId={conversationId}
        messageId={message.message_id}
        isOwn={isOwn}
      />

      {/* Auto-mark viewed for others' messages */}
      <ViewTracker
        conversationId={conversationId}
        messageId={message.message_id}
        isOwn={isOwn}
      />

      {/* Forward dialog */}
      <ForwardDialog
        open={forwardOpen}
        onOpenChange={setForwardOpen}
        message={message}
        sourceConversationId={conversationId}
      />

      {/* Delete confirm */}
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
    </>
  );
}
