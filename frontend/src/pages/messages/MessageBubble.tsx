import { cn } from "@/lib/utils";
import type { Message } from "@/api/types";

interface MessageBubbleProps {
  message: Message;
  isOwn: boolean;
  showSender?: boolean;
}

export function MessageBubble({ message, isOwn, showSender }: MessageBubbleProps) {
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

  return (
    <div className={cn("flex", isOwn ? "justify-end" : "justify-start")}>
      <div
        className={cn(
          "group relative max-w-[75%] rounded-2xl px-4 py-2",
          isOwn
            ? "bg-primary text-primary-foreground"
            : "bg-muted text-foreground",
        )}
      >
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

        {/* File attachment */}
        {message.kind === "file" && message.file_name && (
          <a
            href={message.file_url ?? "#"}
            className={cn(
              "mt-1 inline-flex items-center gap-1 rounded-lg border px-3 py-1.5 text-xs font-medium",
              isOwn
                ? "border-primary-foreground/20 text-primary-foreground hover:bg-primary-foreground/10"
                : "border-border text-foreground hover:bg-accent",
            )}
            target="_blank"
            rel="noopener noreferrer"
          >
            {message.file_name}
          </a>
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
  );
}
