interface ChatReplyQuoteProps {
  replyToPreview: { sender_display_name: string; text: string } | null;
}

export function ChatReplyQuote({ replyToPreview }: ChatReplyQuoteProps) {
  if (!replyToPreview) return null;

  return (
    <div
      className="flex items-center gap-1 px-1.5 py-0.5 mb-0.5 rounded bg-muted/60 border-l-2 border-primary/40 text-[10px] text-muted-foreground truncate"
      data-testid="chat-reply-quote"
    >
      <span className="font-semibold shrink-0">
        {replyToPreview.sender_display_name}:
      </span>
      <span className="truncate">{replyToPreview.text}</span>
    </div>
  );
}
