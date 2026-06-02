// MSG-007: Render message/comment text with inline custom emoji images.
//
// `:shortcode:` tokens that resolve (via the custom-emoji map) to an image URL
// are rendered as inline <img> elements; everything else stays as text.
import * as React from "react";
import { cn } from "@/lib/utils";
import { useCustomEmojiMap } from "@/hooks/useCustomEmojiMap";
import { splitCustomEmojiText, isEmojiOnly } from "@/utils/emoji";

export interface MessageTextProps {
  text: string;
  className?: string;
}

export function MessageText({ text, className }: MessageTextProps) {
  const customEmojiMap = useCustomEmojiMap(text);
  const parts = React.useMemo(
    () => splitCustomEmojiText(text, customEmojiMap),
    [text, customEmojiMap],
  );

  const hasCustom = parts.some((p) => p.type === "emoji");

  return (
    <p
      data-testid="message-text"
      className={cn(
        "whitespace-pre-wrap break-words text-sm",
        !hasCustom && isEmojiOnly(text) && "text-5xl leading-relaxed py-1",
        className,
      )}
    >
      {parts.map((part, idx) =>
        part.type === "emoji" ? (
          <img
            key={`ce-${idx}-${part.shortcode}`}
            src={part.url}
            alt={`:${part.shortcode}:`}
            title={`:${part.shortcode}:`}
            data-custom-emoji={part.shortcode}
            className="inline-block h-5 w-5 align-text-bottom"
          />
        ) : (
          <React.Fragment key={`t-${idx}`}>{part.value}</React.Fragment>
        ),
      )}
    </p>
  );
}

export default MessageText;
