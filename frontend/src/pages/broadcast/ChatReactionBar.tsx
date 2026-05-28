import { useState } from "react";
import { reactToChatMessage } from "@/api/endpoints/broadcast-chat";

const ALLOWED_EMOJI = ["\u{1F44D}", "❤️", "\u{1F602}", "\u{1F525}", "\u{1F62E}", "\u{1F44F}"];

interface ChatReactionBarProps {
  sessionId: string;
  messageId: string;
  reactionsCounts?: Record<string, number> | null;
  myReactions?: string[] | null;
}

export function ChatReactionBar({
  sessionId,
  messageId,
  reactionsCounts,
  myReactions,
}: ChatReactionBarProps) {
  const [localCounts, setLocalCounts] = useState<Record<string, number>>(
    reactionsCounts || {},
  );
  const [localMine, setLocalMine] = useState<string[]>(myReactions || []);

  const handleToggle = async (emoji: string) => {
    const isActive = localMine.includes(emoji);
    const action = isActive ? "remove" : "add";

    // Optimistic update
    setLocalCounts((prev) => ({
      ...prev,
      [emoji]: (prev[emoji] || 0) + (isActive ? -1 : 1),
    }));
    setLocalMine((prev) =>
      isActive ? prev.filter((e) => e !== emoji) : [...prev, emoji],
    );

    try {
      const result = await reactToChatMessage(
        sessionId,
        messageId,
        emoji,
        action,
      );
      setLocalCounts(result.reactions_counts || {});
    } catch {
      // Revert on error
      setLocalCounts((prev) => ({
        ...prev,
        [emoji]: (prev[emoji] || 0) + (isActive ? 1 : -1),
      }));
      setLocalMine((prev) =>
        isActive ? [...prev, emoji] : prev.filter((e) => e !== emoji),
      );
    }
  };

  const hasAnyReactions = Object.values(localCounts).some((c) => c > 0);

  return (
    <div className="flex flex-wrap gap-0.5 mt-0.5" data-testid="chat-reaction-bar">
      {ALLOWED_EMOJI.map((emoji) => {
        const count = localCounts[emoji] || 0;
        const isActive = localMine.includes(emoji);
        if (count === 0 && !hasAnyReactions) return null;
        return (
          <button
            key={emoji}
            onClick={() => handleToggle(emoji)}
            className={`inline-flex items-center gap-0.5 px-1 py-0 rounded text-[10px] border transition-colors ${
              isActive
                ? "bg-primary/10 border-primary/30 text-primary"
                : "bg-muted/50 border-transparent text-muted-foreground hover:bg-muted"
            }`}
            data-testid={`reaction-${emoji}`}
            data-active={isActive}
          >
            <span>{emoji}</span>
            {count > 0 && <span>{count}</span>}
          </button>
        );
      })}
    </div>
  );
}
