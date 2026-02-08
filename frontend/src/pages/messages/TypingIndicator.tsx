import { useEffect, useCallback, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import { getTyping, sendTyping } from "@/api/endpoints/messaging";
import { useAuthStore } from "@/stores/authStore";
import { cn } from "@/lib/utils";

const TYPING_POLL_MS = 3_000;
const TYPING_DEBOUNCE_MS = 2_000;

// ─── Typing Dots Animation ─────────────────────────────────────

function BouncingDots() {
  return (
    <span className="inline-flex items-center gap-0.5" aria-hidden="true">
      {[0, 1, 2].map((i) => (
        <span
          key={i}
          className="inline-block h-1.5 w-1.5 rounded-full bg-muted-foreground animate-bounce"
          style={{ animationDelay: `${i * 150}ms`, animationDuration: "0.8s" }}
        />
      ))}
    </span>
  );
}

// ─── TypingIndicator Component ─────────────────────────────────

interface TypingIndicatorProps {
  conversationId: string;
  className?: string;
}

export function TypingIndicator({ conversationId, className }: TypingIndicatorProps) {
  const userId = useAuthStore((s) => s.userId);

  const { data: typers } = useQuery({
    queryKey: ["typing", conversationId],
    queryFn: () => getTyping(conversationId),
    refetchInterval: TYPING_POLL_MS,
    staleTime: TYPING_POLL_MS,
    enabled: !!conversationId,
  });

  // Filter out self
  const others = (typers ?? []).filter((t) => t.user_id !== userId);

  if (others.length === 0) return null;

  const label =
    others.length === 1
      ? `${others[0]!.user_id} is typing`
      : `${others.length} people are typing`;

  return (
    <div
      className={cn(
        "flex items-center gap-1.5 px-4 py-1.5 text-xs text-muted-foreground",
        className,
      )}
    >
      <BouncingDots />
      <span>{label}</span>
    </div>
  );
}

// ─── useTypingSignal Hook ──────────────────────────────────────

/**
 * Returns a callback to invoke on each keystroke in the compose area.
 * Debounces the sendTyping API call so it fires at most once every 2s.
 */
export function useTypingSignal(conversationId: string) {
  const lastSentRef = useRef(0);

  const onKeystroke = useCallback(() => {
    const now = Date.now();
    if (now - lastSentRef.current < TYPING_DEBOUNCE_MS) return;
    lastSentRef.current = now;
    sendTyping(conversationId).catch(() => {});
  }, [conversationId]);

  // Reset when conversation changes
  useEffect(() => {
    lastSentRef.current = 0;
  }, [conversationId]);

  return onKeystroke;
}
