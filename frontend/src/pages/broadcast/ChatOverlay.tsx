import { useEffect, useState } from "react";
import type { ChatMessage } from "@/api/endpoints/broadcast-chat";

// ─── Types ──────────────────────────────────────────────────────

interface OverlayMessage extends ChatMessage {
  animationId: string;
  enteredAt: number;
}

interface ChatOverlayProps {
  messages: ChatMessage[];
  enabled: boolean;
}

// ─── Component ──────────────────────────────────────────────────

export function ChatOverlay({ messages, enabled }: ChatOverlayProps) {
  const [overlayMessages, setOverlayMessages] = useState<OverlayMessage[]>([]);
  const [lastProcessed, setLastProcessed] = useState<string | null>(null);

  // Add new messages to overlay
  useEffect(() => {
    if (!enabled || messages.length === 0) return;
    const latest = messages[messages.length - 1];
    if (!latest || latest.message_id === lastProcessed || latest.deleted) return;

    setLastProcessed(latest.message_id);
    setOverlayMessages((prev) => [
      ...prev.slice(-20),
      {
        ...latest,
        animationId: `overlay-${latest.message_id}`,
        enteredAt: Date.now(),
      },
    ]);
  }, [messages, enabled, lastProcessed]);

  // Remove messages after animation duration (8 seconds)
  useEffect(() => {
    if (!enabled) return;
    const timer = setInterval(() => {
      setOverlayMessages((prev) =>
        prev.filter((m) => Date.now() - m.enteredAt < 8000),
      );
    }, 1000);
    return () => clearInterval(timer);
  }, [enabled]);

  if (!enabled) return null;

  return (
    <div
      className="absolute inset-0 pointer-events-none overflow-hidden"
      data-testid="chat-overlay"
    >
      {overlayMessages.map((msg, idx) => (
        <div
          key={msg.animationId}
          className="absolute text-white text-sm font-medium drop-shadow-lg animate-chat-scroll whitespace-nowrap"
          style={{
            top: `${(idx % 8) * 12 + 5}%`,
            animationDelay: `${(idx % 3) * 200}ms`,
          }}
          data-testid="overlay-message"
        >
          <span className="text-blue-300 mr-1">{msg.sender_display_name}:</span>
          {msg.text}
        </div>
      ))}
    </div>
  );
}
