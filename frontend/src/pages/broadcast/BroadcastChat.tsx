import { useEffect, useRef, useState, useCallback } from "react";
import { MessageCircle, Trash2, VolumeX, Send } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  sendChatMessage,
  getChatHistory,
  deleteChatMessage,
  muteChatUser,
  type ChatMessage,
} from "@/api/endpoints/broadcast-chat";

// ─── Types ──────────────────────────────────────────────────────

interface BroadcastChatProps {
  sessionId: string;
  isBroadcaster: boolean;
}

// ─── Component ───────────────────────────────────────────────���──

export function BroadcastChat({ sessionId, isBroadcaster }: BroadcastChatProps) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputText, setInputText] = useState("");
  const [cooldown, setCooldown] = useState(false);
  const [connected, setConnected] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const userScrolledRef = useRef(false);

  // ─── Load initial history ──────────────────────────────────────

  useEffect(() => {
    if (!sessionId) return;
    getChatHistory(sessionId, { limit: 100 })
      .then((data) => setMessages(data.messages))
      .catch(() => {});
  }, [sessionId]);

  // ─── SSE connection for real-time updates ──────────────────────

  useEffect(() => {
    if (!sessionId) return;

    let es: EventSource | null = null;
    let retryCount = 0;
    let destroyed = false;

    function connect() {
      if (destroyed) return;
      const url = `/broadcast/sessions/${sessionId}/chat/stream?poll_ms=500`;
      es = new EventSource(url, { withCredentials: true });

      es.onopen = () => {
        setConnected(true);
        retryCount = 0;
      };

      es.addEventListener("chat:message", (event) => {
        const msg: ChatMessage = JSON.parse(event.data);
        setMessages((prev) => [...prev, msg].slice(-500));
      });

      es.addEventListener("chat:delete", (event) => {
        const { message_id } = JSON.parse(event.data);
        setMessages((prev) => prev.filter((m) => m.message_id !== message_id));
      });

      es.onerror = () => {
        es?.close();
        setConnected(false);
        if (destroyed) return;
        const delay = Math.min(1000 * 2 ** retryCount, 15000);
        retryCount++;
        setTimeout(connect, delay);
      };

      eventSourceRef.current = es;
    }

    connect();

    return () => {
      destroyed = true;
      es?.close();
      eventSourceRef.current = null;
    };
  }, [sessionId]);

  // ─── Auto-scroll to bottom ────────────────────────────────────

  useEffect(() => {
    if (!userScrolledRef.current) {
      messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages]);

  const handleScroll = useCallback(() => {
    const container = containerRef.current;
    if (!container) return;
    const isAtBottom =
      container.scrollHeight - container.scrollTop - container.clientHeight < 50;
    userScrolledRef.current = !isAtBottom;
  }, []);

  // ─── Send message ─────────────────────────────────────────────

  const handleSend = async () => {
    if (!inputText.trim() || cooldown) return;
    const text = inputText.trim();
    setInputText("");
    setCooldown(true);
    setTimeout(() => setCooldown(false), 2000);

    try {
      await sendChatMessage(sessionId, text);
    } catch {
      // Silently ignore — SSE will deliver the message if successful
    }
  };

  // ─── Moderation actions ───────────────────────────────────────

  const handleDelete = async (messageId: string) => {
    try {
      await deleteChatMessage(sessionId, messageId);
      setMessages((prev) => prev.filter((m) => m.message_id !== messageId));
    } catch {
      // Ignore
    }
  };

  const handleMute = async (userId: string) => {
    try {
      await muteChatUser(sessionId, userId, 300);
    } catch {
      // Ignore
    }
  };

  // ─── Render ───────────────────────────────────────────────────

  return (
    <div className="flex flex-col h-full border-l border-border bg-card" data-testid="broadcast-chat">
      {/* Header */}
      <div className="flex items-center gap-2 px-3 py-2 border-b border-border">
        <MessageCircle className="h-4 w-4 text-muted-foreground" />
        <span className="text-sm font-medium">Live Chat</span>
        {connected && (
          <Badge variant="secondary" className="text-xs ml-auto">
            Live
          </Badge>
        )}
      </div>

      {/* Messages list */}
      <div
        ref={containerRef}
        className="flex-1 overflow-y-auto p-2 space-y-1"
        onScroll={handleScroll}
        data-testid="chat-messages"
      >
        {messages.map((msg) => (
          <div
            key={msg.message_id}
            className="group flex items-start gap-1 px-1 py-0.5 rounded hover:bg-muted/50"
            data-testid="chat-message"
          >
            <div className="flex-1 min-w-0">
              <span className="text-xs font-semibold text-primary mr-1">
                {msg.sender_display_name}:
              </span>
              <span className="text-xs text-foreground break-words">
                {msg.deleted ? "[Message removed]" : msg.text}
              </span>
            </div>
            {isBroadcaster && !msg.deleted && (
              <div className="hidden group-hover:flex items-center gap-0.5 shrink-0">
                <button
                  onClick={() => handleDelete(msg.message_id)}
                  className="p-0.5 rounded hover:bg-destructive/20"
                  title="Delete message"
                  data-testid="chat-delete-btn"
                >
                  <Trash2 className="h-3 w-3 text-destructive" />
                </button>
                <button
                  onClick={() => handleMute(msg.sender_id)}
                  className="p-0.5 rounded hover:bg-warning/20"
                  title="Mute user (5 min)"
                  data-testid="chat-mute-btn"
                >
                  <VolumeX className="h-3 w-3 text-warning" />
                </button>
              </div>
            )}
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div className="border-t border-border p-2 flex gap-2">
        <Input
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && !e.shiftKey && handleSend()}
          placeholder="Send a message..."
          maxLength={280}
          disabled={cooldown}
          className="text-xs h-8"
          data-testid="chat-input"
        />
        <Button
          onClick={handleSend}
          disabled={cooldown || !inputText.trim()}
          size="sm"
          className="h-8 px-2"
          data-testid="chat-send-btn"
        >
          <Send className="h-3.5 w-3.5" />
        </Button>
      </div>

      {/* Character count */}
      {inputText.length > 0 && (
        <div className="px-2 pb-1 text-right">
          <span
            className={`text-[10px] ${inputText.length > 260 ? "text-destructive" : "text-muted-foreground"}`}
            data-testid="chat-char-count"
          >
            {280 - inputText.length}
          </span>
        </div>
      )}
    </div>
  );
}
