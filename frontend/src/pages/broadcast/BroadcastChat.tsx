import { useEffect, useRef, useState, useCallback } from "react";
import { MessageCircle, Trash2, VolumeX, Send, Reply, Clock, Lock, Ticket, Package } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
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
import { ChatReactionBar } from "./ChatReactionBar";
import { ChatReplyQuote } from "./ChatReplyQuote";
import { ChatLockedCard } from "./ChatLockedCard";
import { BroadcastLotteryCard } from "@/components/broadcast/BroadcastLotteryCard";
import { BroadcastLotteryCreator } from "@/components/broadcast/BroadcastLotteryCreator";
import { LotteryResultOverlay } from "@/components/broadcast/LotteryResultOverlay";
import { ProductLinkCard } from "./ProductLinkCard";
import { ShelfProductPicker } from "./ShelfProductPicker";
import type { BroadcastLotteryResultEntry } from "@/api/types";

// ─── Types ──────────────────────────────────────────────────────

interface BroadcastChatProps {
  sessionId: string;
  isBroadcaster: boolean;
}

// ─── Component ──────────────────────────────────────────────────

export function BroadcastChat({ sessionId, isBroadcaster }: BroadcastChatProps) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputText, setInputText] = useState("");
  const [cooldown, setCooldown] = useState(false);
  const [connected, setConnected] = useState(false);
  // Phase B — Reply state
  const [replyTarget, setReplyTarget] = useState<ChatMessage | null>(null);
  // Phase C — Expiry toggle (broadcaster only)
  const [expirySeconds, setExpirySeconds] = useState<number | null>(null);
  // Phase D — Lock toggle (broadcaster only)
  const [lockCents, setLockCents] = useState<number | null>(null);
  const [lockDesc, setLockDesc] = useState("");
  // Lottery state (BCAST-014)
  const [showLotteryCreator, setShowLotteryCreator] = useState(false);
  const [lotteryResult, setLotteryResult] = useState<BroadcastLotteryResultEntry | null>(null);
  // Product share state (LCOM-002 / GAP-0290)
  const [showProductPicker, setShowProductPicker] = useState(false);
  const queryClient = useQueryClient();

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

      // Phase A — Reaction SSE event
      es.addEventListener("chat:reaction", (event) => {
        const data = JSON.parse(event.data);
        setMessages((prev) =>
          prev.map((m) =>
            m.message_id === data.message_id
              ? { ...m, reactions_counts: data.counts }
              : m,
          ),
        );
      });

      // Phase D — Unlock SSE event
      es.addEventListener("chat:unlock", (event) => {
        const data = JSON.parse(event.data);
        setMessages((prev) =>
          prev.map((m) =>
            m.message_id === data.message_id
              ? { ...m, text: data.text, is_unlocked: true }
              : m,
          ),
        );
      });

      // Lottery SSE events (BCAST-014)
      es.addEventListener("chat:lottery", (event) => {
        const msg: ChatMessage = JSON.parse(event.data);
        setMessages((prev) => {
          if (prev.some((m) => m.message_id === msg.message_id)) return prev;
          return [...prev, msg].slice(-500);
        });
      });

      // Product link SSE events (LCOM-002 / GAP-0289)
      es.addEventListener("chat:product_link", (event) => {
        const msg: ChatMessage = JSON.parse(event.data);
        setMessages((prev) => {
          if (prev.some((m) => m.message_id === msg.message_id)) return prev;
          return [...prev, msg].slice(-500);
        });
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

    const options: Record<string, unknown> = {};
    if (replyTarget) {
      options.reply_to_message_id = replyTarget.message_id;
    }
    if (isBroadcaster && expirySeconds) {
      options.expires_in_seconds = expirySeconds;
    }
    if (isBroadcaster && lockCents) {
      options.lock_price_cents = lockCents;
      if (lockDesc) options.lock_description = lockDesc;
    }

    try {
      await sendChatMessage(sessionId, text, options as {
        reply_to_message_id?: string;
        expires_in_seconds?: number;
        lock_price_cents?: number;
        lock_description?: string;
      });
    } catch {
      // Silently ignore — SSE will deliver the message if successful
    }

    // Clear toggles after send
    setReplyTarget(null);
    setExpirySeconds(null);
    setLockCents(null);
    setLockDesc("");
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

  // ─── Render message content ───────────────────────────────────

  const renderMessageContent = (msg: ChatMessage) => {
    if (msg.deleted) {
      return <span className="text-xs text-muted-foreground italic">[Message removed]</span>;
    }

    // Phase C — Expired
    if (msg.expired) {
      return (
        <span className="text-xs text-muted-foreground italic" data-testid="chat-expired">
          [This message has expired]
        </span>
      );
    }

    // Phase D — Locked
    if (msg.lock_price_cents && msg.is_unlocked === false) {
      return (
        <ChatLockedCard
          sessionId={sessionId}
          messageId={msg.message_id}
          lockPriceCents={msg.lock_price_cents}
          lockDescription={msg.lock_description}
          isUnlocked={false}
          text={msg.text}
          onUnlocked={(text) => {
            setMessages((prev) =>
              prev.map((m) =>
                m.message_id === msg.message_id
                  ? { ...m, text, is_unlocked: true }
                  : m,
              ),
            );
          }}
        />
      );
    }

    // LCOM-002 / GAP-0289 — Product link card
    if (msg.kind === "product_link" && msg.product_link) {
      return (
        <ProductLinkCard sessionId={sessionId} productLink={msg.product_link} />
      );
    }

    return (
      <span className="text-xs text-foreground break-words">
        {msg.text}
      </span>
    );
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
          msg.kind === "lottery" && msg.lottery_id ? (
            <BroadcastLotteryCard
              key={msg.message_id}
              sessionId={sessionId}
              lotteryId={msg.lottery_id}
              title={msg.text ?? "Lottery"}
              isBroadcaster={isBroadcaster}
            />
          ) : (
          <div
            key={msg.message_id}
            className="group px-1 py-0.5 rounded hover:bg-muted/50"
            data-testid="chat-message"
          >
            {/* Phase B — Reply quote */}
            {msg.reply_to_preview && (
              <ChatReplyQuote replyToPreview={msg.reply_to_preview} />
            )}

            <div className="flex items-start gap-1">
              <div className="flex-1 min-w-0">
                <span className="text-xs font-semibold text-primary mr-1">
                  {msg.sender_display_name}:
                </span>
                {renderMessageContent(msg)}

                {/* Phase C — Expiry indicator */}
                {msg.expires_at && !msg.expired && (
                  <ExpiryBadge expiresAt={msg.expires_at} />
                )}

                {/* Phase D — Tip total */}
                {msg.tip_total_cents != null && msg.tip_total_cents > 0 && (
                  <span className="ml-1 text-[10px] text-amber-500" data-testid="chat-tip-total">
                    ${(msg.tip_total_cents / 100).toFixed(2)} tips
                  </span>
                )}
              </div>

              {/* Action buttons */}
              <div className="hidden group-hover:flex items-center gap-0.5 shrink-0">
                {/* Reply button */}
                <button
                  onClick={() => setReplyTarget(msg)}
                  className="p-0.5 rounded hover:bg-muted"
                  title="Reply"
                  data-testid="chat-reply-btn"
                >
                  <Reply className="h-3 w-3 text-muted-foreground" />
                </button>

                {isBroadcaster && !msg.deleted && (
                  <>
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
                  </>
                )}
              </div>
            </div>

            {/* Phase A — Reactions */}
            <ChatReactionBar
              sessionId={sessionId}
              messageId={msg.message_id}
              reactionsCounts={msg.reactions_counts}
              myReactions={msg.my_reactions}
            />
          </div>
          )
        ))}
        <div ref={messagesEndRef} />
      </div>

      {/* Reply indicator */}
      {replyTarget && (
        <div className="flex items-center gap-1 px-2 py-1 bg-muted/50 border-t border-border" data-testid="chat-reply-indicator">
          <Reply className="h-3 w-3 text-primary shrink-0" />
          <span className="text-[10px] text-muted-foreground truncate flex-1">
            Replying to {replyTarget.sender_display_name}: {replyTarget.text?.slice(0, 50)}
          </span>
          <button
            onClick={() => setReplyTarget(null)}
            className="text-[10px] text-muted-foreground hover:text-foreground shrink-0"
            data-testid="chat-reply-cancel"
          >
            x
          </button>
        </div>
      )}

      {/* Lottery creator (BCAST-014) */}
      {showLotteryCreator && (
        <div className="border-t border-border p-2">
          <BroadcastLotteryCreator
            sessionId={sessionId}
            onCreated={() => setShowLotteryCreator(false)}
            onCancel={() => setShowLotteryCreator(false)}
          />
        </div>
      )}

      {/* Lottery result overlay (BCAST-014) */}
      {lotteryResult && (
        <LotteryResultOverlay
          result={lotteryResult}
          onDismiss={() => setLotteryResult(null)}
        />
      )}

      {/* Broadcaster toggles */}
      {isBroadcaster && (
        <div className="flex items-center gap-1 px-2 py-1 border-t border-border" data-testid="broadcaster-toggles">
          <button
            onClick={() => setExpirySeconds(expirySeconds ? null : 60)}
            className={`p-1 rounded text-[10px] ${expirySeconds ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-muted"}`}
            title="Toggle expiry"
            data-testid="toggle-expiry"
          >
            <Clock className="h-3 w-3" />
          </button>
          {expirySeconds && (
            <select
              value={expirySeconds}
              onChange={(e) => setExpirySeconds(Number(e.target.value))}
              className="text-[10px] bg-transparent border rounded px-1 h-5"
              data-testid="expiry-select"
            >
              <option value={30}>30s</option>
              <option value={60}>1m</option>
              <option value={300}>5m</option>
              <option value={900}>15m</option>
              <option value={3600}>1h</option>
              <option value={86400}>24h</option>
            </select>
          )}
          <button
            onClick={() => setLockCents(lockCents ? null : 500)}
            className={`p-1 rounded text-[10px] ${lockCents ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-muted"}`}
            title="Toggle lock"
            data-testid="toggle-lock"
          >
            <Lock className="h-3 w-3" />
          </button>
          {lockCents && (
            <input
              type="number"
              value={lockCents}
              onChange={(e) => setLockCents(Number(e.target.value) || null)}
              className="text-[10px] bg-transparent border rounded px-1 h-5 w-16"
              placeholder="cents"
              data-testid="lock-cents-input"
            />
          )}
          <button
            onClick={() => setShowLotteryCreator(!showLotteryCreator)}
            className={`p-1 rounded text-[10px] ${showLotteryCreator ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-muted"}`}
            title="Create lottery"
            data-testid="toggle-lottery"
          >
            <Ticket className="h-3 w-3" />
          </button>
          {/* Share product (LCOM-002 / GAP-0290) */}
          <button
            onClick={() => setShowProductPicker(true)}
            className="p-1 rounded text-[10px] text-muted-foreground hover:bg-muted"
            title="Share product"
            data-testid="toggle-product-share"
          >
            <Package className="h-3 w-3" />
          </button>
        </div>
      )}

      {/* Shelf product picker (LCOM-002 / GAP-0290) */}
      {isBroadcaster && (
        <ShelfProductPicker
          sessionId={sessionId}
          open={showProductPicker}
          onClose={() => setShowProductPicker(false)}
          onSent={() => {
            // The SSE chat:product_link event delivers the message to the
            // broadcaster's own stream, so no manual state update is needed.
          }}
        />
      )}

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

// ─── Expiry Badge Sub-component ─────────────────────────────────

function ExpiryBadge({ expiresAt }: { expiresAt: number }) {
  const [remaining, setRemaining] = useState(() => Math.max(0, expiresAt - Math.floor(Date.now() / 1000)));

  useEffect(() => {
    const interval = setInterval(() => {
      const r = Math.max(0, expiresAt - Math.floor(Date.now() / 1000));
      setRemaining(r);
    }, 1000);
    return () => clearInterval(interval);
  }, [expiresAt]);

  if (remaining <= 0) return null;

  const mins = Math.floor(remaining / 60);
  const secs = remaining % 60;

  return (
    <span className="ml-1 text-[10px] text-amber-500" data-testid="chat-expiry-badge">
      {mins}:{secs.toString().padStart(2, "0")}
    </span>
  );
}
