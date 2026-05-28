import { useCallback, useEffect, useRef, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Send, Clock, Eye, MessageCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  getPrivateChatMessages,
  sendPrivateChatMessage,
  endPrivateChat,
  getPrivateChatStatus,
  type PrivateChatMessage,
  type PrivateChatStatus,
  type PrivateChatHistoryResponse,
} from "@/api/endpoints/broadcastPrivateChat";

interface PrivateChatPanelProps {
  sessionId: string;
  chatId: string;
  tier: 1 | 2;
  isBroadcaster: boolean;
  onEnded?: () => void;
}

function formatTime(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}:${s.toString().padStart(2, "0")}`;
}

export function PrivateChatPanel({
  sessionId,
  chatId,
  tier,
  isBroadcaster,
  onEnded,
}: PrivateChatPanelProps) {
  const queryClient = useQueryClient();
  const [inputText, setInputText] = useState("");
  const [countdown, setCountdown] = useState<number | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // ─── Queries ──────────────────────────────────────────────────

  const statusQuery = useQuery<PrivateChatStatus>({
    queryKey: ["private-chat-status", sessionId, chatId],
    queryFn: () => getPrivateChatStatus(sessionId, chatId),
    refetchInterval: 10_000,
  });

  const messagesQuery = useQuery<PrivateChatHistoryResponse>({
    queryKey: ["private-chat-messages", sessionId, chatId],
    queryFn: () => getPrivateChatMessages(sessionId, chatId, { limit: 100 }),
    refetchInterval: 3_000,
  });

  // ─── Mutations ────────────────────────────────────────────────

  const sendMut = useMutation({
    mutationFn: (text: string) =>
      sendPrivateChatMessage(sessionId, chatId, { text }),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["private-chat-messages", sessionId, chatId],
      });
      setInputText("");
    },
  });

  const endMut = useMutation({
    mutationFn: () => endPrivateChat(sessionId, chatId),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["private-chat-status", sessionId, chatId],
      });
      onEnded?.();
    },
  });

  // ─── Timer ────────────────────────────────────────────────────

  useEffect(() => {
    if (!statusQuery.data) return;
    const { remaining_seconds, status } = statusQuery.data;
    if (status === "ended") {
      setCountdown(0);
      return;
    }
    setCountdown(remaining_seconds);
    const timer = setInterval(() => {
      setCountdown((prev) => {
        if (prev === null || prev <= 0) {
          clearInterval(timer);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [statusQuery.data]);

  // ─── Auto-scroll ──────────────────────────────────────────────

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messagesQuery.data]);

  // ─── Handlers ─────────────────────────────────────────────────

  const handleSend = useCallback(() => {
    const text = inputText.trim();
    if (!text) return;
    sendMut.mutate(text);
  }, [inputText, sendMut]);

  const isEnded =
    statusQuery.data?.status === "ended" || countdown === 0;
  const canSend = (tier === 1 || isBroadcaster) && !isEnded;
  const messages: PrivateChatMessage[] = messagesQuery.data?.messages ?? [];
  const voyeurCount = statusQuery.data?.voyeur_count ?? 0;

  return (
    <Card className="flex h-full flex-col">
      <CardHeader className="flex-none border-b px-3 py-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <MessageCircle className="h-4 w-4" />
            <CardTitle className="text-sm font-medium">
              Private Chat
            </CardTitle>
            {tier === 2 && (
              <Badge variant="secondary" className="text-xs">
                <Eye className="mr-1 h-3 w-3" />
                Spectating
              </Badge>
            )}
          </div>
          <div className="flex items-center gap-2">
            {voyeurCount > 0 && (
              <span className="flex items-center gap-1 text-xs text-muted-foreground">
                <Eye className="h-3 w-3" />
                {voyeurCount}
              </span>
            )}
            {countdown !== null && (
              <Badge
                variant={countdown <= 60 ? "destructive" : "outline"}
                className="font-mono text-xs"
              >
                <Clock className="mr-1 h-3 w-3" />
                {formatTime(countdown)}
              </Badge>
            )}
            {canSend && (
              <Button
                size="sm"
                variant="ghost"
                onClick={() => endMut.mutate()}
                className="text-xs text-destructive"
              >
                End
              </Button>
            )}
          </div>
        </div>
      </CardHeader>

      <CardContent className="flex-1 overflow-y-auto p-3">
        <div className="space-y-2">
          {messages.map((msg: PrivateChatMessage) => (
            <div key={msg.message_id} className="text-sm">
              <span className="font-semibold">
                {msg.sender_display_name || msg.sender_id}
              </span>
              :{" "}
              <span className={msg.filtered ? "text-muted-foreground" : ""}>
                {msg.text}
              </span>
            </div>
          ))}
          <div ref={messagesEndRef} />
        </div>
        {isEnded && (
          <div className="mt-4 text-center text-sm text-muted-foreground">
            This private chat has ended.
          </div>
        )}
      </CardContent>

      {canSend && (
        <div className="flex-none border-t p-2">
          <form
            className="flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              handleSend();
            }}
          >
            <Input
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              placeholder="Type a message..."
              maxLength={500}
              className="flex-1 text-sm"
              disabled={sendMut.isPending}
            />
            <Button
              type="submit"
              size="sm"
              disabled={!inputText.trim() || sendMut.isPending}
            >
              <Send className="h-4 w-4" />
            </Button>
          </form>
        </div>
      )}
    </Card>
  );
}
