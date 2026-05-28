import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Clock, Eye, DollarSign, MessageCircle, XCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  listPrivateChats,
  endPrivateChat,
  type PrivateChatSummary,
  type PrivateChatListResponse,
} from "@/api/endpoints/broadcastPrivateChat";

interface PrivateChatDashboardProps {
  sessionId: string;
  onSelectChat?: (chatId: string) => void;
}

function formatTime(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}:${s.toString().padStart(2, "0")}`;
}

function ChatRow({
  chat,
  sessionId,
  onSelect,
}: {
  chat: PrivateChatSummary;
  sessionId: string;
  onSelect?: () => void;
}) {
  const queryClient = useQueryClient();

  const endMut = useMutation({
    mutationFn: () => endPrivateChat(sessionId, chat.chat_id),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["private-chats", sessionId],
      });
    },
  });

  return (
    <div
      className="flex cursor-pointer items-center justify-between rounded border p-3 transition-colors hover:bg-muted/50"
      onClick={onSelect}
    >
      <div className="flex flex-col gap-1">
        <div className="flex items-center gap-2">
          <MessageCircle className="h-4 w-4" />
          <span className="text-sm font-medium">
            {chat.viewer_display_name || chat.viewer_id}
          </span>
          <Badge variant="outline" className="text-xs">
            ${(chat.rate_per_minute_cents / 100).toFixed(2)}/min
          </Badge>
        </div>
        <div className="flex items-center gap-3 text-xs text-muted-foreground">
          <span className="flex items-center gap-1">
            <Clock className="h-3 w-3" />
            {formatTime(chat.remaining_seconds)}
          </span>
          {chat.voyeur_count > 0 && (
            <span className="flex items-center gap-1">
              <Eye className="h-3 w-3" />
              {chat.voyeur_count} spectator
              {chat.voyeur_count !== 1 ? "s" : ""}
            </span>
          )}
          <span className="flex items-center gap-1">
            <DollarSign className="h-3 w-3" />$
            {(chat.total_revenue_cents / 100).toFixed(2)}
          </span>
        </div>
      </div>
      <Button
        size="sm"
        variant="destructive"
        onClick={(e: React.MouseEvent) => {
          e.stopPropagation();
          endMut.mutate();
        }}
        disabled={endMut.isPending}
      >
        <XCircle className="h-4 w-4" />
      </Button>
    </div>
  );
}

export function PrivateChatDashboard({
  sessionId,
  onSelectChat,
}: PrivateChatDashboardProps) {
  const chatsQuery = useQuery<PrivateChatListResponse>({
    queryKey: ["private-chats", sessionId],
    queryFn: () => listPrivateChats(sessionId),
    refetchInterval: 10_000,
  });

  const chats: PrivateChatSummary[] = chatsQuery.data?.chats ?? [];
  const totalRevenue = chats.reduce(
    (sum: number, c: PrivateChatSummary) => sum + c.total_revenue_cents,
    0,
  );

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between px-4 py-3">
        <CardTitle className="flex items-center gap-2 text-sm font-medium">
          <MessageCircle className="h-4 w-4" />
          Private Chats ({chats.length})
        </CardTitle>
        <Badge variant="secondary" className="font-mono">
          <DollarSign className="mr-1 h-3 w-3" />
          {(totalRevenue / 100).toFixed(2)}
        </Badge>
      </CardHeader>
      <CardContent className="space-y-2 px-4 pb-4">
        {chats.length === 0 ? (
          <p className="text-center text-sm text-muted-foreground">
            No active private chats.
          </p>
        ) : (
          chats.map((chat: PrivateChatSummary) => (
            <ChatRow
              key={chat.chat_id}
              chat={chat}
              sessionId={sessionId}
              onSelect={() => onSelectChat?.(chat.chat_id)}
            />
          ))
        )}
      </CardContent>
    </Card>
  );
}
