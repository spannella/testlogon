import * as React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Send, Lock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { useAuthStore } from "@/stores/authStore";
import {
  listDelegatedMessages,
  sendDelegatedMessage,
} from "@/api/endpoints/delegates";
import type { DelegatedMessage, DelegatedConversation } from "@/api/types";

interface DelegateConversationViewProps {
  conversation: DelegatedConversation;
  onBack?: () => void;
}

/**
 * Conversation view for delegates managing a creator's messages.
 * Shows messages with delegate attribution and allows sending
 * messages on behalf of the creator.
 */
export function DelegateConversationView({
  conversation,
  onBack,
}: DelegateConversationViewProps) {
  const queryClient = useQueryClient();
  const managingCreatorId = useAuthStore((s) => s.managingCreatorId);
  const userId = useAuthStore((s) => s.userId);
  const [text, setText] = React.useState("");

  const creatorId = managingCreatorId ?? "";

  const { data: messages = [], isLoading } = useQuery<DelegatedMessage[]>({
    queryKey: [
      "delegate",
      "messages",
      creatorId,
      conversation.conversation_id,
    ],
    queryFn: () =>
      listDelegatedMessages(creatorId, conversation.conversation_id),
    enabled: !!creatorId,
    refetchInterval: 5000,
  });

  const sendMut = useMutation({
    mutationFn: (msgText: string) =>
      sendDelegatedMessage(creatorId, conversation.conversation_id, {
        text: msgText,
      }),
    onSuccess: () => {
      setText("");
      queryClient.invalidateQueries({
        queryKey: [
          "delegate",
          "messages",
          creatorId,
          conversation.conversation_id,
        ],
      });
      queryClient.invalidateQueries({
        queryKey: ["delegate", "conversations", creatorId],
      });
    },
  });

  const handleSend = () => {
    const trimmed = text.trim();
    if (!trimmed) return;
    sendMut.mutate(trimmed);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  // Show messages oldest first (API returns newest first)
  const sortedMessages = [...messages].reverse();

  return (
    <div className="flex h-full flex-col" data-testid="delegate-conversation-view">
      {/* Header */}
      <div className="flex items-center gap-2 border-b border-border px-4 py-3">
        {onBack && (
          <Button variant="ghost" size="sm" onClick={onBack} className="md:hidden">
            Back
          </Button>
        )}
        <div className="flex-1">
          <p className="font-semibold">
            {conversation.title ||
              conversation.participants
                .filter((p) => p.user_id !== creatorId)
                .map((p) => p.user_id)
                .join(", ") ||
              "Conversation"}
          </p>
          <p className="text-xs text-muted-foreground">
            Delegate mode - messages sent as {creatorId}
          </p>
        </div>
      </div>

      {/* Messages */}
      <ScrollArea className="flex-1 p-4">
        {isLoading && (
          <p className="text-center text-sm text-muted-foreground">
            Loading messages...
          </p>
        )}
        {sortedMessages.map((msg) => (
          <DelegateMessageBubble
            key={msg.message_id}
            message={msg}
            creatorId={creatorId}
            currentDelegateId={userId ?? ""}
          />
        ))}
        {sortedMessages.length === 0 && !isLoading && (
          <p className="text-center text-sm text-muted-foreground">
            No messages yet
          </p>
        )}
      </ScrollArea>

      {/* Compose bar */}
      <div className="flex items-center gap-2 border-t border-border p-3">
        <Input
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Send message as creator..."
          className="flex-1"
          data-testid="delegate-compose-input"
        />
        <Button
          size="sm"
          onClick={handleSend}
          disabled={!text.trim() || sendMut.isPending}
          data-testid="delegate-send-button"
        >
          <Send className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}

/** Message bubble for delegate view with attribution badges */
function DelegateMessageBubble({
  message,
  creatorId,
  currentDelegateId,
}: {
  message: DelegatedMessage;
  creatorId: string;
  currentDelegateId: string;
}) {
  const isFromCreatorSide = message.sender_id === creatorId;

  if (message.delegate_cannot_decrypt) {
    return (
      <div className="mb-3 flex justify-start">
        <div className="max-w-[75%] rounded-lg bg-muted p-3">
          <div className="flex items-center gap-1 text-sm text-muted-foreground">
            <Lock className="h-3 w-3" />
            <span>Encrypted message - creator only</span>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            {new Date(message.created_at * 1000).toLocaleTimeString()}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div
      className={`mb-3 flex ${isFromCreatorSide ? "justify-end" : "justify-start"}`}
    >
      <div
        className={`max-w-[75%] rounded-lg p-3 ${
          isFromCreatorSide
            ? "bg-primary text-primary-foreground"
            : "bg-muted"
        }`}
      >
        {!isFromCreatorSide && (
          <p className="mb-1 text-xs font-medium opacity-70">
            {message.sender_id}
          </p>
        )}
        <p className="text-sm">{message.text}</p>
        <div className="mt-1 flex items-center gap-1">
          <span className="text-xs opacity-60">
            {new Date(message.created_at * 1000).toLocaleTimeString()}
          </span>
          {message.sent_by_delegate && (
            <Badge variant="outline" className="h-4 text-[10px]">
              {message.sent_by_delegate === currentDelegateId
                ? "Sent by you"
                : `via ${message.delegate_display_name || message.sent_by_delegate}`}
            </Badge>
          )}
          {message.delegate_tag && (
            <span className="text-xs opacity-50">{message.delegate_tag}</span>
          )}
        </div>
      </div>
    </div>
  );
}
