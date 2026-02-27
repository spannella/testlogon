import * as React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Headphones, MessageSquare } from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/shared/EmptyState";
import { ConversationView } from "@/pages/messages/ConversationView";
import { useMessagingStream } from "@/hooks/useMessagingStream";
import { useHeartbeat } from "@/hooks/usePresence";
import {
  getConversations,
  startHelpdeskConversation,
  getHelpdeskQueue,
} from "@/api/endpoints/messaging";
import type { Conversation } from "@/api/types";
import { useAuthStore } from "@/stores/authStore";

const HELPDESK_GROUP_ID = import.meta.env.VITE_HELPDESK_GROUP_ID ?? "e2e-helpdesk";

function routingStateBadge(state: string) {
  if (state === "awaiting_agent") {
    return <Badge className="bg-amber-100 text-amber-800 border-amber-200 shrink-0">Waiting</Badge>;
  }
  if (state === "assigned") {
    return <Badge className="bg-green-100 text-green-800 border-green-200 shrink-0">Assigned</Badge>;
  }
  if (state === "paused_no_agents_online") {
    return <Badge className="bg-red-100 text-red-800 border-red-200 shrink-0">Paused</Badge>;
  }
  return null;
}

function ConvoRow({
  convo,
  active,
  onClick,
  showBadge,
}: {
  convo: Conversation;
  active: boolean;
  onClick: () => void;
  showBadge: boolean;
}) {
  const userId = useAuthStore((s) => s.userId);
  const participantNames = convo.participants
    .filter((p) => p.user_id !== userId)
    .map((p) => p.display_name ?? p.user_id)
    .join(", ");
  const title = convo.title ?? (participantNames || "Conversation");

  return (
    <button
      className={cn(
        "flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-sm transition-colors",
        active ? "bg-primary/10 text-primary" : "hover:bg-accent",
      )}
      onClick={onClick}
    >
      <Avatar className="h-8 w-8 shrink-0">
        <AvatarFallback className="text-xs">{title.slice(0, 2).toUpperCase()}</AvatarFallback>
      </Avatar>
      <span className="min-w-0 flex-1 truncate font-medium">{title}</span>
      {showBadge && convo.routing_state && routingStateBadge(convo.routing_state)}
      {!showBadge && (convo.unread_count ?? 0) > 0 && (
        <Badge className="ml-auto shrink-0 text-[10px]">{convo.unread_count}</Badge>
      )}
    </button>
  );
}

export default function HelpdeskPage() {
  const queryClient = useQueryClient();
  const userId = useAuthStore((s) => s.userId);
  const [activeConvo, setActiveConvo] = React.useState<Conversation | null>(null);
  const [mobileShowConvo, setMobileShowConvo] = React.useState(false);

  useMessagingStream(true);
  useHeartbeat(true);

  // Agent queue — 403 if not an agent (non-members get no queue)
  const { data: queueData, isError: queueError } = useQuery({
    queryKey: ["helpdesk-queue", HELPDESK_GROUP_ID],
    queryFn: () => getHelpdeskQueue(HELPDESK_GROUP_ID),
    retry: false,
    refetchOnWindowFocus: true,
    staleTime: 10_000,
  });

  // User's own helpdesk conversations (support chats they started)
  const { data: convoData } = useQuery({
    queryKey: ["conversations"],
    queryFn: () => getConversations(),
    refetchOnWindowFocus: true,
    staleTime: 0,
  });

  const myHelpdeskConvos = React.useMemo(() => {
    const all = convoData?.conversations ?? [];
    return all.filter((c) => c.routing_mode === "helpdesk_bridge");
  }, [convoData]);

  const startSupportChat = useMutation({
    mutationFn: () => startHelpdeskConversation(HELPDESK_GROUP_ID),
    onSuccess: (convo) => {
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
      setActiveConvo(convo);
      setMobileShowConvo(true);
    },
    onError: () => toast.error("Failed to start support chat"),
  });

  const handleSelect = (convo: Conversation) => {
    setActiveConvo(convo);
    setMobileShowConvo(true);
  };

  // Keep activeConvo in sync with latest data from cache
  React.useEffect(() => {
    if (!activeConvo) return;
    const all = [
      ...(queueData ?? []),
      ...myHelpdeskConvos,
    ];
    const fresh = all.find((c) => c.conversation_id === activeConvo.conversation_id);
    if (fresh) setActiveConvo(fresh);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [queueData, myHelpdeskConvos]);

  const queueConvos = queueData ?? [];
  const isAgent = !queueError;

  return (
    <div className="flex h-full">
      {/* Left panel */}
      <div
        className={cn(
          "w-full flex-shrink-0 border-r border-border md:w-72 lg:w-80",
          mobileShowConvo ? "hidden md:flex" : "flex",
          "flex-col",
        )}
      >
        {/* Header */}
        <div className="flex items-center gap-2 border-b border-border px-4 py-3">
          <Headphones className="h-5 w-5 text-muted-foreground" />
          <h1 className="text-base font-semibold">Helpdesk</h1>
        </div>

        <div className="flex-1 overflow-y-auto px-2 py-3 space-y-4">
          {/* Contact Support button */}
          <div className="px-1">
            <Button
              className="w-full"
              onClick={() => startSupportChat.mutate()}
              disabled={startSupportChat.isPending}
              aria-label="Contact Support"
            >
              <MessageSquare className="mr-2 h-4 w-4" />
              {startSupportChat.isPending ? "Starting…" : "Contact Support"}
            </Button>
          </div>

          {/* Agent queue section */}
          {isAgent && (
            <div>
              <p className="mb-1 px-3 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                Agent Queue
              </p>
              {queueConvos.length === 0 ? (
                <p className="px-3 py-2 text-xs text-muted-foreground">No conversations in queue</p>
              ) : (
                <ul className="space-y-0.5">
                  {queueConvos.map((convo) => (
                    <li key={convo.conversation_id}>
                      <ConvoRow
                        convo={convo}
                        active={activeConvo?.conversation_id === convo.conversation_id}
                        onClick={() => handleSelect(convo)}
                        showBadge
                      />
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}

          {/* User's own helpdesk chats */}
          <div>
            <p className="mb-1 px-3 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
              Your Support Chats
            </p>
            {myHelpdeskConvos.length === 0 ? (
              <p className="px-3 py-2 text-xs text-muted-foreground">
                No support chats yet. Click "Contact Support" to start one.
              </p>
            ) : (
              <ul className="space-y-0.5">
                {myHelpdeskConvos
                  .filter(
                    (c) =>
                      !queueConvos.some((q) => q.conversation_id === c.conversation_id),
                  )
                  .map((convo) => (
                    <li key={convo.conversation_id}>
                      <ConvoRow
                        convo={convo}
                        active={activeConvo?.conversation_id === convo.conversation_id}
                        onClick={() => handleSelect(convo)}
                        showBadge={false}
                      />
                    </li>
                  ))}
                {/* Also show own agent-queue conversations as own chats if user is both agent and initiator */}
                {myHelpdeskConvos
                  .filter(
                    (c) =>
                      queueConvos.some((q) => q.conversation_id === c.conversation_id) &&
                      c.created_by === userId,
                  )
                  .map((convo) => (
                    <li key={`own-${convo.conversation_id}`}>
                      <ConvoRow
                        convo={convo}
                        active={activeConvo?.conversation_id === convo.conversation_id}
                        onClick={() => handleSelect(convo)}
                        showBadge={false}
                      />
                    </li>
                  ))}
              </ul>
            )}
          </div>
        </div>
      </div>

      {/* Right panel */}
      <div
        className={cn(
          "flex-1",
          !mobileShowConvo ? "hidden md:flex" : "flex",
          "flex-col",
        )}
      >
        {activeConvo ? (
          <ConversationView
            conversation={activeConvo}
            onBack={() => setMobileShowConvo(false)}
            onClaimSuccess={(state, agentUserId) =>
              setActiveConvo((prev) =>
                prev ? { ...prev, routing_state: state, active_agent_user_id: agentUserId } : null,
              )
            }
          />
        ) : (
          <EmptyState
            icon={<Headphones className="h-8 w-8" />}
            title="Helpdesk"
            description="Contact support or select a conversation from the queue"
            className="h-full"
          />
        )}
      </div>
    </div>
  );
}
