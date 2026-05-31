import * as React from "react";
import { useLocation } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { MessageSquare } from "lucide-react";
import { cn } from "@/lib/utils";
import type { Conversation, DelegatedConversation } from "@/api/types";
import { ConversationList } from "./ConversationList";
import { ConversationView } from "./ConversationView";
import { DelegateBanner } from "./DelegateBanner";
import { DelegateConversationView } from "./DelegateConversationView";
import { EmptyState } from "@/components/shared/EmptyState";
import { PageMeta } from "@/components/shared/PageMeta";
import { useMessagingStream } from "@/hooks/useMessagingStream";
import { useHeartbeat } from "@/hooks/usePresence";
import { useAuthStore } from "@/stores/authStore";
import { listDelegatedConversations } from "@/api/endpoints/delegates";

export default function MessagesPage() {
  const location = useLocation();
  const managingCreatorId = useAuthStore((s) => s.managingCreatorId);

  const [activeConvo, setActiveConvo] = React.useState<Conversation | null>(
    (location.state as { openConversation?: Conversation } | null)?.openConversation ?? null,
  );
  const [mobileShowConvo, setMobileShowConvo] = React.useState(
    !!(location.state as { openConversation?: Conversation } | null)?.openConversation,
  );

  // Delegate mode: active delegated conversation
  const [activeDelegateConvo, setActiveDelegateConvo] =
    React.useState<DelegatedConversation | null>(null);

  // Connect to real-time messaging stream (only when not in delegate mode)
  useMessagingStream(!managingCreatorId);

  // Send presence heartbeat every 30s
  useHeartbeat(true);

  // Reset active conversations when switching modes
  React.useEffect(() => {
    setActiveConvo(null);
    setActiveDelegateConvo(null);
    setMobileShowConvo(false);
  }, [managingCreatorId]);

  // Fetch delegated conversations when in managing mode
  const { data: delegatedConvos = [] } = useQuery<DelegatedConversation[]>({
    queryKey: ["delegate", "conversations", managingCreatorId],
    queryFn: () => listDelegatedConversations(managingCreatorId!),
    enabled: !!managingCreatorId,
    refetchInterval: 10_000,
  });

  const handleSelect = (convo: Conversation) => {
    setActiveConvo(convo);
    setMobileShowConvo(true);
  };

  const handleDelegateSelect = (convo: DelegatedConversation) => {
    setActiveDelegateConvo(convo);
    setMobileShowConvo(true);
  };

  const handleBack = () => {
    setMobileShowConvo(false);
  };

  // Delegate mode UI
  if (managingCreatorId) {
    return (
      <div className="flex h-full flex-col">
        <PageMeta title="Messages - Delegate" />
        <DelegateBanner />
        <div className="flex flex-1 overflow-hidden">
          {/* Delegated conversation list */}
          <div
            className={cn(
              "w-full flex-shrink-0 border-r border-border md:w-72 lg:w-80",
              mobileShowConvo ? "hidden md:flex" : "flex",
              "flex-col",
            )}
          >
            <div className="border-b border-border px-4 py-3">
              <h2 className="text-sm font-semibold">Creator's Conversations</h2>
            </div>
            <div className="flex-1 overflow-auto">
              {delegatedConvos.map((c) => (
                <button
                  key={c.conversation_id}
                  onClick={() => handleDelegateSelect(c)}
                  className={cn(
                    "flex w-full items-center gap-3 border-b border-border px-4 py-3 text-left hover:bg-muted/50",
                    activeDelegateConvo?.conversation_id === c.conversation_id &&
                      "bg-muted",
                  )}
                  data-testid={`delegate-convo-${c.conversation_id}`}
                >
                  <div className="flex-1 min-w-0">
                    <p className="truncate text-sm font-medium">
                      {c.title ||
                        c.participants
                          .filter((p) => p.user_id !== managingCreatorId)
                          .map((p) => p.user_id)
                          .join(", ") ||
                        c.conversation_id}
                    </p>
                    <p className="truncate text-xs text-muted-foreground">
                      {c.last_message_preview || "No messages yet"}
                    </p>
                  </div>
                  {c.unread_count > 0 && (
                    <span className="flex h-5 w-5 items-center justify-center rounded-full bg-primary text-[10px] text-primary-foreground">
                      {c.unread_count}
                    </span>
                  )}
                </button>
              ))}
              {delegatedConvos.length === 0 && (
                <p className="px-4 py-8 text-center text-sm text-muted-foreground">
                  No conversations
                </p>
              )}
            </div>
          </div>

          {/* Delegated conversation view */}
          <div
            className={cn(
              "flex-1",
              !mobileShowConvo ? "hidden md:flex" : "flex",
              "flex-col",
            )}
          >
            {activeDelegateConvo ? (
              <DelegateConversationView
                conversation={activeDelegateConvo}
                onBack={handleBack}
              />
            ) : (
              <EmptyState
                icon={<MessageSquare className="h-8 w-8" />}
                title="Select a conversation"
                description="Choose a creator's conversation to manage"
                className="h-full"
              />
            )}
          </div>
        </div>
      </div>
    );
  }

  // Normal mode
  return (
    <div className="flex h-full">
      <PageMeta title="Messages" />
      {/* Conversation list panel */}
      <div
        className={cn(
          "w-full flex-shrink-0 border-r border-border md:w-72 lg:w-80",
          // On mobile: hide when viewing a conversation
          mobileShowConvo ? "hidden md:flex" : "flex",
          "flex-col",
        )}
      >
        <ConversationList
          activeId={activeConvo?.conversation_id}
          onSelect={handleSelect}
        />
      </div>

      {/* Conversation view panel */}
      <div
        className={cn(
          "flex-1",
          // On mobile: hide when showing the list
          !mobileShowConvo ? "hidden md:flex" : "flex",
          "flex-col",
        )}
      >
        {activeConvo ? (
          <ConversationView
            conversation={activeConvo}
            onBack={handleBack}
          />
        ) : (
          <EmptyState
            icon={<MessageSquare className="h-8 w-8" />}
            title="Select a conversation"
            description="Choose a conversation from the list to start messaging"
            className="h-full"
          />
        )}
      </div>
    </div>
  );
}
