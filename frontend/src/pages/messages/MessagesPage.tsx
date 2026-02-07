import * as React from "react";
import { MessageSquare } from "lucide-react";
import { cn } from "@/lib/utils";
import type { Conversation } from "@/api/types";
import { ConversationList } from "./ConversationList";
import { ConversationView } from "./ConversationView";
import { EmptyState } from "@/components/shared/EmptyState";
import { useMessagingStream } from "@/hooks/useMessagingStream";
import { useHeartbeat } from "@/hooks/usePresence";

export default function MessagesPage() {
  const [activeConvo, setActiveConvo] = React.useState<Conversation | null>(null);
  const [mobileShowConvo, setMobileShowConvo] = React.useState(false);

  // Connect to real-time messaging stream
  useMessagingStream(true);

  // Send presence heartbeat every 30s
  useHeartbeat(true);

  const handleSelect = (convo: Conversation) => {
    setActiveConvo(convo);
    setMobileShowConvo(true);
  };

  const handleBack = () => {
    setMobileShowConvo(false);
  };

  return (
    <div className="flex h-full">
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
