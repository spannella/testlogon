import * as React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Search, Plus, MessageSquare } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";
import { getConversations, startConversation } from "@/api/endpoints/messaging";
import type { Conversation } from "@/api/types";
import { PresenceDot } from "./PresenceDot";
import { UserSearch } from "./UserSearch";
import { useAuthStore } from "@/stores/authStore";

interface ConversationListProps {
  activeId?: string;
  onSelect: (conversation: Conversation) => void;
}

export function ConversationList({ activeId, onSelect }: ConversationListProps) {
  const [search, setSearch] = React.useState("");
  const [newConvoOpen, setNewConvoOpen] = React.useState(false);
  const userId = useAuthStore((s) => s.userId);

  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ["conversations"],
    queryFn: () => getConversations(),
  });

  const createConvo = useMutation({
    mutationFn: (pid: string) => startConversation({ participant_id: pid }),
    onSuccess: (convo) => {
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
      onSelect(convo);
      setNewConvoOpen(false);
    },
  });

  const conversations = data?.conversations ?? [];

  const filtered = search.trim()
    ? conversations.filter((c) => {
        const q = search.toLowerCase();
        const title = conversationName(c).toLowerCase();
        const lastMsg = c.last_message?.body?.toLowerCase() ?? "";
        return title.includes(q) || lastMsg.includes(q);
      })
    : conversations;

  return (
    <div className="flex h-full flex-col">
      {/* Search */}
      <div className="border-b border-border p-3">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search conversations..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
      </div>

      {/* List */}
      <div className="flex-1 overflow-y-auto">
        {isLoading ? (
          <div className="space-y-1 p-2">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="flex items-center gap-3 rounded-lg p-3">
                <Skeleton className="h-10 w-10 rounded-full" />
                <div className="flex-1 space-y-1.5">
                  <Skeleton className="h-3.5 w-24" />
                  <Skeleton className="h-3 w-40" />
                </div>
              </div>
            ))}
          </div>
        ) : filtered.length === 0 ? (
          <EmptyState
            icon={<MessageSquare className="h-6 w-6" />}
            title={search ? "No matches" : "No conversations"}
            description={search ? "Try a different search" : "Start a new conversation"}
            className="py-12"
          />
        ) : (
          <div className="space-y-0.5 p-2">
            {filtered.map((convo) => {
              const name = conversationName(convo);
              const initials = name.slice(0, 2).toUpperCase();
              const active = convo.conversation_id === activeId;
              const lastMsg = convo.last_message;
              const unread = (convo.unread_count ?? 0) > 0;

              return (
                <button
                  key={convo.conversation_id}
                  className={cn(
                    "flex w-full items-center gap-3 rounded-lg p-3 text-left transition-colors",
                    active
                      ? "bg-primary/10 text-foreground"
                      : "hover:bg-accent text-foreground",
                  )}
                  onClick={() => onSelect(convo)}
                >
                  <div className="relative shrink-0">
                    <Avatar className="h-10 w-10">
                      <AvatarFallback className="text-xs">{initials}</AvatarFallback>
                    </Avatar>
                    {convo.type === "dm" && (() => {
                      const other = convo.participants.find((p) => p.user_id !== userId);
                      return other ? <PresenceDot userId={other.user_id} /> : null;
                    })()}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center justify-between gap-2">
                      <span className={cn("truncate text-sm", unread ? "font-semibold" : "font-medium")}>
                        {name}
                      </span>
                      {lastMsg && (
                        <span className="shrink-0 text-[10px] text-muted-foreground">
                          {formatTimestamp(lastMsg.created_at)}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center justify-between gap-2">
                      <span className={cn(
                        "truncate text-xs",
                        unread ? "font-medium text-foreground" : "text-muted-foreground",
                      )}>
                        {lastMsg?.body ?? "No messages yet"}
                      </span>
                      {unread && (
                        <span className="flex h-5 min-w-5 shrink-0 items-center justify-center rounded-full bg-primary px-1 text-[10px] font-bold text-primary-foreground">
                          {convo.unread_count! > 99 ? "99+" : convo.unread_count}
                        </span>
                      )}
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* New conversation button */}
      <div className="border-t border-border p-3">
        <Button
          variant="outline"
          className="w-full"
          onClick={() => setNewConvoOpen(true)}
        >
          <Plus className="h-4 w-4" />
          New conversation
        </Button>
      </div>

      {/* New conversation dialog */}
      <Dialog open={newConvoOpen} onOpenChange={setNewConvoOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New Conversation</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <UserSearch
              placeholder="Search for a user..."
              onSelect={(user) => createConvo.mutate(user.user_id)}
            />
            {createConvo.isPending && (
              <p className="text-sm text-muted-foreground">Starting conversation...</p>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ─── Helpers ─────────────────────────────────────────────────────

function conversationName(c: Conversation): string {
  if (c.title) return c.title;
  if (c.participants.length > 0) {
    return c.participants
      .slice(0, 3)
      .map((p) => p.display_name ?? p.user_id)
      .join(", ");
  }
  return "Conversation";
}

function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

  if (diffDays === 0) {
    return date.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
  }
  if (diffDays === 1) return "Yesterday";
  if (diffDays < 7) {
    return date.toLocaleDateString(undefined, { weekday: "short" });
  }
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}
