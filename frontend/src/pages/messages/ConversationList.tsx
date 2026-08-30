import * as React from "react";
import { locationPreview } from "@/lib/locationCards";
import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Search, Plus, MessageSquare, Users, BellOff } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";
import { getConversations, startConversation, startGroupConversation } from "@/api/endpoints/messaging";
import type { Conversation, Message, UserSearchResult } from "@/api/types";
import { PresenceDot } from "./PresenceDot";
import { UserSearch } from "./UserSearch";
import { useAuthStore } from "@/stores/authStore";
import { transferPreview } from "@/lib/cryptoTransfer";
import { isRevealLocked } from "@/lib/revealAt";
import { resolveCanonicalProfilePath } from "@/components/shared/UserProfileLink";
import { StalenessIndicator } from "@/components/shared/StalenessIndicator";
import { isMuted } from "@/lib/conversationMute";

interface ConversationListProps {
  activeId?: string;
  onSelect: (conversation: Conversation) => void;
}

export function ConversationList({ activeId, onSelect }: ConversationListProps) {
  const navigate = useNavigate();
  const [search, setSearch] = React.useState("");
  const [newConvoOpen, setNewConvoOpen] = React.useState(false);
  const [isGroupMode, setIsGroupMode] = React.useState(false);
  const [groupTitle, setGroupTitle] = React.useState("");
  const [groupParticipants, setGroupParticipants] = React.useState<UserSearchResult[]>([]);
  const userId = useAuthStore((s) => s.userId);

  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ["conversations"],
    queryFn: () => getConversations(),
    refetchOnWindowFocus: true,
    refetchOnMount: true,
    staleTime: 0,
  });

  // Check if data came from offline cache
  const isFromCache = (data as any)?.__fromOfflineCache === true;
  const cachedAt = (data as any)?.__cachedAt as number | undefined;

  const addConvoToCache = (convo: Conversation) => {
    queryClient.setQueryData(
      ["conversations"],
      (old: { conversations: Conversation[]; next_cursor?: string } | Conversation[] | undefined) => {
        const existing: Conversation[] = Array.isArray(old) ? old : (old?.conversations ?? []);
        if (existing.some((c) => c.conversation_id === convo.conversation_id)) return old;
        const updated = [convo, ...existing];
        return Array.isArray(old) ? updated : { ...(old ?? {}), conversations: updated };
      },
    );
    queryClient.invalidateQueries({ queryKey: ["conversations"] });
  };

  const createConvo = useMutation({
    mutationFn: (pid: string) => startConversation({ participant_ids: [pid], type: "dm" }),
    onSuccess: (convo) => {
      addConvoToCache(convo);
      onSelect(convo);
      setNewConvoOpen(false);
    },
  });

  const createGroupConvo = useMutation({
    mutationFn: () =>
      startGroupConversation({
        participant_ids: groupParticipants.map((p) => p.user_id),
        title: groupTitle.trim() || undefined,
      }),
    onSuccess: (convo) => {
      addConvoToCache(convo);
      onSelect(convo);
      setNewConvoOpen(false);
      setGroupParticipants([]);
      setGroupTitle("");
    },
  });

  const conversations = data?.conversations ?? [];

  const filtered = search.trim()
    ? conversations.filter((c) => {
        const q = search.toLowerCase();
        const title = conversationName(c, userId ?? undefined).toLowerCase();
        const lastMsg = (c.last_message?.text ?? c.last_message_preview ?? "").toLowerCase();
        return title.includes(q) || lastMsg.includes(q);
      })
    : conversations;

  return (
    <div className="flex h-full flex-col">
      {/* Staleness indicator for cached data */}
      {isFromCache && (
        <div className="border-b border-border px-3 py-1.5">
          <StalenessIndicator cachedAt={cachedAt} />
        </div>
      )}

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
              const name = conversationName(convo, userId ?? undefined);
              const initials = name.slice(0, 2).toUpperCase();
              const active = convo.conversation_id === activeId;
              const lastMsg = convo.last_message;
              const unread = (convo.unread_count ?? 0) > 0;

              const other = convo.type === "dm" ? convo.participants.find((p) => p.user_id !== userId) : undefined;
              const profilePath = other
                ? resolveCanonicalProfilePath({ userId: other.user_id, displayName: other.display_name })
                : null;

              return (
                <button
                  key={convo.conversation_id}
                  data-testid={`conversation-row-${convo.conversation_id}`}
                  className={cn(
                    "flex w-full items-center gap-3 rounded-lg p-3 text-left transition-colors",
                    active
                      ? "bg-primary/10 text-foreground"
                      : "hover:bg-accent text-foreground",
                  )}
                  onClick={() => onSelect(convo)}
                >
                  <div className="relative shrink-0">
                    <Avatar
                      className={cn("h-10 w-10", profilePath ? "cursor-pointer hover:ring-2 hover:ring-primary/30" : "")}
                      role={profilePath ? "link" : undefined}
                      aria-label={profilePath && other ? `Open ${other.display_name ?? other.user_id} profile` : undefined}
                      onClick={profilePath ? (e) => {
                        e.stopPropagation();
                        navigate(profilePath);
                      } : undefined}
                    >
                      {other?.profile_photo_url && <AvatarImage src={other.profile_photo_url} alt={other.display_name ?? other.user_id} />}
                      <AvatarFallback className="text-xs">{initials}</AvatarFallback>
                    </Avatar>
                    {convo.type === "dm" && (() => {
                      const other = convo.participants.find((p) => p.user_id !== userId);
                      return other ? <PresenceDot userId={other.user_id} /> : null;
                    })()}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center justify-between gap-2">
                      <span
                        className={cn(
                          "truncate text-sm",
                          unread ? "font-semibold" : "font-medium",
                          profilePath ? "cursor-pointer hover:underline" : undefined,
                        )}
                        role={profilePath ? "link" : undefined}
                        aria-label={profilePath && other ? `Open ${other.display_name ?? other.user_id} profile` : undefined}
                        onClick={profilePath ? (e) => {
                          e.stopPropagation();
                          navigate(profilePath);
                        } : undefined}
                      >
                        {name}
                      </span>
                      {isMuted(convo.muted_until, Math.floor(Date.now() / 1000)) && (
                        <BellOff
                          className="h-3 w-3 shrink-0 text-muted-foreground"
                          aria-label="Muted"
                        />
                      )}
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
                        {getPreviewText(lastMsg, convo, userId ?? undefined)}
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
      <div className="border-t border-border p-3 flex gap-2">
        <Button
          variant="outline"
          className="flex-1"
          onClick={() => { setIsGroupMode(false); setNewConvoOpen(true); }}
        >
          <Plus className="h-4 w-4" />
          New DM
        </Button>
        <Button
          variant="outline"
          className="flex-1"
          onClick={() => { setIsGroupMode(true); setGroupParticipants([]); setGroupTitle(""); setNewConvoOpen(true); }}
        >
          <Users className="h-4 w-4" />
          New Group
        </Button>
      </div>

      {/* New conversation dialog */}
      <Dialog open={newConvoOpen} onOpenChange={setNewConvoOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{isGroupMode ? "New Group Conversation" : "New Direct Message"}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            {isGroupMode ? (
              <>
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">Group name (optional)</label>
                  <Input
                    placeholder="e.g. Team Chat"
                    value={groupTitle}
                    onChange={(e) => setGroupTitle(e.target.value)}
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">Add participants</label>
                  <UserSearch
                    placeholder="Search for users..."
                    onSelect={(user) => {
                      if (!groupParticipants.find((p) => p.user_id === user.user_id)) {
                        setGroupParticipants((prev) => [...prev, user]);
                      }
                    }}
                  />
                </div>
                {groupParticipants.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {groupParticipants.map((p) => (
                      <Badge key={p.user_id} variant="secondary" className="gap-1">
                        {p.display_name ?? p.user_id}
                        <button
                          onClick={() => setGroupParticipants((prev) => prev.filter((x) => x.user_id !== p.user_id))}
                          className="ml-1 text-muted-foreground hover:text-foreground"
                        >
                          ×
                        </button>
                      </Badge>
                    ))}
                  </div>
                )}
                <Button
                  className="w-full"
                  onClick={() => createGroupConvo.mutate()}
                  disabled={groupParticipants.length === 0 || createGroupConvo.isPending}
                >
                  {createGroupConvo.isPending ? "Creating..." : `Create Group (${groupParticipants.length} participant${groupParticipants.length !== 1 ? "s" : ""})`}
                </Button>
              </>
            ) : (
              <>
                <UserSearch
                  placeholder="Search for a user..."
                  onSelect={(user) => createConvo.mutate(user.user_id)}
                />
                {createConvo.isPending && (
                  <p className="text-sm text-muted-foreground">Starting conversation...</p>
                )}
              </>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ─── Helpers ─────────────────────────────────────────────────────

function getPreviewText(lastMsg: Message | undefined, convo: Conversation, currentUserId?: string): string {
  if (!lastMsg) return convo.last_message_preview ?? "No messages yet";
  if (lastMsg.expired) return "[This message has expired]";
  // FE-120: hide scheduled-reveal content from recipients until reveal time.
  if (isRevealLocked(lastMsg.reveal_at, lastMsg.sender_id === currentUserId, Math.floor(Date.now() / 1000)))
    return "🔒 Scheduled reveal";
  if (lastMsg.view_once && lastMsg.text === null) return "[Already viewed]";
  if (lastMsg.locked && !lastMsg.is_unlocked) return "[Locked message]";
  if (lastMsg.kind === "voice_message") return "[Voice message]";
  if (lastMsg.kind === "voicemail") return "[Voicemail]";
  if (lastMsg.kind === "countdown")
    return `[Countdown: ${lastMsg.countdown_title ?? lastMsg.text ?? ""}]`;
  if (lastMsg.kind === "gif") return "[GIF]";
  if (lastMsg.kind === "sticker") return "[Sticker]";
  if (lastMsg.kind === "find_datetime") return "[Find a Time]";
  if (lastMsg.kind === "market_card") return `[Market: ${lastMsg.symbol ?? ""}]`;
  if (lastMsg.kind === "position_card") return `[Position: ${lastMsg.symbol ?? ""}]`;
  if (lastMsg.kind === "crypto_transfer")
    return transferPreview(
      { sender_id: lastMsg.sender_id, asset: lastMsg.asset, amount: lastMsg.amount },
      currentUserId,
    );
  if (lastMsg.kind === "location")
    return locationPreview(lastMsg.label ?? undefined, lastMsg.place_name ?? undefined);
  if (lastMsg.kind === "live_location") return "📍 Live location";
  return lastMsg.text ?? convo.last_message_preview ?? "No messages yet";
}

function conversationName(c: Conversation, currentUserId?: string): string {
  if (c.title) return c.title;
  const pool = (c.type === "dm" && currentUserId)
    ? c.participants.filter((p) => p.user_id !== currentUserId)
    : c.participants;
  const shown = (pool.length ? pool : c.participants).slice(0, 3);
  return shown.map((p) => p.display_name ?? p.user_id).join(", ") || "Conversation";
}

function formatTimestamp(ts: number): string {
  const date = new Date(ts * 1000);
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
