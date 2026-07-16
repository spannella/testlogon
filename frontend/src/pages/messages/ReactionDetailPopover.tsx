// MSG-011: Reaction detail popover — tapping a reaction badge shows who reacted
// with what (avatar + display name per emoji), grouped into emoji tabs.
import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { ReactionEmoji } from "@/components/shared/ReactionEmoji";
import { getReactionDetails } from "@/api/endpoints/messaging";

export interface ReactionDetailPopoverProps {
  conversationId: string;
  messageId: string;
  /** Emoji keys present on the message (used to pre-render tabs). */
  emojis: string[];
  /** Per-emoji counts, used to render counts on tabs while loading. */
  counts?: Record<string, number>;
  trigger: React.ReactNode;
}

function initialsFor(name: string): string {
  const trimmed = (name || "").trim();
  if (!trimmed) return "?";
  const parts = trimmed.split(/\s+/);
  const first = parts[0] ?? "";
  if (parts.length === 1) return first.slice(0, 2).toUpperCase();
  const last = parts[parts.length - 1] ?? "";
  return ((first[0] ?? "") + (last[0] ?? "")).toUpperCase();
}

export function ReactionDetailPopover({
  conversationId,
  messageId,
  emojis,
  counts,
  trigger,
}: ReactionDetailPopoverProps) {
  const [open, setOpen] = React.useState(false);
  const [activeEmoji, setActiveEmoji] = React.useState<string | null>(
    emojis[0] ?? null,
  );

  const { data, isLoading } = useQuery({
    queryKey: ["reaction-details", conversationId, messageId],
    queryFn: () => getReactionDetails(conversationId, messageId),
    enabled: open,
    refetchOnWindowFocus: true,
    staleTime: 5_000,
  });

  // Prefer server-side emoji order once loaded, falling back to the prop order.
  const tabEmojis = React.useMemo(() => {
    const fromServer = data ? Object.keys(data.reactions) : [];
    return fromServer.length > 0 ? fromServer : emojis;
  }, [data, emojis]);

  const selected =
    activeEmoji && tabEmojis.includes(activeEmoji)
      ? activeEmoji
      : tabEmojis[0] ?? null;

  const users = selected ? data?.reactions?.[selected] ?? [] : [];

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>{trigger}</PopoverTrigger>
      <PopoverContent
        align="start"
        className="w-64 p-0"
        data-testid="reaction-detail-popover"
      >
        {/* Emoji tabs */}
        <div className="flex flex-wrap gap-1 border-b border-border p-2">
          {tabEmojis.map((emoji) => (
            <button
              key={emoji}
              type="button"
              data-testid={`reaction-tab-${emoji}`}
              onClick={() => setActiveEmoji(emoji)}
              className={cn(
                "inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs transition-colors",
                selected === emoji
                  ? "bg-primary/20 ring-1 ring-primary/40"
                  : "hover:bg-accent",
              )}
            >
              <ReactionEmoji reactionKey={emoji} />
              <span>{counts?.[emoji] ?? data?.reactions?.[emoji]?.length ?? 0}</span>
            </button>
          ))}
        </div>

        {/* User list for the selected emoji */}
        <div className="max-h-56 overflow-y-auto p-2">
          {isLoading ? (
            <div className="flex items-center justify-center py-4 text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
            </div>
          ) : users.length === 0 ? (
            <p className="py-3 text-center text-xs text-muted-foreground">
              No reactions
            </p>
          ) : (
            <ul className="space-y-1" data-testid="reaction-user-list">
              {users.map((u) => (
                <li
                  key={u.user_sub}
                  className="flex items-center gap-2 rounded px-1 py-0.5"
                  data-testid="reaction-user-row"
                >
                  <Avatar className="h-6 w-6">
                    {u.profile_photo_url ? (
                      <AvatarImage src={u.profile_photo_url} alt={u.display_name} />
                    ) : null}
                    <AvatarFallback className="text-[10px]">
                      {initialsFor(u.display_name)}
                    </AvatarFallback>
                  </Avatar>
                  <span className="truncate text-sm">{u.display_name}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </PopoverContent>
    </Popover>
  );
}

export default ReactionDetailPopover;
