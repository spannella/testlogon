import { useEffect, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { cn } from "@/lib/utils";
import { getViewers, markViewed } from "@/api/endpoints/messaging";
import type { MessageViewer } from "@/api/types";

const MAX_AVATARS = 5;

interface ReadReceiptsProps {
  conversationId: string;
  messageId: string;
  isOwn: boolean;
}

export function ReadReceipts({ conversationId, messageId, isOwn }: ReadReceiptsProps) {
  // Only show read receipts on own messages
  if (!isOwn) return null;

  return <ReadReceiptsInner conversationId={conversationId} messageId={messageId} />;
}

function ReadReceiptsInner({
  conversationId,
  messageId,
}: {
  conversationId: string;
  messageId: string;
}) {
  const { data: viewers } = useQuery({
    queryKey: ["message-views", conversationId, messageId],
    queryFn: () => getViewers(conversationId, messageId),
    staleTime: 30_000,
    enabled: !messageId.startsWith("optimistic-"),
  });

  const items: MessageViewer[] = viewers ?? [];

  if (items.length === 0) return null;

  const visible = items.slice(0, MAX_AVATARS);
  const overflow = items.length - MAX_AVATARS;

  const label = items.map((v) => v.user_id).join(", ");

  return (
    <div className="flex items-center justify-end gap-0.5 pt-0.5" title={`Seen by ${label}`}>
      {visible.map((viewer, i) => (
        <Avatar
          key={viewer.user_id}
          className={cn(
            "h-5 w-5 border border-background",
            i > 0 && "-ml-1.5",
          )}
        >
          <AvatarFallback className="text-[8px]">
            {viewer.user_id.slice(0, 2).toUpperCase()}
          </AvatarFallback>
        </Avatar>
      ))}
      {overflow > 0 && (
        <span className="ml-0.5 text-[10px] text-muted-foreground">+{overflow}</span>
      )}
    </div>
  );
}

// ─── Auto-mark viewed via IntersectionObserver ─────────────────

interface ViewTrackerProps {
  conversationId: string;
  messageId: string;
  isOwn: boolean;
}

export function ViewTracker({ conversationId, messageId, isOwn }: ViewTrackerProps) {
  const ref = useRef<HTMLDivElement>(null);
  const markedRef = useRef(false);

  useEffect(() => {
    // Don't track own messages or optimistic messages
    if (isOwn) return;
    if (messageId.startsWith("optimistic-")) return;

    const el = ref.current;
    if (!el) return;

    const observer = new IntersectionObserver(
      (entries) => {
        const entry = entries[0];
        if (entry?.isIntersecting && !markedRef.current) {
          markedRef.current = true;
          markViewed(conversationId, messageId).catch(() => {});
        }
      },
      { threshold: 0.5 },
    );

    observer.observe(el);
    return () => observer.disconnect();
  }, [conversationId, messageId, isOwn]);

  if (isOwn) return null;
  return <div ref={ref} className="h-px w-full" aria-hidden="true" />;
}
