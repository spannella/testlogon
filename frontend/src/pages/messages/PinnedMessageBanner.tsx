import { Pin, X } from "lucide-react";
import { Button } from "@/components/ui/button";

interface PinnedMessageBannerProps {
  latestPinnedMessageId?: string;
  latestPinnedAt?: number;
  previewText?: string;
  onViewAllPins: () => void;
  onJumpToMessage: (messageId: string) => void;
  onDismiss: () => void;
}

function formatPinnedAt(ts?: number): string {
  if (!ts) return "";
  return new Date(ts * 1000).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

export function PinnedMessageBanner({
  latestPinnedMessageId,
  latestPinnedAt,
  previewText,
  onViewAllPins,
  onJumpToMessage,
  onDismiss,
}: PinnedMessageBannerProps) {
  if (!latestPinnedMessageId) return null;

  return (
    <div className="flex items-center gap-3 border-b border-amber-200 bg-amber-50/80 px-4 py-2">
      <Pin className="h-4 w-4 shrink-0 text-amber-700" />
      <div className="min-w-0 flex-1">
        <p className="truncate text-sm font-medium text-amber-900">
          {previewText?.trim() || "Pinned message"}
        </p>
        {latestPinnedAt ? (
          <p className="text-xs text-amber-700">Pinned {formatPinnedAt(latestPinnedAt)}</p>
        ) : null}
      </div>
      <Button variant="ghost" size="sm" className="h-7 px-2 text-xs" onClick={onViewAllPins}>
        View all pins
      </Button>
      <Button
        variant="ghost"
        size="sm"
        className="h-7 px-2 text-xs"
        onClick={() => onJumpToMessage(latestPinnedMessageId)}
      >
        Jump
      </Button>
      <Button variant="ghost" size="icon" className="h-7 w-7" aria-label="Dismiss pinned banner" onClick={onDismiss}>
        <X className="h-3.5 w-3.5" />
      </Button>
    </div>
  );
}
