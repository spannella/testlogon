import { cn } from "@/lib/utils";
import { usePresenceStatus } from "@/hooks/usePresence";

interface PresenceDotProps {
  userId: string;
  className?: string;
}

/**
 * Small green/grey dot indicating online/offline presence.
 * Positioned absolute — wrap parent in `relative` for correct placement.
 */
export function PresenceDot({ userId, className }: PresenceDotProps) {
  const { online } = usePresenceStatus(userId);

  return (
    <span
      className={cn(
        "absolute bottom-0 right-0 block h-2.5 w-2.5 rounded-full border-2 border-background",
        online
          ? "bg-emerald-500 shadow-[0_0_4px_rgba(16,185,129,0.6)]"
          : "bg-muted-foreground/40",
        className,
      )}
      aria-label={online ? "Online" : "Offline"}
    />
  );
}
