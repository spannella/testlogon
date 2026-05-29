import { cn } from "@/lib/utils";
import type { MemberBadgeData } from "@/api/types";

interface MemberBadgeProps {
  badge: MemberBadgeData | null;
  size?: "xs" | "sm" | "md";
  showName?: boolean;
}

export function MemberBadge({ badge, size = "sm", showName = true }: MemberBadgeProps) {
  if (!badge) return null;

  const sizeClasses = {
    xs: "px-1 py-0 text-[10px]",
    sm: "px-1.5 py-0.5 text-xs",
    md: "px-2 py-1 text-sm",
  };

  return (
    <span
      className={cn(
        "inline-flex items-center gap-0.5 rounded-full font-medium",
        sizeClasses[size],
      )}
      style={{
        backgroundColor: badge.badge_color ? `${badge.badge_color}20` : undefined,
        color: badge.badge_color || undefined,
      }}
      title={badge.tier_name}
    >
      {badge.badge_image_url ? (
        <img src={badge.badge_image_url} alt="" className="h-3 w-3 rounded-full" />
      ) : badge.badge_emoji ? (
        <span>{badge.badge_emoji}</span>
      ) : null}
      {showName && <span>{badge.tier_name}</span>}
    </span>
  );
}
