import { Info } from "lucide-react";

/**
 * Honest "coming soon" note shown when a `/me/referral*` or `/me/rewards*` read
 * 404s (the surface is UI-complete but the backend has not shipped yet). Reused
 * across the referrals + rewards screens so the empty state reads the same.
 */
export function PendingRewards({
  label = "This program",
}: {
  label?: string;
}) {
  return (
    <div className="flex items-start gap-2 rounded-lg border border-dashed bg-muted/30 p-4 text-sm text-muted-foreground">
      <Info className="mt-0.5 h-4 w-4 shrink-0" />
      <div>
        <p className="font-medium text-foreground">Rewards program coming soon</p>
        <p>
          {label} is not available yet on this environment — the rewards endpoints have not shipped.
          The surface is wired and will populate automatically once they do.
        </p>
      </div>
    </div>
  );
}
