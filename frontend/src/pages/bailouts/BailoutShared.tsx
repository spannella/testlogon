import { Info } from "lucide-react";
import { cn } from "@/lib/utils";
import { formatBps, type HealthZone } from "@/lib/bailout";

/**
 * Shared building blocks for the MARGIN DISTRESS / PRE-EMPTIVE BAILOUT AUCTION
 * surface: the honest "pending backend" note (every read 404s until the backend
 * ships) and the 3-zone health meter. Kept framework-light and reused across the
 * position surface, the auction panel, and the discovery board.
 */

/** Honest "pending backend" note shown when a `/me/margin/distress` or
 * `/me/bailouts/*` read 404s (the surface is UI-complete; the backend has not
 * shipped). It never fabricates a distress signal — it says so plainly. */
export function BailoutPendingBackend({ label = "This data" }: { label?: string }) {
  return (
    <div className="flex items-start gap-2 rounded-lg border border-dashed bg-muted/30 p-4 text-sm text-muted-foreground">
      <Info className="mt-0.5 h-4 w-4 shrink-0" />
      <div>
        <p className="font-medium text-foreground">Pending backend</p>
        <p>
          {label} is not available yet — the margin-distress / bailout-auction endpoints have not
          shipped on this environment. Distress is server-authoritative, so nothing is shown until
          the backend reports it (the client never fabricates a distress signal). The surface is
          wired and will populate automatically once the routes deploy.
        </p>
      </div>
    </div>
  );
}

const ZONE_META: Record<
  HealthZone,
  { label: string; badge: string; bar: string; text: string }
> = {
  healthy: {
    label: "Healthy",
    badge: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
    bar: "bg-emerald-500",
    text: "Comfortably above the liquidation line.",
  },
  distress: {
    label: "Distress",
    badge: "bg-amber-500/15 text-amber-700 dark:text-amber-400",
    bar: "bg-amber-500",
    text: "Inside the volatility-scaled danger band — still solvent, but a bailout can be opened.",
  },
  liquidation: {
    label: "Liquidation",
    badge: "bg-rose-500/15 text-rose-700 dark:text-rose-400",
    bar: "bg-rose-500",
    text: "Equity is at/under maintenance — the bailout window is closed (this is a liquidation).",
  },
};

/** A small zone badge. */
export function ZoneBadge({ zone }: { zone: HealthZone }) {
  const m = ZONE_META[zone];
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold",
        m.badge,
      )}
    >
      {m.label}
    </span>
  );
}

/**
 * The 3-zone Healthy -> Distress -> Liquidation health meter. `fraction` (0..1)
 * is how far the buffer has been consumed toward the danger line (0 = healthy
 * edge, 1 = at the danger line / in-band). The active zone tints the fill.
 */
export function HealthMeter({
  zone,
  fraction,
  bufferBps,
  dangerBps,
}: {
  zone: HealthZone;
  fraction: number;
  bufferBps: number;
  dangerBps: number;
}) {
  const m = ZONE_META[zone];
  // Liquidation pins the meter full; otherwise use the consumed fraction.
  const pct = zone === "liquidation" ? 100 : Math.round(Math.max(0, Math.min(1, fraction)) * 100);
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <ZoneBadge zone={zone} />
          <span className="text-xs text-muted-foreground">{m.text}</span>
        </div>
      </div>
      {/* Meter track with the three zone regions marked by gradient stops. */}
      <div className="relative h-3 w-full overflow-hidden rounded-full bg-muted">
        {/* zone regions: green (0-50%), amber (50-85%), rose (85-100%) */}
        <div
          className="absolute inset-y-0 left-0 right-0"
          style={{
            background:
              "linear-gradient(90deg, rgba(16,185,129,0.25) 0%, rgba(16,185,129,0.25) 50%, rgba(245,158,11,0.25) 50%, rgba(245,158,11,0.25) 85%, rgba(244,63,94,0.25) 85%)",
          }}
        />
        <div
          className={cn("relative h-full rounded-full transition-all", m.bar)}
          style={{ width: `${pct}%` }}
        />
      </div>
      <div className="flex justify-between text-[11px] text-muted-foreground">
        <span>
          Buffer to liq: <span className="font-medium text-foreground">{formatBps(bufferBps)}</span>
        </span>
        <span>
          Danger line: <span className="font-medium text-foreground">{formatBps(dangerBps)}</span>
        </span>
      </div>
    </div>
  );
}
