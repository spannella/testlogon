// Config + pure helpers for the Home "Trading & Investing" section.
//
// The tile list is the single source of truth for the quick-link grid on the
// Home dashboard AND (icon/label reused) the mobile "More" trading block. Every
// route here is already shipped + routed; icons/labels mirror the Sidebar so the
// two navigations stay visually consistent. Kept dependency-free (icon is a
// lucide component ref) so the pure helpers below are unit-testable in isolation.

import type { LucideIcon } from "lucide-react";
import {
  CandlestickChart,
  Sparkles,
  Boxes,
  ShieldAlert,
  Bell,
  Timer,
  Landmark,
  LifeBuoy,
  Building2,
  Receipt,
} from "lucide-react";

export interface TradingSurface {
  /** Stable id (used as React key + test anchor). */
  id: string;
  label: string;
  /** One-line description shown under the label on the dashboard card. */
  desc: string;
  path: string;
  icon: LucideIcon;
}

/**
 * The ten trading / investing surfaces to surface on Home + mobile nav.
 * Order = rough "start here -> deeper tooling" flow.
 */
export const TRADING_SURFACES: TradingSurface[] = [
  { id: "invest", label: "Invest", desc: "Your investing hub", path: "/invest", icon: Sparkles },
  { id: "markets", label: "Markets", desc: "Live order books & charts", path: "/markets", icon: CandlestickChart },
  { id: "strategies", label: "Strategy Funds", desc: "Invest in NAV-unit funds", path: "/strategies", icon: Boxes },
  { id: "portfolio-analytics", label: "Portfolio Risk", desc: "Exposure & risk analytics", path: "/portfolio/analytics", icon: ShieldAlert },
  { id: "activity-center", label: "Activity Center", desc: "Fills, funding & liquidations", path: "/activity-center", icon: Bell },
  { id: "algos", label: "Active Algos", desc: "TWAP & iceberg monitors", path: "/algos", icon: Timer },
  { id: "tokens", label: "Creator Tokens", desc: "Mint & trade creator tokens", path: "/tokens", icon: Landmark },
  { id: "bailouts", label: "Bailouts", desc: "Liquidity relief programs", path: "/bailouts", icon: LifeBuoy },
  { id: "custody-providers", label: "Custody Providers", desc: "Connect a custodian", path: "/custody/providers", icon: Building2 },
  { id: "reports-tax", label: "Tax & Gains", desc: "Realized gains & tax lots", path: "/reports/tax", icon: Receipt },
];

/** Format an unread/activity count for a small badge (caps at 99+). */
export function formatUnreadBadge(n: number | undefined | null): string | null {
  if (n == null || !Number.isFinite(n) || n <= 0) return null;
  const v = Math.floor(n);
  return v > 99 ? "99+" : String(v);
}

/** A minimal shape used by the "top strategy" teaser picker (subset of Strategy). */
export interface TopStrategyLike {
  name: string;
  inception_return_bps?: number;
  aum_cents?: number;
}

/**
 * Pick the single "top" strategy for the Home teaser: highest inception return
 * (bps), tie-broken by AUM. Returns undefined for an empty/absent list so the
 * caller can degrade gracefully. Pure — no fetching.
 */
export function pickTopStrategy<T extends TopStrategyLike>(list: T[] | undefined | null): T | undefined {
  if (!Array.isArray(list) || list.length === 0) return undefined;
  return list.reduce((best, cur) => {
    const b = best.inception_return_bps ?? -Infinity;
    const c = cur.inception_return_bps ?? -Infinity;
    if (c > b) return cur;
    if (c === b && (cur.aum_cents ?? 0) > (best.aum_cents ?? 0)) return cur;
    return best;
  });
}

/** Format a bps return as a signed percentage string (e.g. +12.3%). */
export function formatReturnBps(bps: number | undefined | null): string {
  if (bps == null || !Number.isFinite(bps)) return "—";
  const pct = bps / 100;
  return `${pct > 0 ? "+" : ""}${pct.toFixed(1)}%`;
}
