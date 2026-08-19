import * as React from "react";
import { toast } from "sonner";
import { notify } from "@/lib/tradeFeedback";
import { loadAlertPrefs, ALERT_PREFS_KEY, type AlertPrefs } from "@/lib/tradingPrefs";
import {
  useFillsFees,
  useLiquidations,
  useFundingPayments,
  useMarginAccount,
  usePmResolutions,
} from "@/hooks/useTrading";
import { useSymbols } from "@/hooks/useMarketData";
import { formatPrice, formatQty } from "@/pages/markets/format";
import type { MarketSymbol } from "@/api/endpoints/marketData";
import type {
  FillFee,
  Liquidation,
  FundingPayment,
  MarginAccount,
  PmResolution,
} from "@/api/endpoints/trading";

// ── Trading alerts: client-side DERIVED from the existing `/me/*` feeds ──
// There is NO backend notifications route, so we synthesize alerts by diffing
// the polled trader feeds against a per-feed "last-seen" marker persisted in
// localStorage. On the FIRST fetch of each feed we SEED the marker (no toast
// storm on load); thereafter only genuinely-new events fire an alert + toast.

export type TradingAlertKind =
  | "fill"
  | "liquidation"
  | "funding"
  | "margin"
  | "pm_resolved";

export interface TradingAlert {
  /** Stable de-dupe id (kind + event key). */
  id: string;
  kind: TradingAlertKind;
  title: string;
  message: string;
  /** Epoch ms for ordering + relative-time render. */
  ts: number;
  read: boolean;
}

/** Cap the retained list so a busy account never grows unbounded. */
const MAX_ALERTS = 50;
const LS_ALERTS = "tl.tradingAlerts.v1";
const LS_SEEN = "tl.tradingAlerts.seen.v1";

/** Per-feed high-water marks (the newest event key we have already alerted on). */
interface SeenMarkers {
  /** newest fill ts seen. */
  fillTs?: number;
  /** newest liquidation ts seen. */
  liqTs?: number;
  /** newest funding ts seen. */
  fundingTs?: number;
  /** newest PM-resolution ts seen. */
  pmTs?: number;
  /** last margin distress snapshot: [is_liquidating, distress_level]. */
  marginLiquidating?: number;
  marginDistress?: number;
  /** whether each feed has been primed with a first fetch (so we seed silently). */
  fillPrimed?: boolean;
  liqPrimed?: boolean;
  fundingPrimed?: boolean;
  pmPrimed?: boolean;
  marginPrimed?: boolean;
}

function loadJson<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return fallback;
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function saveJson(key: string, value: unknown): void {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* quota / private-mode — alerts degrade to in-memory only */
  }
}

/** Timestamps in these feeds may be seconds OR ms — normalize to ms. */
function toMs(ts: number | undefined): number {
  if (ts == null || !Number.isFinite(ts)) return 0;
  // < 1e12 => seconds; otherwise already ms (ns would be >> 1e15 but the feeds use s/ms).
  return ts < 1e12 ? Math.floor(ts * 1000) : Math.floor(ts);
}

/** Relative "3m ago" / "just now" from an epoch-ms timestamp. */
export function relativeTime(ts: number, now = Date.now()): string {
  const s = Math.max(0, Math.floor((now - ts) / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

interface DeriveContext {
  symbolName: (id: number | undefined) => string;
  scalerFor: (id: number | undefined) => number;
}

/** Build a symbol-id -> display-name + price_scaler lookup from /md/symbols. */
function useSymbolLookup(): DeriveContext {
  const { data } = useSymbols();
  return React.useMemo(() => {
    const byId = new Map<number, MarketSymbol>();
    for (const s of data?.symbols ?? []) byId.set(s.symbol_id, s);
    return {
      symbolName: (id) =>
        (id != null && byId.get(id)?.symbol) || (id != null ? `#${id}` : "?"),
      scalerFor: (id) => (id != null && byId.get(id)?.price_scaler) || 1,
    };
  }, [data]);
}

/**
 * Subscribe to the trader feeds and surface NEW events as alerts.
 * Returns the alert list + unread count + read/clear controls for a bell UI.
 */
export function useTradingAlerts(enabled = true) {
  const fills = useFillsFees(enabled);
  const liquidations = useLiquidations(enabled);
  const funding = useFundingPayments(enabled);
  const margin = useMarginAccount(enabled);
  const pm = usePmResolutions(enabled);
  const ctx = useSymbolLookup();

  const [alerts, setAlerts] = React.useState<TradingAlert[]>(() =>
    loadJson<TradingAlert[]>(LS_ALERTS, []),
  );
  const seenRef = React.useRef<SeenMarkers>(loadJson<SeenMarkers>(LS_SEEN, {}));

  // Per-kind alert preferences (Settings > Trading). Missing = enabled.
  const [alertPrefs, setAlertPrefs] = React.useState<AlertPrefs>(() => loadAlertPrefs());
  const prefsRef = React.useRef(alertPrefs);
  prefsRef.current = alertPrefs;
  React.useEffect(() => {
    const reload = () => setAlertPrefs(loadAlertPrefs());
    // Cross-tab changes fire "storage"; same-tab Settings edits fire a custom event.
    const onStorage = (e: StorageEvent) => {
      if (e.key === ALERT_PREFS_KEY || e.key === null) reload();
    };
    window.addEventListener("storage", onStorage);
    window.addEventListener("tl:alertPrefsChanged", reload);
    return () => {
      window.removeEventListener("storage", onStorage);
      window.removeEventListener("tl:alertPrefsChanged", reload);
    };
  }, []);

  // Persist alerts whenever they change.
  React.useEffect(() => {
    saveJson(LS_ALERTS, alerts.slice(0, MAX_ALERTS));
  }, [alerts]);

  const pushAlerts = React.useCallback(
    (incoming: Omit<TradingAlert, "read">[], primed: boolean) => {
      if (incoming.length === 0) return;
      const prefs = prefsRef.current;
      setAlerts((prev) => {
        const have = new Set(prev.map((a) => a.id));
        // Suppress alert kinds the user disabled in Settings > Trading.
        const fresh = incoming.filter((a) => !have.has(a.id) && prefs[a.kind] !== false);
        if (fresh.length === 0) return prev;
        // Only toast once the feed is primed (not on the seeding first fetch).
        if (primed) {
          for (const a of fresh) {
            toast(a.title, { description: a.message });
            // Surface as an OS notification too (no-op unless permission granted).
            notify(a.title, a.message);
          }
        }
        const merged = [
          ...fresh.map((a) => ({ ...a, read: false })),
          ...prev,
        ]
          .sort((x, y) => y.ts - x.ts)
          .slice(0, MAX_ALERTS);
        return merged;
      });
    },
    [],
  );

  const persistSeen = React.useCallback(() => saveJson(LS_SEEN, seenRef.current), []);

  // ── Fills ──────────────────────────────────────────────────────────
  React.useEffect(() => {
    const rows: FillFee[] | undefined = fills.data?.fills;
    if (!rows) return;
    const seen = seenRef.current;
    const prevMark = seen.fillTs ?? 0;
    const primed = seen.fillPrimed === true;
    const newer = rows.filter((r) => toMs(r.ts) > prevMark);
    let maxTs = prevMark;
    const built = newer.map((r) => {
      const ms = toMs(r.ts);
      if (ms > maxTs) maxTs = ms;
      const sym = ctx.symbolName(r.symbolid);
      const sc = ctx.scalerFor(r.symbolid);
      return {
        id: `fill:${r.symbolid}:${r.ts}:${r.price}:${r.qty}:${r.side}`,
        kind: "fill" as const,
        title: `Filled: ${sym}`,
        message: `${r.side?.toUpperCase() ?? ""} ${formatQty(r.qty, sc)} @ ${formatPrice(r.price, sc)}`.trim(),
        ts: ms || Date.now(),
      };
    });
    pushAlerts(built, primed);
    seen.fillTs = maxTs;
    seen.fillPrimed = true;
    persistSeen();
  }, [fills.data, ctx, pushAlerts, persistSeen]);

  // ── Liquidations ───────────────────────────────────────────────────
  React.useEffect(() => {
    const rows: Liquidation[] | undefined = liquidations.data?.liquidations;
    if (!rows) return;
    const seen = seenRef.current;
    const prevMark = seen.liqTs ?? 0;
    const primed = seen.liqPrimed === true;
    let maxTs = prevMark;
    const built = rows
      .filter((r) => toMs(r.ts) > prevMark)
      .map((r) => {
        const ms = toMs(r.ts);
        if (ms > maxTs) maxTs = ms;
        const sym = ctx.symbolName(r.symbolid);
        const sc = ctx.scalerFor(r.symbolid);
        return {
          id: `liq:${r.symbolid}:${r.ts}:${r.qty}`,
          kind: "liquidation" as const,
          title: `Liquidated ${sym}`,
          message: `${formatQty(r.qty, sc)} closed @ ${formatPrice(r.mark_price, sc)} · PnL ${formatPrice(r.realized_pnl, sc)}`,
          ts: ms || Date.now(),
        };
      });
    pushAlerts(built, primed);
    seen.liqTs = maxTs;
    seen.liqPrimed = true;
    persistSeen();
  }, [liquidations.data, ctx, pushAlerts, persistSeen]);

  // ── Funding settlements ────────────────────────────────────────────
  React.useEffect(() => {
    const rows: FundingPayment[] | undefined = funding.data?.funding;
    if (!rows) return;
    const seen = seenRef.current;
    const prevMark = seen.fundingTs ?? 0;
    const primed = seen.fundingPrimed === true;
    let maxTs = prevMark;
    const built = rows
      .filter((r) => toMs(r.ts) > prevMark)
      .map((r) => {
        const ms = toMs(r.ts);
        if (ms > maxTs) maxTs = ms;
        const sym = ctx.symbolName(r.symbolid);
        const sc = ctx.scalerFor(r.symbolid);
        const dir = r.received ? "received" : "paid";
        const amt = formatPrice(Math.abs(r.payment), sc);
        return {
          id: `funding:${r.symbolid}:${r.ts}:${r.payment}`,
          kind: "funding" as const,
          title: `Funding: ${dir} ${amt}`,
          message: `${sym} · ${r.funding_rate_bps} bps`,
          ts: ms || Date.now(),
        };
      });
    pushAlerts(built, primed);
    seen.fundingTs = maxTs;
    seen.fundingPrimed = true;
    persistSeen();
  }, [funding.data, ctx, pushAlerts, persistSeen]);

  // ── Margin distress ────────────────────────────────────────────────
  // Fires when is_liquidating turns on, or distress_level RISES above the last snapshot.
  React.useEffect(() => {
    const acct: MarginAccount | undefined = margin.data;
    if (!acct) return;
    const seen = seenRef.current;
    const primed = seen.marginPrimed === true;
    const isLiq = acct.is_liquidating ? 1 : 0;
    const distress = acct.distress_level ?? 0;
    const prevLiq = seen.marginLiquidating ?? 0;
    const prevDistress = seen.marginDistress ?? 0;

    if (primed) {
      const turnedLiquidating = isLiq === 1 && prevLiq === 0;
      const distressRose = distress > prevDistress && distress > 0;
      if (turnedLiquidating || distressRose) {
        const now = Date.now();
        pushAlerts(
          [
            {
              id: `margin:${isLiq ? "liq" : "distress"}:${distress}:${Math.floor(now / 60000)}`,
              kind: "margin",
              title: isLiq ? "Margin: liquidating" : "Margin distress",
              message: isLiq
                ? "Your account is being liquidated"
                : `Distress level ${distress} — add margin to avoid liquidation`,
              ts: now,
            },
          ],
          true,
        );
      }
    }
    seen.marginLiquidating = isLiq;
    seen.marginDistress = distress;
    seen.marginPrimed = true;
    persistSeen();
  }, [margin.data, pushAlerts, persistSeen]);

  // ── PM resolutions ─────────────────────────────────────────────────
  React.useEffect(() => {
    const rows: PmResolution[] | undefined = pm.data?.resolutions;
    if (!rows) return;
    const seen = seenRef.current;
    const prevMark = seen.pmTs ?? 0;
    const primed = seen.pmPrimed === true;
    let maxTs = prevMark;
    const built = rows
      .filter((r) => toMs(r.ts) > prevMark)
      .map((r) => {
        const ms = toMs(r.ts);
        if (ms > maxTs) maxTs = ms;
        const sym = ctx.symbolName(r.winning_symbolid ?? r.symbolid);
        const outcome = (r.outcome ?? "").toString().toUpperCase();
        const label = outcome === "YES" || outcome === "NO" ? outcome : outcome || "resolved";
        return {
          id: `pm:${r.symbolid ?? r.group_id ?? "x"}:${r.ts}:${r.winning_symbolid ?? r.outcome ?? ""}`,
          kind: "pm_resolved" as const,
          title: `Market resolved ${label}`,
          message: r.group_id != null ? `${sym} won` : `${sym} settled`,
          ts: ms || Date.now(),
        };
      });
    pushAlerts(built, primed);
    seen.pmTs = maxTs;
    seen.pmPrimed = true;
    persistSeen();
  }, [pm.data, ctx, pushAlerts, persistSeen]);

  // ── Read / clear controls ──────────────────────────────────────────
  const unreadCount = React.useMemo(
    () => alerts.reduce((n, a) => (a.read ? n : n + 1), 0),
    [alerts],
  );

  const markAllRead = React.useCallback(() => {
    setAlerts((prev) => (prev.every((a) => a.read) ? prev : prev.map((a) => ({ ...a, read: true }))));
  }, []);

  const markRead = React.useCallback((id: string) => {
    setAlerts((prev) => prev.map((a) => (a.id === id ? { ...a, read: true } : a)));
  }, []);

  const clearAll = React.useCallback(() => {
    setAlerts([]);
  }, []);

  return { alerts, unreadCount, markAllRead, markRead, clearAll };
}
