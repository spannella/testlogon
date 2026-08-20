import { useEffect, useMemo, useRef, useState } from "react";
import { cn } from "@/lib/utils";
import type { Trade } from "@/api/endpoints/marketData";
import { formatPrice, formatQty, formatTimeNs } from "./format";

interface TimeSalesProps {
  trades: Trade[];
  scaler?: number;
  /** Max rows kept in the visible tape. */
  maxRows?: number;
  isLoading?: boolean;
  /** True when the trades feed is unavailable (query error). */
  unavailable?: boolean;
}

type Flash = "up" | "down" | null;

/** Stable-ish key for a trade so React reconciles rows and flashes correctly. */
function tradeKey(t: Trade): string {
  return `${t.ts_ns}:${t.price}:${t.qty}:${t.aggressor}`;
}

/**
 * Time & Sales tape: a compact, live-scrolling list of the most recent prints,
 * newest on top, colored by aggressor (buy = green, sell = red). The latest
 * print flashes briefly, tinted by whether price ticked up or down vs the
 * previous print.
 */
export default function TimeSales({
  trades,
  scaler = 1,
  maxRows = 50,
  isLoading = false,
  unavailable = false,
}: TimeSalesProps) {
  const rows = useMemo(() => trades.slice(0, maxRows), [trades, maxRows]);

  // Flash the top row when a new print arrives; tint by tick direction.
  const prevTopKey = useRef<string | null>(null);
  const prevTopPrice = useRef<number | null>(null);
  const [flash, setFlash] = useState<Flash>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const top = rows[0];
    if (!top) return;
    const key = tradeKey(top);
    if (prevTopKey.current !== null && key !== prevTopKey.current) {
      const dir: Flash =
        prevTopPrice.current == null
          ? null
          : top.price > prevTopPrice.current
            ? "up"
            : top.price < prevTopPrice.current
              ? "down"
              : null;
      setFlash(dir ?? "up");
      if (timerRef.current) clearTimeout(timerRef.current);
      timerRef.current = setTimeout(() => setFlash(null), 260);
    }
    prevTopKey.current = key;
    prevTopPrice.current = top.price;
  }, [rows]);

  useEffect(() => () => {
    if (timerRef.current) clearTimeout(timerRef.current);
  }, []);

  if (isLoading && rows.length === 0) {
    return (
      <p className="py-8 text-center text-sm text-muted-foreground">Loading tape…</p>
    );
  }
  if (unavailable) {
    return (
      <p className="py-8 text-center text-sm text-muted-foreground">
        Time &amp; sales unavailable.
      </p>
    );
  }
  if (rows.length === 0) {
    return (
      <p className="py-8 text-center text-sm text-muted-foreground">No prints yet.</p>
    );
  }

  return (
    <div>
      <div className="grid grid-cols-3 gap-2 px-2 pb-1 text-xs uppercase text-muted-foreground">
        <span>Time</span>
        <span className="text-right">Price</span>
        <span className="text-right">Qty</span>
      </div>
      <div className="max-h-72 overflow-y-auto">
        {rows.map((t, i) => {
          const isBuy = t.aggressor === "buy";
          const isTop = i === 0;
          return (
            <div
              key={tradeKey(t)}
              className={cn(
                "grid grid-cols-3 gap-2 px-2 py-0.5 text-sm tabular-nums transition-colors duration-200",
                isTop && flash === "up" && "bg-emerald-500/15",
                isTop && flash === "down" && "bg-rose-500/15"
              )}
            >
              <span className="text-muted-foreground">{formatTimeNs(t.ts_ns)}</span>
              <span
                className={cn(
                  "text-right font-medium",
                  isBuy
                    ? "text-emerald-600 dark:text-emerald-400"
                    : "text-rose-600 dark:text-rose-400"
                )}
              >
                {formatPrice(t.price, scaler)}
              </span>
              <span className="text-right text-muted-foreground">
                {formatQty(t.qty, scaler)}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
