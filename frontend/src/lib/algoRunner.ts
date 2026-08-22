// Client-side ALGO RUNNER hook. Mounted once by the trade ticket for the current
// symbol; it drives every RUNNING TWAP / Iceberg algo for that symbol by placing
// child orders on a timer (TWAP) or on-fill (Iceberg) through the SAME submit
// primitives the ticket uses. Paper-mode algos route children to the local paper
// engine; live algos go through the real place-order mutation.
//
// Algos run ONLY while this hook is mounted (i.e. the tab/ticket is open). On
// unmount every timer is torn down — no orphaned timers. Pausing/cancelling an
// algo (via the store) stops it scheduling further children on the next tick.

import { useEffect, useRef } from "react";
import {
  loadAlgos,
  saveAlgos,
  filledQty,
  isComplete,
  nextPending,
  type AlgoOrder,
  type AlgoChild,
} from "./algoStore";
import {
  placeOrder as placePaperOrder,
  type PaperAccount,
} from "./paperEngine";
import { selectMarketPrice } from "./paperMode";

export interface AlgoRunnerQuotes {
  bestBid?: number;
  bestAsk?: number;
  lastPrice?: number;
}

export interface AlgoRunnerDeps {
  symbolId: number;
  quotes: AlgoRunnerQuotes;
  /** Route a LIVE child order; resolves true when the child is considered filled. */
  placeLiveChild: (args: {
    side: "buy" | "sell";
    type: "market" | "limit";
    price?: number;
    qty: number;
  }) => Promise<{ filled: boolean; fillPrice?: number }>;
  /** Latest paper account (source of truth for paper children). */
  paperAccount: PaperAccount;
  /** Commit a mutated paper account (persist + local state). */
  commitPaper: (acct: PaperAccount) => void;
  /** Called after any algo state mutation so the UI can refresh a status line. */
  onProgress?: () => void;
}

/**
 * Persist a single algo mutation back to the store (re-reading first so we never
 * clobber concurrent changes from another algo / the monitor page).
 */
function commitAlgo(next: AlgoOrder): void {
  const list = loadAlgos().map((a) => (a.id === next.id ? { ...next, updatedAt: Date.now() } : a));
  saveAlgos(list);
}

export function useAlgoRunner(deps: AlgoRunnerDeps): void {
  // Keep the latest deps in a ref so the single interval always sees fresh
  // quotes / account without re-subscribing (which would churn timers).
  const ref = useRef(deps);
  ref.current = deps;
  // Guards so we never double-fire a child while a placement is in flight.
  const inFlight = useRef<Set<string>>(new Set());

  useEffect(() => {
    let cancelled = false;

    async function tick() {
      const { symbolId, quotes, paperAccount, commitPaper, placeLiveChild, onProgress } =
        ref.current;
      const now = Date.now();
      const running = loadAlgos().filter(
        (a) => a.status === "running" && a.symbolId === symbolId,
      );
      for (const algo of running) {
        const key = algo.id;
        if (inFlight.current.has(key)) continue;

        // Complete → mark done.
        if (isComplete(algo)) {
          commitAlgo({ ...algo, status: "done" });
          onProgress?.();
          continue;
        }

        const child = nextPending(algo);
        if (!child) {
          // No pending child but not complete (all placed, awaiting fill) — skip.
          continue;
        }

        if (algo.kind === "twap") {
          // Fire only when the slice's scheduled time has arrived.
          if (child.atMs != null && child.atMs > now) continue;
        } else {
          // Iceberg: only place the next clip once the prior placed clip filled.
          const anyPlacedUnfilled = algo.children.some((c) => c.status === "placed");
          if (anyPlacedUnfilled) continue;
        }

        inFlight.current.add(key);
        try {
          if (algo.paper) {
            const marketPrice = selectMarketPrice(algo.side, {
              bestBid: quotes.bestBid,
              bestAsk: quotes.bestAsk,
              lastPrice: quotes.lastPrice,
              refPrice: algo.limitPrice,
            });
            const { account, fill } = placePaperOrder(
              paperAccount,
              {
                symbolId: algo.symbolId,
                side: algo.side,
                type: algo.childType,
                price: algo.childType === "limit" ? algo.limitPrice : undefined,
                qty: child.qty,
              },
              marketPrice,
            );
            commitPaper(account);
            // Paper children that don't immediately fill (resting limit) are
            // still marked placed; onTick elsewhere would fill them, but for the
            // algo's accounting we advance on the immediate fill only.
            const updatedChild: AlgoChild = fill
              ? { ...child, status: "filled", fillPrice: fill.price, placedAt: now, filledAt: now }
              : { ...child, status: "placed", placedAt: now };
            const fresh = loadAlgos().find((a) => a.id === algo.id);
            if (fresh) {
              const children = fresh.children.map((c) =>
                c.seq === child.seq ? updatedChild : c,
              );
              const withChildren: AlgoOrder = { ...fresh, children };
              commitAlgo(
                isComplete(withChildren) ? { ...withChildren, status: "done" } : withChildren,
              );
            }
          } else {
            const res = await placeLiveChild({
              side: algo.side,
              type: algo.childType,
              price: algo.childType === "limit" ? algo.limitPrice : undefined,
              qty: child.qty,
            });
            if (cancelled) return;
            const updatedChild: AlgoChild = res.filled
              ? { ...child, status: "filled", fillPrice: res.fillPrice, placedAt: now, filledAt: Date.now() }
              : { ...child, status: "placed", placedAt: now };
            const fresh = loadAlgos().find((a) => a.id === algo.id);
            if (fresh) {
              const children = fresh.children.map((c) =>
                c.seq === child.seq ? updatedChild : c,
              );
              const withChildren: AlgoOrder = { ...fresh, children };
              commitAlgo(
                isComplete(withChildren) ? { ...withChildren, status: "done" } : withChildren,
              );
            }
          }
          onProgress?.();
        } catch {
          // Placement failed — leave the child pending; it retries next tick.
        } finally {
          inFlight.current.delete(key);
        }
      }
    }

    // Poll on a short cadence; TWAP timing is enforced per-slice via atMs so a
    // 1s tick is plenty and keeps the countdown display live.
    const id = window.setInterval(() => {
      void tick();
    }, 1000);
    // Fire once immediately so a just-created algo places its first slice.
    void tick();

    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
    // Re-mount the loop only when the symbol changes; deps ride the ref.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deps.symbolId]);
}

/** Total filled ticks for a live algo (re-export convenience). */
export { filledQty };
