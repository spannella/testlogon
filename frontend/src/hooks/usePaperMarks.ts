// Live-mark assembly for the shared PAPER account. Given the account's open
// positions + working orders, this resolves a `marks` map (symbolId -> last
// trade price) by reusing the SAME market-data feed the rest of the app uses
// (GET /md/trades/{id} via getTrades) — it does NOT invent a new fetch. One
// query per distinct symbol touched by the account; each polls on the live 2s
// interval and degrades to `undefined` (no mark) when its feed is missing.
//
// Also exposes a symbolId -> display-name resolver from the /md/symbols catalog,
// and re-reads the persisted paper account on the same-tab PAPER_MODE_EVENT and
// the cross-tab `storage` event so the views stay in sync with the trade ticket.
import { useEffect, useMemo, useState } from "react";
import { useQueries } from "@tanstack/react-query";
import { getTrades } from "@/api/endpoints/marketData";
import { useSymbols } from "@/hooks/useMarketData";
import { loadAccount } from "@/lib/paperStore";
import { PAPER_MODE_EVENT } from "@/lib/paperMode";
import type { PaperAccount } from "@/lib/paperEngine";
import type { PaperMarks, SymName } from "@/lib/paperBlotter";

const LIVE_REFETCH_MS = 2000;

/**
 * Load the persisted paper account and keep it in sync with the trade ticket /
 * Paper page: re-reads on PAPER_MODE_EVENT (same tab) + `storage` (cross tab),
 * and on a light interval so live fills from the ticket surface here too.
 */
export function usePaperAccount(enabled: boolean): PaperAccount {
  const [acct, setAcct] = useState<PaperAccount>(() => loadAccount());
  useEffect(() => {
    if (!enabled) return;
    const reload = () => setAcct(loadAccount());
    reload();
    window.addEventListener("storage", reload);
    window.addEventListener(PAPER_MODE_EVENT, reload);
    // localStorage writes from the same tab (trade ticket / onTick) don't fire
    // `storage`, so poll lightly to pick those up.
    const id = window.setInterval(reload, LIVE_REFETCH_MS);
    return () => {
      window.removeEventListener("storage", reload);
      window.removeEventListener(PAPER_MODE_EVENT, reload);
      window.clearInterval(id);
    };
  }, [enabled]);
  return acct;
}

/** Distinct symbolIds the account has any exposure or resting order in. */
export function accountSymbolIds(acct: PaperAccount): number[] {
  const ids = new Set<number>();
  for (const k of Object.keys(acct.positions)) ids.add(Number(k));
  for (const o of acct.orders) if (o.status === "working") ids.add(o.symbolId);
  return [...ids].sort((a, b) => a - b);
}

export interface PaperMarksResult {
  marks: PaperMarks;
  symName: SymName;
}

/**
 * Assemble a live marks map for every symbol the account touches, plus a
 * symbolId -> name resolver. `enabled=false` (paper mode OFF) issues no queries.
 */
export function usePaperMarks(acct: PaperAccount, enabled: boolean): PaperMarksResult {
  const symbolsQ = useSymbols();
  const symName = useMemo<SymName>(() => {
    const byId = new Map<number, string>();
    for (const s of symbolsQ.data?.symbols ?? []) byId.set(s.symbol_id, s.symbol);
    return (id: number) => byId.get(id) ?? `#${id}`;
  }, [symbolsQ.data]);

  const ids = useMemo(() => accountSymbolIds(acct), [acct]);

  const results = useQueries({
    queries: ids.map((id) => ({
      queryKey: ["md", "trades", id] as const,
      queryFn: () => getTrades(id),
      enabled: enabled && Number.isFinite(id) && id > 0,
      refetchInterval: LIVE_REFETCH_MS,
      staleTime: LIVE_REFETCH_MS,
    })),
  });

  const marks = useMemo<PaperMarks>(() => {
    const m: PaperMarks = {};
    ids.forEach((id, i) => {
      const px = results[i]?.data?.trades?.[0]?.price;
      m[id] = px != null && Number.isFinite(px) && px > 0 ? px : undefined;
    });
    return m;
    // results identity changes each poll; key off the mapped prices instead.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ids, results.map((r) => r.data?.trades?.[0]?.price).join(",")]);

  return { marks, symName };
}
