import { api } from "@/api/client";
import type { TipsSummary, TipsSentResp, TipsSentSummary } from "@/api/types";

/**
 * TIPX-D tips measurement endpoints (ledger-backed, reconciled).
 *
 * getTipsReceivedSummary is the ONE TRUE TOTAL for a creator: NET, all 8
 * surfaces, reversed-excluded — it reconciles to the earnings tips bucket and
 * the leaderboard. getTipsSent / getTipsSentSummary are the tipper-side receipt
 * history (GROSS, what the tipper actually paid).
 */

export type TipPeriod = "7d" | "30d" | "all";

// Reads GET /ui/alerts/tips-summary — the ledger-backed summary that returns the
// TipsSummary shape the TipsFeed renders (total_tips_cents [NET], by_surface,
// unique_tippers, top_tippers). The raw /ui/tips/received projection uses
// total_net_cents/by_type field names and would render $NaN here.
export const getTipsReceivedSummary = (period: TipPeriod = "30d") =>
  api.get<TipsSummary>("/ui/alerts/tips-summary", { period });

export const getTipsSent = (opts?: { limit?: number; cursor?: string; period?: TipPeriod }) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.period) params["period"] = opts.period;
  return api.get<TipsSentResp>("/ui/tips/sent", params);
};

export const getTipsSentSummary = (period: TipPeriod = "all") =>
  api.get<TipsSentSummary>("/ui/tips/sent/summary", { period });
