import { useNavigate } from "react-router-dom";
import { Activity, ArrowUpRight, ArrowDownRight } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { formatPrice } from "@/pages/markets/format";
import type { PositionCardPayload } from "@/lib/tradingCards";

export interface PositionCardProps {
  payload: PositionCardPayload;
  /** Display name of the position owner (attribution). */
  ownerName?: string;
}

/**
 * FE-102: an in-chat position/P&L card. Renders EXACTLY the fields permitted by
 * the payload's disclosure level (the composer already stripped the rest via
 * buildPositionCardPayload). Directional P&L color + "shared by <owner>".
 */
export function PositionCard({ payload, ownerName }: PositionCardProps) {
  const navigate = useNavigate();
  const scaler = payload.price_scaler || 1;
  const roi = payload.roi_pct;
  const up = roi >= 0;
  const isFull = payload.disclosure === "full";
  const isLong = payload.side === "Long";

  const metricLabel = payload.disclosure === "roi" ? "ROI" : "P&L";

  return (
    <Card className="w-72 max-w-full" data-testid="position-card">
      <CardContent className="pt-4">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-1.5 text-sm font-semibold">
            <Activity className="h-4 w-4 shrink-0 text-muted-foreground" />
            <span className="truncate" data-testid="position-card-ticker">
              {payload.symbol}
            </span>
          </div>
          <span
            className={
              "inline-flex items-center gap-0.5 rounded-full px-2 py-0.5 text-xs font-medium " +
              (isLong
                ? "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400"
                : "bg-rose-500/15 text-rose-700 dark:text-rose-400")
            }
            data-testid="position-card-side"
          >
            {isLong ? <ArrowUpRight className="h-3 w-3" /> : <ArrowDownRight className="h-3 w-3" />}
            {payload.side}
          </span>
        </div>

        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-xs text-muted-foreground">{metricLabel}</span>
          <span
            className={
              "text-2xl font-bold tabular-nums " +
              (up
                ? "text-emerald-600 dark:text-emerald-400"
                : "text-rose-600 dark:text-rose-400")
            }
            data-testid="position-card-roi"
          >
            {up ? "+" : ""}
            {roi.toFixed(2)}%
          </span>
        </div>

        {isFull && (
          <div
            className="mt-2 grid grid-cols-3 gap-2 text-xs"
            data-testid="position-card-full-metrics"
          >
            <div>
              <div className="text-muted-foreground">Entry</div>
              <div className="tabular-nums font-medium">
                {payload.entry != null ? formatPrice(payload.entry, scaler) : "—"}
              </div>
            </div>
            <div>
              <div className="text-muted-foreground">Mark</div>
              <div className="tabular-nums font-medium">
                {payload.mark != null ? formatPrice(payload.mark, scaler) : "—"}
              </div>
            </div>
            <div>
              <div className="text-muted-foreground">Size</div>
              <div className="tabular-nums font-medium">
                {payload.size != null ? payload.size : "—"}
              </div>
            </div>
          </div>
        )}

        {ownerName && (
          <p
            className="mt-2 text-[11px] text-muted-foreground"
            data-testid="position-card-owner"
          >
            Shared by {ownerName}
          </p>
        )}

        <Button
          size="sm"
          variant="outline"
          className="mt-3 w-full"
          onClick={() => navigate(`/markets/${payload.symbol_id}`)}
          data-testid="position-card-trade"
        >
          View market
        </Button>
      </CardContent>
    </Card>
  );
}

export default PositionCard;
