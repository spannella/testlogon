import { Gift, Receipt, ThumbsUp, ShoppingBag } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import {
  formatPriceCents,
  orderModeLabel,
  type OrderCardPayload,
} from "@/lib/ecomCards";

export interface OrderShareCardProps {
  payload: OrderCardPayload;
}

/**
 * FE-151: an in-chat order/purchase-share card. Item summary + status + (for
 * gift/recommendation) the amount. In "receipt" mode NO buyer PII and NO money
 * total are shown -- and the payload itself never carries PII (enforced upstream
 * in lib/ecomCards.buildOrderCardPayload). Pure presentation.
 */
export function OrderShareCard({ payload }: OrderShareCardProps) {
  const ModeIcon =
    payload.mode === "gift"
      ? Gift
      : payload.mode === "recommendation"
        ? ThumbsUp
        : payload.mode === "receipt"
          ? Receipt
          : ShoppingBag;

  const showAmount = payload.mode !== "receipt" && payload.amount_cents != null;

  return (
    <Card className="w-72 max-w-full" data-testid="order-share-card" data-mode={payload.mode}>
      <CardContent className="pt-4">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-1.5 text-sm font-semibold">
            <ModeIcon className="h-4 w-4 shrink-0 text-muted-foreground" />
            <span data-testid="order-share-mode">{orderModeLabel(payload.mode)}</span>
          </div>
          <span
            className="inline-flex items-center rounded-full bg-muted px-2 py-0.5 text-[11px] font-medium capitalize text-muted-foreground"
            data-testid="order-share-status"
          >
            {String(payload.status).replace(/_/g, " ")}
          </span>
        </div>

        <ul className="mt-2 space-y-0.5" data-testid="order-share-items">
          {payload.items.length === 0 ? (
            <li className="text-xs text-muted-foreground">
              {payload.item_count} item{payload.item_count === 1 ? "" : "s"}
            </li>
          ) : (
            payload.items.slice(0, 4).map((it, i) => (
              <li key={i} className="flex items-center justify-between gap-2 text-sm">
                <span className="min-w-0 truncate">{it.name}</span>
                <span className="shrink-0 text-xs text-muted-foreground tabular-nums">
                  ×{it.quantity}
                </span>
              </li>
            ))
          )}
          {payload.items.length > 4 && (
            <li className="text-xs text-muted-foreground">
              +{payload.items.length - 4} more
            </li>
          )}
        </ul>

        {showAmount && (
          <div
            className="mt-2 text-right text-sm font-semibold tabular-nums"
            data-testid="order-share-amount"
          >
            {formatPriceCents(payload.amount_cents, payload.currency)}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default OrderShareCard;
