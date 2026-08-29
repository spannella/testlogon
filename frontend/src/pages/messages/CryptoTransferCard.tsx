import { ArrowDownLeft, ArrowUpRight, Check, Clock, X } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import {
  amountLabel,
  badgeVariant,
  formatFiatCents,
  statusLabel,
  type CryptoTransferPayload,
} from "@/lib/cryptoTransfer";

export interface CryptoTransferCardProps {
  payload: CryptoTransferPayload;
  /** True when the CURRENT viewer is the sender (drives directional styling). */
  sent: boolean;
  /** Counterparty display name (recipient when sent, sender when received). */
  counterpartyName?: string;
}

/**
 * FE-111: an in-chat crypto-transfer card. Asset + amount (+ fiat), from→to,
 * a status badge (pending/complete/failed) and directional styling driven by
 * whether the current viewer is the sender. Pure presentation — all derivation
 * lives in lib/cryptoTransfer.
 */
export function CryptoTransferCard({ payload, sent, counterpartyName }: CryptoTransferCardProps) {
  const variant = badgeVariant(payload.status);
  const label = statusLabel(payload.status);

  const StatusIcon = variant === "success" ? Check : variant === "danger" ? X : Clock;

  return (
    <Card
      className={cn(
        "w-72 max-w-full border-l-4",
        sent ? "border-l-sky-500" : "border-l-emerald-500",
      )}
      data-testid="crypto-transfer-card"
      data-direction={sent ? "sent" : "received"}
    >
      <CardContent className="pt-4">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-1.5 text-sm font-semibold">
            {sent ? (
              <ArrowUpRight className="h-4 w-4 shrink-0 text-sky-600 dark:text-sky-400" />
            ) : (
              <ArrowDownLeft className="h-4 w-4 shrink-0 text-emerald-600 dark:text-emerald-400" />
            )}
            <span data-testid="crypto-transfer-direction">
              {sent ? "Sent crypto" : "Received crypto"}
            </span>
          </div>
          <span
            className={cn(
              "inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium",
              variant === "success" &&
                "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
              variant === "danger" && "bg-rose-500/15 text-rose-700 dark:text-rose-400",
              variant === "pending" && "bg-amber-500/15 text-amber-700 dark:text-amber-400",
            )}
            data-testid="crypto-transfer-status"
          >
            <StatusIcon className="h-3 w-3" />
            {label}
          </span>
        </div>

        <div className="mt-2">
          <div
            className="text-2xl font-bold tabular-nums"
            data-testid="crypto-transfer-amount"
          >
            {amountLabel(payload.amount, payload.asset)}
          </div>
          {payload.fiat_cents != null && (
            <div
              className="text-xs text-muted-foreground tabular-nums"
              data-testid="crypto-transfer-fiat"
            >
              ≈ {formatFiatCents(payload.fiat_cents)}
            </div>
          )}
        </div>

        {counterpartyName && (
          <p
            className="mt-2 text-[11px] text-muted-foreground"
            data-testid="crypto-transfer-party"
          >
            {sent ? "To" : "From"} {counterpartyName}
          </p>
        )}
      </CardContent>
    </Card>
  );
}

export default CryptoTransferCard;
