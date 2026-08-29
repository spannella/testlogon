import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertCircle, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { getBalance, mergeBalances, type DisplayAsset } from "@/api/endpoints/custody";
import { usePrices } from "@/hooks/useTrading";
import {
  fiatEquivalentCents,
  formatFiatCents,
  validateSend,
  type CryptoTransferPayload,
  type ValidateReason,
} from "@/lib/cryptoTransfer";

interface CryptoSendComposerDialogProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (payload: CryptoTransferPayload) => void;
  /** Recipient (DM partner) display name for the payload attribution. */
  recipientName?: string;
  /** Sender (current user) display name for the payload attribution. */
  senderName?: string;
}

const REASON_MESSAGE: Record<ValidateReason, string> = {
  empty: "Enter an amount to send.",
  invalid: "Enter a valid amount.",
  nonpositive: "Amount must be greater than zero.",
  insufficient: "Insufficient balance for this amount.",
  below_min: "Amount is below the minimum transfer size.",
  over_max: "Amount is over the per-transfer limit.",
  kyc: "Identity verification is required before sending crypto.",
};

function num(v: number | string | undefined): number {
  const n = typeof v === "string" ? parseFloat(v) : v ?? 0;
  return Number.isFinite(n) ? (n as number) : 0;
}

/**
 * FE-110: send-crypto composer. Asset picker (from custody balances) + amount
 * with a live fiat-equivalent preview (amount × /me/prices rate) + an inline
 * balance/limit/KYC check + a confirm sheet. On confirm it emits a
 * CryptoTransferPayload; the caller POSTs to the crypto-send card endpoint and
 * degrades-on-404 to a normal `crypto_transfer` message (see messaging.ts).
 *
 * There is no account-facing custody limits/KYC read today, so limits+KYC
 * degrade to a generic informational note (validateSend still supports both so
 * the check is exercisable + unit-tested).
 */
export function CryptoSendComposerDialog({
  open,
  onClose,
  onSubmit,
  recipientName,
  senderName,
}: CryptoSendComposerDialogProps) {
  const balanceQ = useQuery({
    queryKey: ["custody", "balance", "cryptoSend"],
    queryFn: getBalance,
    enabled: open,
    retry: false,
  });
  const pricesQ = usePrices(open);

  const rows: DisplayAsset[] = useMemo(
    () => mergeBalances(balanceQ.data?.balances).filter((r) => num(r.balance) > 0 || !r.unknown),
    [balanceQ.data],
  );

  const [asset, setAsset] = useState<string>("");
  const [amount, setAmount] = useState<string>("");
  const [confirming, setConfirming] = useState(false);

  // Default the asset to the first row with a positive balance once loaded.
  useEffect(() => {
    if (!open) return;
    if (asset && rows.some((r) => r.symbol === asset)) return;
    const firstFunded = rows.find((r) => num(r.balance) > 0) ?? rows[0];
    if (firstFunded) setAsset(firstFunded.symbol);
  }, [open, rows, asset]);

  const selected = rows.find((r) => r.symbol === asset);
  const decimals = selected?.decimals ?? 18;
  const balanceStr = selected ? String(selected.balance) : "0";

  // USD cents per whole coin from /me/prices (decimal-string dollars -> cents).
  const rateCents = useMemo(() => {
    const p = pricesQ.data?.prices?.[asset] ?? pricesQ.data?.prices?.[asset?.toUpperCase()];
    if (p == null) return null;
    const dollars = parseFloat(String(p));
    return Number.isFinite(dollars) ? Math.round(dollars * 100) : null;
  }, [pricesQ.data, asset]);

  const fiatCents =
    rateCents != null && amount.trim() !== ""
      ? fiatEquivalentCents(amount, rateCents, decimals)
      : null;

  const validation = validateSend({
    amountStr: amount,
    decimals,
    balanceStr,
    // kycOk left undefined + no min/max: no account-facing read exists yet, so
    // this degrades to a generic note (below) rather than a hard gate.
  });

  // Only surface an inline error once the user has typed something.
  const showError = amount.trim() !== "" && !validation.ok;
  const errorMsg = showError && validation.reason ? REASON_MESSAGE[validation.reason] : "";

  function reset() {
    setAmount("");
    setConfirming(false);
  }
  function handleClose() {
    reset();
    onClose();
  }
  function handleContinue() {
    if (!selected || !validation.ok) return;
    setConfirming(true);
  }
  function handleConfirm() {
    if (!selected || !validation.ok) return;
    const payload: CryptoTransferPayload = {
      asset: selected.symbol,
      amount: amount.trim(),
      decimals,
      to: recipientName,
      from: senderName,
      fiat_cents: fiatCents ?? undefined,
      status: "pending",
    };
    onSubmit(payload);
    reset();
  }

  return (
    <Dialog open={open} onOpenChange={(o) => (!o ? handleClose() : undefined)}>
      <DialogContent className="max-w-md">
        {!confirming ? (
          <>
            <DialogHeader>
              <DialogTitle>Send crypto</DialogTitle>
              <DialogDescription>
                Send from your custody balance{recipientName ? ` to ${recipientName}` : ""}.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="crypto-send-asset">Asset</Label>
                <Select value={asset} onValueChange={(v) => setAsset(v)}>
                  <SelectTrigger id="crypto-send-asset" data-testid="crypto-send-asset">
                    <SelectValue placeholder="Select an asset" />
                  </SelectTrigger>
                  <SelectContent>
                    {balanceQ.isLoading ? (
                      <div className="px-2 py-1.5 text-sm text-muted-foreground">Loading…</div>
                    ) : rows.length === 0 ? (
                      <div className="px-2 py-1.5 text-sm text-muted-foreground">
                        No assets available
                      </div>
                    ) : (
                      rows.map((r) => (
                        <SelectItem key={r.symbol} value={r.symbol}>
                          {r.symbol} — {num(r.balance).toLocaleString(undefined, {
                            maximumFractionDigits: 8,
                          })}
                        </SelectItem>
                      ))
                    )}
                  </SelectContent>
                </Select>
                {selected && (
                  <p className="text-xs text-muted-foreground" data-testid="crypto-send-balance">
                    Balance: {num(selected.balance).toLocaleString(undefined, { maximumFractionDigits: 8 })}{" "}
                    {selected.symbol}
                  </p>
                )}
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="crypto-send-amount">Amount</Label>
                <Input
                  id="crypto-send-amount"
                  inputMode="decimal"
                  placeholder="0.0"
                  value={amount}
                  onChange={(e) => setAmount(e.target.value)}
                  data-testid="crypto-send-amount"
                  aria-invalid={showError}
                />
                <p className="text-xs text-muted-foreground" data-testid="crypto-send-fiat">
                  {fiatCents != null
                    ? `≈ ${formatFiatCents(fiatCents)}`
                    : pricesQ.isError
                      ? "USD price unavailable"
                      : " "}
                </p>
              </div>

              {showError && (
                <p
                  className="flex items-center gap-1.5 text-sm text-rose-600 dark:text-rose-400"
                  data-testid="crypto-send-error"
                >
                  <AlertCircle className="h-4 w-4 shrink-0" />
                  {errorMsg}
                </p>
              )}

              <p
                className="flex items-start gap-1.5 rounded-md bg-muted/50 p-2 text-[11px] text-muted-foreground"
                data-testid="crypto-send-note"
              >
                <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                Transfers may be subject to identity verification and per-transfer
                limits. Large or restricted transfers can require additional review.
              </p>
            </div>

            <DialogFooter>
              <Button variant="outline" onClick={handleClose}>
                Cancel
              </Button>
              <Button
                onClick={handleContinue}
                disabled={!selected || !validation.ok}
                data-testid="crypto-send-continue"
              >
                Review
              </Button>
            </DialogFooter>
          </>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle>Confirm transfer</DialogTitle>
              <DialogDescription>
                Review the details before sending.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-2 rounded-lg border p-3 text-sm" data-testid="crypto-send-confirm">
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Amount</span>
                <span className="font-semibold tabular-nums">
                  {amount.trim()} {selected?.symbol}
                </span>
              </div>
              {fiatCents != null && (
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Value</span>
                  <span className="tabular-nums">≈ {formatFiatCents(fiatCents)}</span>
                </div>
              )}
              {recipientName && (
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">To</span>
                  <span className="font-medium">{recipientName}</span>
                </div>
              )}
            </div>

            <DialogFooter>
              <Button variant="outline" onClick={() => setConfirming(false)}>
                Back
              </Button>
              <Button onClick={handleConfirm} data-testid="crypto-send-confirm-send">
                Send {amount.trim()} {selected?.symbol}
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

export default CryptoSendComposerDialog;
