import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  disposeAsset,
  type FixedAsset,
} from "@/api/endpoints/fixedAssets";
import { dollarsToCents, fmtCents } from "./lib";

interface Props {
  asset: FixedAsset;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onDisposed: () => void;
}

export function DisposalForm({ asset, open, onOpenChange, onDisposed }: Props) {
  const [reason, setReason] = useState("");
  const [proceeds, setProceeds] = useState("");
  const [paymentIntent, setPaymentIntent] = useState("");

  const proceedsCents = dollarsToCents(proceeds);
  const nbv = asset.net_book_value_cents;
  const gainLoss = proceedsCents - nbv;

  const disposeMut = useMutation({
    mutationFn: () =>
      disposeAsset(asset.asset_id, {
        disposal_reason: reason.trim() || undefined,
        proceeds_amount_cents: proceeds ? proceedsCents : undefined,
        proceeds_payment_intent_id: paymentIntent.trim() || undefined,
      }),
    onSuccess: () => {
      onOpenChange(false);
      setReason("");
      setProceeds("");
      setPaymentIntent("");
      onDisposed();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to dispose asset"),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Dispose asset</DialogTitle>
          <DialogDescription>
            Disposing posts a closing journal entry and cancels remaining depreciation periods.
            This cannot be undone.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div className="rounded-md border bg-muted/40 p-3 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Net book value</span>
              <span className="font-medium tabular-nums">{fmtCents(nbv)}</span>
            </div>
            {proceeds && (
              <div className="mt-1 flex justify-between">
                <span className="text-muted-foreground">
                  Projected {gainLoss >= 0 ? "gain" : "loss"} on disposal
                </span>
                <span
                  className={
                    "font-medium tabular-nums " +
                    (gainLoss >= 0 ? "text-emerald-600" : "text-destructive")
                  }
                >
                  {fmtCents(Math.abs(gainLoss))}
                </span>
              </div>
            )}
          </div>
          <div className="grid gap-2">
            <Label htmlFor="dispose-reason">Disposal reason</Label>
            <Textarea
              id="dispose-reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Sold / scrapped / written off…"
              rows={2}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="dispose-proceeds">Proceeds ($)</Label>
            <Input
              id="dispose-proceeds"
              value={proceeds}
              onChange={(e) => setProceeds(e.target.value)}
              placeholder="0.00"
              inputMode="decimal"
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="dispose-pi">Proceeds payment intent id (optional)</Label>
            <Input
              id="dispose-pi"
              value={paymentIntent}
              onChange={(e) => setPaymentIntent(e.target.value)}
              placeholder="pi_…"
            />
            <p className="text-xs text-muted-foreground">
              Required to route a cash receipt into the billing ledger.
            </p>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            onClick={() => disposeMut.mutate()}
            disabled={disposeMut.isPending}
          >
            {disposeMut.isPending ? "Disposing…" : "Confirm disposal"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
