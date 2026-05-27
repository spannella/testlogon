import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { submitRefundRequest } from "@/api/endpoints/refundRequests";
import type { LedgerEntry } from "@/api/types";

interface Props {
  transaction: LedgerEntry | null;
  onClose: () => void;
}

function formatCents(cents: number): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
  }).format(cents / 100);
}

export function RefundRequestDialog({ transaction, onClose }: Props) {
  const [reason, setReason] = useState("");
  const [partialAmount, setPartialAmount] = useState("");
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: submitRefundRequest,
    onSuccess: () => {
      toast.success("Refund request submitted. You will be notified when it is reviewed.");
      queryClient.invalidateQueries({ queryKey: ["refunds", "my-requests"] });
      onClose();
      setReason("");
      setPartialAmount("");
    },
    onError: (err: Error & { response?: { data?: { detail?: string } } }) => {
      const detail = err?.response?.data?.detail || err.message || "Failed to submit refund request";
      toast.error(String(detail));
    },
  });

  if (!transaction) return null;

  const entryId = (transaction as Record<string, unknown>).entry_id as string | undefined;

  const handleSubmit = () => {
    if (!entryId) return;
    const amountVal = partialAmount.trim() ? Math.round(parseFloat(partialAmount) * 100) : undefined;
    mutation.mutate({
      transaction_entry_id: entryId,
      reason,
      amount_cents: amountVal,
    });
  };

  return (
    <Dialog open={!!transaction} onOpenChange={(open) => { if (!open) onClose(); }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Request Refund</DialogTitle>
          <DialogDescription>
            Submit a refund request for this transaction. An admin will review it.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <div className="rounded-md border p-3 text-sm space-y-1">
            <p><span className="font-medium">Type:</span> {transaction.type?.replace(/_/g, " ")}</p>
            <p><span className="font-medium">Amount:</span> {formatCents(transaction.amount_cents)}</p>
            <p><span className="font-medium">Date:</span> {new Date(transaction.ts * 1000).toLocaleDateString()}</p>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="refund-reason">Reason (min 10 characters)</Label>
            <Textarea
              id="refund-reason"
              placeholder="Describe why you are requesting a refund..."
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              rows={4}
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="refund-amount">Partial amount (USD, leave blank for full refund)</Label>
            <Input
              id="refund-amount"
              type="number"
              step="0.01"
              min="0.01"
              placeholder={`${(transaction.amount_cents / 100).toFixed(2)} (full)`}
              value={partialAmount}
              onChange={(e) => setPartialAmount(e.target.value)}
            />
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button
            onClick={handleSubmit}
            disabled={reason.length < 10 || mutation.isPending || !entryId}
          >
            {mutation.isPending ? "Submitting..." : "Submit Request"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
