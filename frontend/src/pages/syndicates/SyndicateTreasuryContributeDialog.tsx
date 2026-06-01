import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogTrigger,
} from "@/components/ui/dialog";
import { depositToTreasury } from "@/api/endpoints/syndicateTreasury";

export default function SyndicateTreasuryContributeDialog({
  syndicateId,
}: {
  syndicateId: string;
}) {
  const [open, setOpen] = useState(false);
  const [amount, setAmount] = useState("");
  const [error, setError] = useState("");
  const queryClient = useQueryClient();

  const mut = useMutation({
    mutationFn: () => depositToTreasury(syndicateId, Math.round(parseFloat(amount) * 100)),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["syndicate-treasury", syndicateId] });
      setOpen(false);
      setAmount("");
      setError("");
    },
    onError: () => setError("Deposit failed. Check your wallet balance."),
  });

  const dollars = parseFloat(amount);
  const valid = !Number.isNaN(dollars) && dollars >= 1 && dollars <= 10000;

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" data-testid="treasury-contribute-btn">
          <Plus className="h-4 w-4 mr-1" /> Contribute
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Contribute to Treasury</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div
            className="flex items-start gap-2 rounded-md border border-yellow-300 bg-yellow-50 dark:bg-yellow-900/20 p-3 text-sm text-yellow-800 dark:text-yellow-200"
            data-testid="treasury-contribute-warning"
          >
            <AlertTriangle className="h-4 w-4 mt-0.5 flex-shrink-0" />
            <span>
              Contributions are pooled into the shared syndicate treasury. They cannot be
              withdrawn directly by you.
            </span>
          </div>
          <div>
            <label className="text-sm font-medium">Amount (USD)</label>
            <Input
              type="number"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              placeholder="10.00"
              min={1}
              max={10000}
              step={0.01}
            />
          </div>
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
        <DialogFooter>
          <Button onClick={() => mut.mutate()} disabled={!valid || mut.isPending}>
            {mut.isPending ? "Contributing..." : "Confirm Contribution"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
