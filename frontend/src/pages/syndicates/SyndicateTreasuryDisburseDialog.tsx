import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Send } from "lucide-react";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { disburseFromTreasury } from "@/api/endpoints/syndicateTreasury";
import type { SyndicateMemberOut } from "@/api/types";

export default function SyndicateTreasuryDisburseDialog({
  syndicateId,
  members,
}: {
  syndicateId: string;
  members: SyndicateMemberOut[];
}) {
  const [open, setOpen] = useState(false);
  const [recipient, setRecipient] = useState("");
  const [amount, setAmount] = useState("");
  const [note, setNote] = useState("");
  const [error, setError] = useState("");
  const queryClient = useQueryClient();

  const mut = useMutation({
    mutationFn: () =>
      disburseFromTreasury(syndicateId, {
        recipient_user_id: recipient,
        amount_cents: Math.round(parseFloat(amount) * 100),
        note,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["syndicate-treasury", syndicateId] });
      setOpen(false);
      setRecipient("");
      setAmount("");
      setNote("");
      setError("");
    },
    onError: () => setError("Disbursement failed. Check the treasury balance."),
  });

  const dollars = parseFloat(amount);
  const valid = !!recipient && !Number.isNaN(dollars) && dollars > 0;

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" variant="outline" data-testid="treasury-disburse-btn">
          <Send className="h-4 w-4 mr-1" /> Disburse
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Disburse Treasury Funds</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <label className="text-sm font-medium">Recipient</label>
            <Select value={recipient} onValueChange={setRecipient}>
              <SelectTrigger>
                <SelectValue placeholder="Select a member" />
              </SelectTrigger>
              <SelectContent>
                {members.map((m) => (
                  <SelectItem key={m.user_id} value={m.user_id}>
                    {m.display_name || m.user_id}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <label className="text-sm font-medium">Amount (USD)</label>
            <Input
              type="number"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              placeholder="10.00"
              min={0.01}
              step={0.01}
            />
          </div>
          <div>
            <label className="text-sm font-medium">Note (optional)</label>
            <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Reason" />
          </div>
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
        <DialogFooter>
          <Button onClick={() => mut.mutate()} disabled={!valid || mut.isPending}>
            {mut.isPending ? "Disbursing..." : "Confirm Disbursement"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
