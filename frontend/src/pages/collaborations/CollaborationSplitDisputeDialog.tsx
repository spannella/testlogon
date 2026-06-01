import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { fileDispute } from "@/api/endpoints/collaborationRevenue";
import type { CollabSplitRecord } from "@/api/types";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";

interface Props {
  collabId: string;
  split: CollabSplitRecord | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export default function CollaborationSplitDisputeDialog({
  collabId,
  split,
  open,
  onOpenChange,
}: Props) {
  const qc = useQueryClient();
  const [reason, setReason] = useState("");

  const mut = useMutation({
    mutationFn: () =>
      fileDispute(collabId, split!.split_id, { reason }),
    onSuccess: () => {
      toast.success("Dispute filed");
      qc.invalidateQueries({ queryKey: ["collab-splits", collabId] });
      qc.invalidateQueries({ queryKey: ["collab-disputes", collabId] });
      setReason("");
      onOpenChange(false);
    },
    onError: (err: unknown) => {
      const msg =
        (err as { message?: string })?.message || "Failed to file dispute";
      toast.error(msg);
    },
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Dispute Split</DialogTitle>
          <DialogDescription>
            File a dispute on this split if you believe the distribution is
            incorrect. The other collaborator or an admin can resolve it.
          </DialogDescription>
        </DialogHeader>

        {split && (
          <div className="text-sm text-muted-foreground space-y-1">
            <div>Split ID: <span className="font-mono">{split.split_id}</span></div>
            <div>Gross: ${(split.gross_amount_cents / 100).toFixed(2)}</div>
            <div>Source: {split.source}</div>
          </div>
        )}

        <div className="space-y-2">
          <Label htmlFor="dispute-reason">Reason</Label>
          <Textarea
            id="dispute-reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Explain why this split is incorrect (min 10 characters)"
            rows={4}
          />
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            disabled={reason.trim().length < 10 || mut.isPending}
            onClick={() => mut.mutate()}
          >
            File Dispute
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
