import { useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";

// ─── Request Cancellation ──────────────────────────────────────

interface CancelRequestDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSubmit: (reason: string) => void;
  loading?: boolean;
}

export function CancelRequestDialog({
  open,
  onOpenChange,
  onSubmit,
  loading,
}: CancelRequestDialogProps) {
  const [reason, setReason] = useState("");

  const handleSubmit = () => {
    onSubmit(reason);
    setReason("");
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Request Cancellation</DialogTitle>
          <DialogDescription>
            Provide a reason for cancelling this order. The request will be reviewed.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-2">
          <Label htmlFor="cancel-reason">Reason (optional)</Label>
          <Textarea
            id="cancel-reason"
            placeholder="Why would you like to cancel?"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={3}
          />
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={loading}>
            Never mind
          </Button>
          <Button variant="destructive" onClick={handleSubmit} disabled={loading}>
            {loading ? "Submitting..." : "Request Cancellation"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Respond to Cancel Request ─────────────────────────────────

interface CancelRespondDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onRespond: (decision: "APPROVE" | "DENY", note: string) => void;
  loading?: boolean;
}

export function CancelRespondDialog({
  open,
  onOpenChange,
  onRespond,
  loading,
}: CancelRespondDialogProps) {
  const [note, setNote] = useState("");

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Respond to Cancel Request</DialogTitle>
          <DialogDescription>
            Approve or deny this cancellation request.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-2">
          <Label htmlFor="respond-note">Note (optional)</Label>
          <Textarea
            id="respond-note"
            placeholder="Add a note..."
            value={note}
            onChange={(e) => setNote(e.target.value)}
            rows={3}
          />
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={loading}>
            Cancel
          </Button>
          <Button
            variant="outline"
            onClick={() => onRespond("DENY", note)}
            disabled={loading}
          >
            {loading ? "..." : "Deny"}
          </Button>
          <Button
            variant="destructive"
            onClick={() => onRespond("APPROVE", note)}
            disabled={loading}
          >
            {loading ? "..." : "Approve Cancellation"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
