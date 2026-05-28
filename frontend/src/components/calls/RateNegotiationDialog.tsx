import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { DollarSign } from "lucide-react";

export interface RateNegotiationDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  creatorName: string;
  rateCentsPerMinute: number;
  minBalanceMinutes: number;
  currentBalanceCents: number;
  onAccept: () => void;
  onDecline: () => void;
}

function formatDollars(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

export function RateNegotiationDialog({
  open,
  onOpenChange,
  creatorName,
  rateCentsPerMinute,
  minBalanceMinutes,
  currentBalanceCents,
  onAccept,
  onDecline,
}: RateNegotiationDialogProps) {
  const requiredCents = rateCentsPerMinute * minBalanceMinutes;
  const hasSufficientBalance = currentBalanceCents >= requiredCents;
  const estimatedMinutes = rateCentsPerMinute > 0
    ? Math.floor(currentBalanceCents / rateCentsPerMinute)
    : 0;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <DollarSign className="h-5 w-5" />
            Paid Call
          </DialogTitle>
          <DialogDescription>
            {creatorName} charges {formatDollars(rateCentsPerMinute)}/min for
            private calls.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3 py-2">
          <div className="flex justify-between text-sm">
            <span className="text-muted-foreground">Rate</span>
            <span className="font-medium">
              {formatDollars(rateCentsPerMinute)}/min
            </span>
          </div>
          <div className="flex justify-between text-sm">
            <span className="text-muted-foreground">Minimum balance</span>
            <span className="font-medium">
              {formatDollars(requiredCents)} ({minBalanceMinutes} min)
            </span>
          </div>
          <div className="flex justify-between text-sm">
            <span className="text-muted-foreground">Your wallet</span>
            <span className="font-medium">
              {formatDollars(currentBalanceCents)}
            </span>
          </div>
          {hasSufficientBalance && (
            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground">Estimated duration</span>
              <span className="font-medium">~{estimatedMinutes} min</span>
            </div>
          )}
          {!hasSufficientBalance && (
            <p className="text-sm text-destructive">
              Insufficient balance. You need at least{" "}
              {formatDollars(requiredCents)} to start this call.
            </p>
          )}
        </div>

        <DialogFooter className="gap-2">
          <Button variant="outline" onClick={onDecline}>
            Cancel
          </Button>
          <Button onClick={onAccept} disabled={!hasSufficientBalance}>
            Start Paid Call
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
