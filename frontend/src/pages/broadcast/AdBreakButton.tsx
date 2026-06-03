import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Timer } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { triggerAdBreak } from "@/api/endpoints/broadcast-ads";

export interface AdBreakButtonProps {
  sessionId: string;
  isLive: boolean;
  adBreakActive: boolean;
  durationSeconds: number;
  onTriggered?: () => void;
}

/**
 * Broadcaster control: insert a mid-roll ad break for all viewers (ADS-006).
 */
export function AdBreakButton({
  sessionId,
  isLive,
  adBreakActive,
  durationSeconds,
  onTriggered,
}: AdBreakButtonProps) {
  const [confirmOpen, setConfirmOpen] = useState(false);

  const mutation = useMutation({
    mutationFn: () => triggerAdBreak(sessionId),
    onSuccess: () => {
      setConfirmOpen(false);
      onTriggered?.();
    },
  });

  const disabled = !isLive || adBreakActive || mutation.isPending;

  return (
    <>
      <Button
        data-testid="ad-break-button"
        variant="secondary"
        size="sm"
        className="gap-1"
        disabled={disabled}
        onClick={() => setConfirmOpen(true)}
      >
        <Timer className="h-4 w-4" />
        {adBreakActive ? "Ad Break Active" : "Insert Ad Break"}
      </Button>

      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent data-testid="ad-break-confirm-dialog">
          <DialogHeader>
            <DialogTitle>Insert {durationSeconds}s ad break?</DialogTitle>
            <DialogDescription>
              All non-subscriber viewers will see an ad for {durationSeconds} seconds.
              The stream continues underneath.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setConfirmOpen(false)}>
              Cancel
            </Button>
            <Button
              data-testid="ad-break-confirm"
              onClick={() => mutation.mutate()}
              disabled={mutation.isPending}
            >
              {mutation.isPending ? "Starting…" : "Insert Ad Break"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

export default AdBreakButton;
