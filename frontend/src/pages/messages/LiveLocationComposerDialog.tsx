import { useState } from "react";
import { Radio } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { LIVE_DURATION_OPTIONS } from "@/lib/liveLocation";

interface LiveLocationComposerDialogProps {
  open: boolean;
  onClose: () => void;
  /** Emit the chosen duration in seconds; the caller starts the share. */
  onSubmit: (durationSec: number) => void;
  starting?: boolean;
}

/**
 * FE-131: "Share live location" duration picker. Pick 15m / 1h / 8h, then the
 * caller starts the share (useLiveLocationShare) which begins relaying position
 * until the chosen duration expires (auto-stop) or the sharer stops early.
 */
export function LiveLocationComposerDialog({
  open,
  onClose,
  onSubmit,
  starting,
}: LiveLocationComposerDialogProps) {
  const [seconds, setSeconds] = useState<number>(LIVE_DURATION_OPTIONS[0]?.seconds ?? 900);

  return (
    <Dialog open={open} onOpenChange={(o) => (!o ? onClose() : undefined)}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Radio className="h-4 w-4 text-rose-500" />
            Share live location
          </DialogTitle>
          <DialogDescription>
            Your recipients will see your position update on a live map until it
            expires. You can stop sharing at any time.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-2 py-1" role="radiogroup" aria-label="Share duration">
          {LIVE_DURATION_OPTIONS.map((opt) => {
            const selected = opt.seconds === seconds;
            return (
              <Button
                key={opt.seconds}
                type="button"
                variant={selected ? "default" : "outline"}
                className="justify-start"
                role="radio"
                aria-checked={selected}
                onClick={() => setSeconds(opt.seconds)}
                data-testid={`live-location-duration-${opt.seconds}`}
              >
                {opt.label}
              </Button>
            );
          })}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={starting}>
            Cancel
          </Button>
          <Button
            onClick={() => onSubmit(seconds)}
            disabled={starting}
            data-testid="live-location-start"
          >
            {starting ? "Starting…" : "Start sharing"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default LiveLocationComposerDialog;
