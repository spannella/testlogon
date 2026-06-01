import { useState } from "react";
import { BellOff } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export interface SnoozeDurationPickerProps {
  userId: string;
  userName: string;
  open: boolean;
  onClose: () => void;
  onSnooze: (days: number) => void;
  isPending?: boolean;
}

const PRESETS = [1, 3, 7, 30];

/** SOCIAL-007: shared dialog to choose a snooze duration (preset or custom). */
export function SnoozeDurationPicker({
  userName,
  open,
  onClose,
  onSnooze,
  isPending = false,
}: SnoozeDurationPickerProps) {
  const [selected, setSelected] = useState<number>(7);
  const [custom, setCustom] = useState<string>("");

  const customDays = custom.trim() === "" ? null : Number(custom);
  const effectiveDays = customDays ?? selected;
  const valid =
    Number.isInteger(effectiveDays) && effectiveDays >= 1 && effectiveDays <= 90;

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent data-testid="snooze-duration-picker">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <BellOff className="h-4 w-4" />
            Snooze {userName}
          </DialogTitle>
          <DialogDescription>
            Hide their posts from your feed for a while. They won&apos;t be
            unfollowed and won&apos;t know you snoozed them.
          </DialogDescription>
        </DialogHeader>

        <div className="grid grid-cols-4 gap-2 py-2">
          {PRESETS.map((d) => (
            <Button
              key={d}
              type="button"
              variant={customDays === null && selected === d ? "default" : "outline"}
              size="sm"
              data-testid={`snooze-preset-${d}`}
              onClick={() => {
                setSelected(d);
                setCustom("");
              }}
            >
              {d} {d === 1 ? "day" : "days"}
            </Button>
          ))}
        </div>

        <div className="flex items-center gap-2">
          <Input
            type="number"
            min={1}
            max={90}
            placeholder="Custom"
            value={custom}
            data-testid="snooze-custom-days"
            onChange={(e) => setCustom(e.target.value)}
            className="w-28"
          />
          <span className="text-sm text-muted-foreground">days (1–90)</span>
        </div>

        <DialogFooter>
          <Button type="button" variant="ghost" onClick={onClose} disabled={isPending}>
            Cancel
          </Button>
          <Button
            type="button"
            data-testid="snooze-confirm"
            disabled={!valid || isPending}
            onClick={() => onSnooze(effectiveDays)}
          >
            Snooze
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
