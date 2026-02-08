import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { DollarSign } from "lucide-react";
import { toast } from "sonner";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { tipPostDirect } from "@/api/endpoints/newsfeed";

const PRESETS = [100, 500, 1000] as const; // cents

interface TipDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  postId: string;
  authorId: string;
}

export function TipDialog({ open, onOpenChange, postId, authorId }: TipDialogProps) {
  const queryClient = useQueryClient();
  const [amountCents, setAmountCents] = useState<number>(100);
  const [customValue, setCustomValue] = useState("");
  const [isCustom, setIsCustom] = useState(false);

  const mutation = useMutation({
    mutationFn: () => tipPostDirect(postId, { amount_cents: amountCents }),
    onSuccess: () => {
      toast.success(`Tip of $${(amountCents / 100).toFixed(2)} sent!`);
      void queryClient.invalidateQueries({ queryKey: ["feed"] });
      onOpenChange(false);
      resetState();
    },
    onError: () => toast.error("Failed to send tip"),
  });

  const resetState = () => {
    setAmountCents(100);
    setCustomValue("");
    setIsCustom(false);
  };

  const selectPreset = (cents: number) => {
    setAmountCents(cents);
    setIsCustom(false);
    setCustomValue("");
  };

  const handleCustomChange = (val: string) => {
    setCustomValue(val);
    setIsCustom(true);
    const parsed = parseFloat(val);
    if (!isNaN(parsed) && parsed > 0) {
      setAmountCents(Math.round(parsed * 100));
    }
  };

  const canSubmit = amountCents > 0 && !mutation.isPending;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <DollarSign className="h-4 w-4" /> Send a Tip
          </DialogTitle>
        </DialogHeader>

        <p className="text-sm text-muted-foreground">
          Tip <span className="font-medium text-foreground">{authorId}</span> for this post
        </p>

        {/* Preset amounts */}
        <div className="flex gap-2">
          {PRESETS.map((cents) => (
            <Button
              key={cents}
              type="button"
              variant={!isCustom && amountCents === cents ? "default" : "outline"}
              size="sm"
              className="flex-1"
              onClick={() => selectPreset(cents)}
            >
              ${(cents / 100).toFixed(0)}
            </Button>
          ))}
        </div>

        {/* Custom amount */}
        <div className="space-y-1">
          <label className="text-xs text-muted-foreground">Custom amount</label>
          <div className="relative">
            <span className="absolute left-3 top-1/2 -translate-y-1/2 text-sm text-muted-foreground">
              $
            </span>
            <Input
              type="number"
              min="0.01"
              step="0.01"
              placeholder="0.00"
              value={customValue}
              onChange={(e) => handleCustomChange(e.target.value)}
              className={cn("pl-7", isCustom && "ring-2 ring-primary")}
            />
          </div>
        </div>

        {/* Summary */}
        {amountCents > 0 && (
          <p className="text-center text-lg font-semibold">
            ${(amountCents / 100).toFixed(2)}
          </p>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={() => mutation.mutate()} disabled={!canSubmit}>
            {mutation.isPending ? "Sending..." : "Send Tip"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
