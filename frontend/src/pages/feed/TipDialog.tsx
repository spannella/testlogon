import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CreditCard, Check, DollarSign, Loader2 } from "lucide-react";
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
import { tipPostDirect, tipPost } from "@/api/endpoints/newsfeed";
import { getPaymentMethods } from "@/api/endpoints/billing";
import type { PaymentMethod } from "@/api/types";

const PRESETS = [100, 500, 1000] as const; // cents

interface TipDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  postId: string;
  authorId: string;
  /** If provided, tips the comment instead of the post directly */
  commentId?: string;
}

export function TipDialog({ open, onOpenChange, postId, authorId, commentId }: TipDialogProps) {
  const queryClient = useQueryClient();
  const [amountCents, setAmountCents] = useState<number>(100);
  const [customValue, setCustomValue] = useState("");
  const [isCustom, setIsCustom] = useState(false);
  const [selectedPmId, setSelectedPmId] = useState<string | null>(null);

  const isCommentTip = Boolean(commentId);

  // Payment methods — only needed for post tips
  const { data: paymentMethods = [] } = useQuery<PaymentMethod[]>({
    queryKey: ["billing", "payment-methods"],
    queryFn: getPaymentMethods,
    staleTime: 5 * 60 * 1000,
    enabled: open && !isCommentTip,
  });

  // Compute effective PM: selected or default
  const effectivePm = selectedPmId
    ? paymentMethods.find((m) => m.payment_method_id === selectedPmId)
    : (paymentMethods.find((m) => m.is_default) ?? paymentMethods[0]);

  const postTipMutation = useMutation({
    mutationFn: () =>
      tipPostDirect(postId, {
        amount_cents: amountCents,
        ...(effectivePm ? { payment_method_id: effectivePm.payment_method_id } : {}),
      }),
    onSuccess: () => {
      toast.success(`Tip of $${(amountCents / 100).toFixed(2)} sent!`);
      void queryClient.invalidateQueries({ queryKey: ["feed"] });
      onOpenChange(false);
      resetState();
    },
    onError: () => toast.error("Failed to send tip"),
  });

  const commentTipMutation = useMutation({
    mutationFn: () => tipPost(postId, commentId!, amountCents),
    onSuccess: () => {
      toast.success(`Tip of $${(amountCents / 100).toFixed(2)} sent!`);
      void queryClient.invalidateQueries({ queryKey: ["comments", postId] });
      onOpenChange(false);
      resetState();
    },
    onError: () => toast.error("Failed to send tip"),
  });

  const mutation = isCommentTip ? commentTipMutation : postTipMutation;

  const resetState = () => {
    setAmountCents(100);
    setCustomValue("");
    setIsCustom(false);
    setSelectedPmId(null);
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

  // For post tips, PM is required if PMs are available
  const pmRequired = !isCommentTip && paymentMethods.length > 0;
  const canSubmit =
    amountCents > 0 &&
    !mutation.isPending &&
    (!pmRequired || Boolean(effectivePm));

  const handleSend = () => {
    mutation.mutate();
  };

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) resetState(); onOpenChange(o); }}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <DollarSign className="h-4 w-4" /> Send a Tip
          </DialogTitle>
        </DialogHeader>

        <p className="text-sm text-muted-foreground">
          Tip <span className="font-medium text-foreground">{authorId}</span>
          {isCommentTip ? " for their comment" : " for this post"}
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

        {/* Payment method selector — post tips only */}
        {!isCommentTip && paymentMethods.length > 0 && (
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">Payment method</label>
            <div className="space-y-1.5">
              {paymentMethods.map((pm) => {
                const label = pm.brand
                  ? `${pm.brand.charAt(0).toUpperCase() + pm.brand.slice(1)} •••• ${pm.last4}`
                  : (pm.label ?? pm.method_type);
                const active = (selectedPmId ?? effectivePm?.payment_method_id) === pm.payment_method_id;
                return (
                  <button
                    key={pm.payment_method_id}
                    type="button"
                    onClick={() => setSelectedPmId(pm.payment_method_id)}
                    className={cn(
                      "flex w-full items-center gap-3 rounded-lg border px-3 py-2 text-sm transition-colors hover:bg-accent",
                      active ? "border-primary bg-primary/5" : "border-border",
                    )}
                  >
                    <CreditCard className="h-4 w-4 shrink-0 text-muted-foreground" />
                    <span className="flex-1 text-left">{label}</span>
                    {pm.is_default && (
                      <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">Default</span>
                    )}
                    {active && <Check className="h-4 w-4 text-primary" />}
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {!isCommentTip && paymentMethods.length === 0 && (
          <p className="text-xs text-muted-foreground">
            Add a payment method in Billing to send tips.
          </p>
        )}

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
          <Button onClick={handleSend} disabled={!canSubmit}>
            {mutation.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              "Send Tip"
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
