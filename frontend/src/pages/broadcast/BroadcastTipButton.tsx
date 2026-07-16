import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { DollarSign, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { sendBroadcastTip } from "@/api/endpoints/broadcast-tips";
import { api } from "@/api/client";

interface PaymentMethod {
  payment_method_id: string;
  brand?: string;
  last4?: string;
  type?: string;
}

interface BroadcastTipButtonProps {
  sessionId: string;
  tipEnabled: boolean;
  tipMinCents: number;
  tipMaxCents: number;
  isBroadcaster: boolean;
}

const PRESETS = [100, 500, 1000, 2500];

export function BroadcastTipButton({
  sessionId,
  tipEnabled,
  tipMinCents,
  tipMaxCents,
  isBroadcaster,
}: BroadcastTipButtonProps) {
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [amountCents, setAmountCents] = useState(PRESETS[0]);
  const [customAmount, setCustomAmount] = useState("");
  const [useCustom, setUseCustom] = useState(false);
  const [message, setMessage] = useState("");
  const [selectedPmId, setSelectedPmId] = useState("");

  const pmQuery = useQuery({
    queryKey: ["billing", "payment-methods"],
    queryFn: async () => {
      const resp = await api.get<{ items: PaymentMethod[] }>("/ui/billing/payment-methods");
      return resp.items ?? [];
    },
    enabled: open,
  });

  const pms = pmQuery.data ?? [];

  const tipMut = useMutation({
    mutationFn: () => {
      const cents = useCustom ? Math.round(parseFloat(customAmount) * 100) : (amountCents ?? 0);
      return sendBroadcastTip(sessionId, {
        amount_cents: cents,
        text: message || undefined,
        payment_method_id: selectedPmId,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["broadcast", "tips"] });
      toast.success("Tip sent!");
      setOpen(false);
      setMessage("");
      setUseCustom(false);
      setCustomAmount("");
    },
    onError: (err) => {
      toast.error(err instanceof Error ? err.message : "Failed to send tip");
    },
  });

  if (isBroadcaster || !tipEnabled) return null;

  const effectiveAmount = useCustom
    ? Math.round(parseFloat(customAmount || "0") * 100)
    : (amountCents ?? 0);
  const isValidAmount =
    effectiveAmount >= tipMinCents && effectiveAmount <= tipMaxCents;

  return (
    <>
      <Button
        variant="default"
        size="sm"
        className="gap-1"
        onClick={() => setOpen(true)}
        data-testid="broadcast-tip-button"
      >
        <DollarSign className="h-4 w-4" />
        Tip
      </Button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Send a Tip</DialogTitle>
            <DialogDescription>
              Support the broadcaster with a tip.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            {/* Amount presets */}
            <div className="space-y-2">
              <Label>Amount</Label>
              <div className="flex gap-2 flex-wrap">
                {PRESETS.map((p) => (
                  <Badge
                    key={p}
                    variant={!useCustom && amountCents === p ? "default" : "outline"}
                    className="cursor-pointer px-3 py-1.5 text-sm"
                    onClick={() => {
                      setAmountCents(p);
                      setUseCustom(false);
                    }}
                  >
                    ${(p / 100).toFixed(0)}
                  </Badge>
                ))}
                <Badge
                  variant={useCustom ? "default" : "outline"}
                  className="cursor-pointer px-3 py-1.5 text-sm"
                  onClick={() => setUseCustom(true)}
                >
                  Custom
                </Badge>
              </div>
              {useCustom && (
                <Input
                  type="number"
                  min={(tipMinCents / 100).toFixed(2)}
                  max={(tipMaxCents / 100).toFixed(2)}
                  step="0.01"
                  placeholder={`$${(tipMinCents / 100).toFixed(2)} - $${(tipMaxCents / 100).toFixed(2)}`}
                  value={customAmount}
                  onChange={(e) => setCustomAmount(e.target.value)}
                  data-testid="tip-custom-amount"
                />
              )}
            </div>

            {/* Message */}
            <div className="space-y-2">
              <Label htmlFor="tip-message">Message (optional)</Label>
              <Input
                id="tip-message"
                placeholder="Say something nice..."
                maxLength={280}
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                data-testid="tip-message-input"
              />
            </div>

            {/* Payment method */}
            <div className="space-y-2">
              <Label>Payment Method</Label>
              {pms.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No payment methods found. Add one in Billing.
                </p>
              ) : (
                <Select value={selectedPmId} onValueChange={setSelectedPmId}>
                  <SelectTrigger data-testid="tip-pm-select">
                    <SelectValue placeholder="Select payment method" />
                  </SelectTrigger>
                  <SelectContent>
                    {pms.map((pm) => (
                      <SelectItem
                        key={pm.payment_method_id}
                        value={pm.payment_method_id}
                      >
                        {pm.brand ?? pm.type ?? "Card"} ****{pm.last4 ?? "????"}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => tipMut.mutate()}
              disabled={
                !isValidAmount || !selectedPmId || tipMut.isPending
              }
              data-testid="tip-send-button"
            >
              {tipMut.isPending && (
                <Loader2 className="h-4 w-4 mr-1 animate-spin" />
              )}
              Send ${(effectiveAmount / 100).toFixed(2)}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
