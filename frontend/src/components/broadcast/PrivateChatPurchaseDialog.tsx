import { useState, useMemo } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { ShoppingCart, Eye, MessageCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import {
  purchasePrivateChat,
  getChatTiers,
  type PrivateChatPurchaseResponse,
  type PrivateChatTiers,
} from "@/api/endpoints/broadcastPrivateChat";

interface PrivateChatPurchaseDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  sessionId: string;
  paymentMethods: Array<{ id: string; brand: string; last4: string }>;
  activeChatId?: string; // If set, shows tier-2 (voyeur) purchase
  onPurchased?: (result: PrivateChatPurchaseResponse) => void;
}

export function PrivateChatPurchaseDialog({
  open,
  onOpenChange,
  sessionId,
  paymentMethods,
  activeChatId,
  onPurchased,
}: PrivateChatPurchaseDialogProps) {
  const [tier, setTier] = useState<1 | 2>(activeChatId ? 2 : 1);
  const [duration, setDuration] = useState<number>(5);
  const [pmId, setPmId] = useState<string>(paymentMethods[0]?.id ?? "");

  const tiersQuery = useQuery<PrivateChatTiers>({
    queryKey: ["chat-tiers", sessionId],
    queryFn: () => getChatTiers(sessionId),
    enabled: open,
  });

  const tiers = tiersQuery.data;
  const timeBlocks = tiers?.private_chat_time_blocks ?? [5, 15, 30, 60];
  const ratePerMin =
    tier === 1
      ? tiers?.private_chat_rate_per_minute_cents ?? 500
      : tiers?.voyeur_rate_per_minute_cents ?? 100;

  const totalCents = useMemo(() => ratePerMin * duration, [ratePerMin, duration]);

  const purchaseMut = useMutation({
    mutationFn: () =>
      purchasePrivateChat(sessionId, {
        tier,
        duration_minutes: duration,
        payment_method_id: pmId,
        chat_id: tier === 2 ? activeChatId : undefined,
      }),
    onSuccess: (result: PrivateChatPurchaseResponse) => {
      onPurchased?.(result);
      onOpenChange(false);
    },
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            {tier === 1 ? (
              <MessageCircle className="h-5 w-5" />
            ) : (
              <Eye className="h-5 w-5" />
            )}
            {tier === 1 ? "Private Chat" : "Spectate Chat"}
          </DialogTitle>
          <DialogDescription>
            {tier === 1
              ? "Start a private 1-on-1 text chat with the broadcaster."
              : "Watch this private chat as a read-only spectator."}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          {/* Tier selector (only show if no activeChatId) */}
          {!activeChatId && tiers?.private_chat_voyeur_enabled && (
            <div>
              <label className="mb-1 block text-sm font-medium">Chat Type</label>
              <div className="flex gap-2">
                <Button
                  variant={tier === 1 ? "default" : "outline"}
                  size="sm"
                  onClick={() => setTier(1)}
                >
                  <MessageCircle className="mr-1 h-3 w-3" />
                  Private Chat
                </Button>
                <Button
                  variant={tier === 2 ? "default" : "outline"}
                  size="sm"
                  onClick={() => setTier(2)}
                >
                  <Eye className="mr-1 h-3 w-3" />
                  Spectate
                </Button>
              </div>
            </div>
          )}

          {/* Duration selector */}
          <div>
            <label className="mb-1 block text-sm font-medium">Duration</label>
            <Select
              value={String(duration)}
              onValueChange={(v) => setDuration(Number(v))}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {timeBlocks.map((mins) => (
                  <SelectItem key={mins} value={String(mins)}>
                    {mins} minutes
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Rate display */}
          <div className="flex items-center justify-between rounded border p-3">
            <span className="text-sm text-muted-foreground">Rate</span>
            <span className="font-mono text-sm">
              ${(ratePerMin / 100).toFixed(2)}/min
            </span>
          </div>

          {/* Total cost */}
          <div className="flex items-center justify-between rounded bg-muted p-3">
            <span className="text-sm font-medium">Total</span>
            <Badge variant="secondary" className="font-mono text-base">
              ${(totalCents / 100).toFixed(2)}
            </Badge>
          </div>

          {/* Payment method selector */}
          <div>
            <label className="mb-1 block text-sm font-medium">
              Payment Method
            </label>
            <Select value={pmId} onValueChange={setPmId}>
              <SelectTrigger>
                <SelectValue placeholder="Select payment method" />
              </SelectTrigger>
              <SelectContent>
                {paymentMethods.map((pm) => (
                  <SelectItem key={pm.id} value={pm.id}>
                    {pm.brand} **** {pm.last4}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={() => purchaseMut.mutate()}
            disabled={!pmId || purchaseMut.isPending}
          >
            <ShoppingCart className="mr-2 h-4 w-4" />
            {purchaseMut.isPending ? "Purchasing..." : `Purchase for $${(totalCents / 100).toFixed(2)}`}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
