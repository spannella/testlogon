import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { Lock } from "lucide-react";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { submitPrivateRequest } from "@/api/endpoints/broadcastPrivate";
import { getPaymentMethods } from "@/api/endpoints/billing";
import type { PaymentMethod } from "@/api/types";

interface GoPrivateButtonProps {
  sessionId: string;
  creatorId: string;
  viewerId: string;
  minRateCents?: number;
  sessionStatus: string;
}

export function GoPrivateButton({
  sessionId,
  creatorId,
  viewerId,
  minRateCents = 100,
  sessionStatus,
}: GoPrivateButtonProps) {
  const [open, setOpen] = useState(false);
  const [rateCents, setRateCents] = useState(minRateCents);
  const [maxDuration, setMaxDuration] = useState(60);
  const [selectedPm, setSelectedPm] = useState("");
  const [requestSent, setRequestSent] = useState(false);

  // Hide for broadcaster or non-live sessions
  if (viewerId === creatorId || sessionStatus !== "live") {
    return null;
  }

  const pmQuery = useQuery({
    queryKey: ["billing", "payment-methods"],
    queryFn: getPaymentMethods,
    enabled: open,
  });

  const paymentMethods: PaymentMethod[] = pmQuery.data ?? [];

  const requestMutation = useMutation({
    mutationFn: () =>
      submitPrivateRequest(sessionId, {
        rate_per_minute_cents: rateCents,
        payment_method_id: selectedPm,
        max_duration_minutes: maxDuration,
      }),
    onSuccess: () => {
      setRequestSent(true);
      setOpen(false);
      toast.success("Private session request sent!");
    },
    onError: (err: Error & { response?: { data?: { detail?: string } } }) => {
      const detail = err?.response?.data?.detail ?? "Failed to send request";
      toast.error(typeof detail === "string" ? detail : "Failed to send request");
    },
  });

  const estimatedCost = ((rateCents * maxDuration) / 100).toFixed(2);

  return (
    <>
      <Button
        variant="outline"
        size="sm"
        onClick={() => setOpen(true)}
        disabled={requestSent}
        className="gap-2"
      >
        <Lock className="h-4 w-4" />
        {requestSent ? "Request Sent" : "Go Private"}
      </Button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Request Private Session</DialogTitle>
            <DialogDescription>
              Request a private 1-on-1 video call with the creator. You will be
              billed per minute at your offered rate.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label>Rate (cents/min)</Label>
              <Input
                type="number"
                min={minRateCents}
                max={10000}
                value={rateCents}
                onChange={(e) => setRateCents(Number(e.target.value))}
              />
              <p className="text-xs text-muted-foreground">
                Minimum: ${(minRateCents / 100).toFixed(2)}/min
              </p>
            </div>

            <div className="space-y-2">
              <Label>Max Duration (minutes)</Label>
              <Select
                value={String(maxDuration)}
                onValueChange={(v) => setMaxDuration(Number(v))}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {[5, 10, 15, 30, 60, 90, 120].map((m) => (
                    <SelectItem key={m} value={String(m)}>
                      {m} minutes
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>Payment Method</Label>
              <Select value={selectedPm} onValueChange={setSelectedPm}>
                <SelectTrigger>
                  <SelectValue placeholder="Select payment method" />
                </SelectTrigger>
                <SelectContent>
                  {paymentMethods.map((pm) => (
                    <SelectItem key={pm.payment_method_id} value={pm.payment_method_id}>
                      {pm.brand ?? "Card"} ****{pm.last4 ?? "????"}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="rounded-md bg-muted p-3 text-sm">
              <p>
                Estimated cost: <strong>${estimatedCost}</strong>
              </p>
              <p className="text-muted-foreground">
                (${(rateCents / 100).toFixed(2)}/min x {maxDuration} min max)
              </p>
            </div>
          </div>

          <DialogFooter>
            <Button variant="ghost" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => requestMutation.mutate()}
              disabled={
                !selectedPm ||
                rateCents < minRateCents ||
                requestMutation.isPending
              }
            >
              {requestMutation.isPending ? "Sending..." : "Send Request"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
