import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { RotateCcw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PageHeader } from "@/components/shared/PageHeader";
import { ApiError } from "@/api/client";
import { toast } from "sonner";
import { reverseTip, type TipReverseResult } from "@/api/endpoints/adminTipReversal";

function fmtCents(c: number): string {
  return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" }).format(c / 100);
}

export default function TipReversalPage() {
  const [tipId, setTipId] = useState("");
  const [tipperId, setTipperId] = useState("");
  const [recipientId, setRecipientId] = useState("");
  const [reason, setReason] = useState("admin_reversal");
  const [result, setResult] = useState<TipReverseResult | null>(null);

  const reverseMut = useMutation({
    mutationFn: () =>
      reverseTip(tipId.trim(), {
        tipper_id: tipperId.trim(),
        recipient_id: recipientId.trim() || undefined,
        reason: reason.trim() || "admin_reversal",
      }),
    onSuccess: (r) => {
      setResult(r);
      toast.success(r.idempotent_replay ? "Already reversed (idempotent replay)" : "Tip reversed");
    },
    onError: (err: unknown) => toast.error(err instanceof ApiError ? err.detail : "Reversal failed"),
  });

  return (
    <div className="mx-auto w-full max-w-2xl space-y-6 p-4 sm:p-6">
      <PageHeader title="Tip Reversal" description="Reverse (refund) a tip payment. Admin/root only. Idempotent — safe to retry." />

      <Card>
        <CardContent className="space-y-3 p-4">
          <div className="space-y-1.5">
            <Label htmlFor="tip-id">Tip payment ID</Label>
            <Input id="tip-id" placeholder="tip_payment_id" value={tipId} onChange={(e) => setTipId(e.target.value)} className="font-mono" />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="tipper-id">Tipper ID (required — ledger is partitioned by tipper)</Label>
            <Input id="tipper-id" placeholder="tipper user id" value={tipperId} onChange={(e) => setTipperId(e.target.value)} className="font-mono" />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="recipient-id">Recipient ID (optional — derived if omitted)</Label>
            <Input id="recipient-id" placeholder="recipient user id" value={recipientId} onChange={(e) => setRecipientId(e.target.value)} className="font-mono" />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="reason">Reason</Label>
            <Input id="reason" value={reason} onChange={(e) => setReason(e.target.value)} />
          </div>
          <Button
            variant="destructive"
            disabled={!tipId.trim() || !tipperId.trim() || reverseMut.isPending}
            onClick={() => reverseMut.mutate()}
          >
            <RotateCcw className="mr-1 h-3.5 w-3.5" /> Reverse tip
          </Button>
        </CardContent>
      </Card>

      {result && (
        <Card>
          <CardContent className="space-y-1 p-4 text-sm">
            <div className="flex justify-between"><span className="text-muted-foreground">Tip</span><span className="font-mono">{result.tip_payment_id}</span></div>
            <div className="flex justify-between"><span className="text-muted-foreground">Refunded</span><span>{fmtCents(result.refunded_cents)}</span></div>
            <div className="flex justify-between"><span className="text-muted-foreground">Clawback</span><span>{fmtCents(result.clawback_cents)}</span></div>
            <div className="flex justify-between"><span className="text-muted-foreground">Reversal entry</span><span className="font-mono text-xs">{result.reversal_entry_id}</span></div>
            <div className="flex justify-between"><span className="text-muted-foreground">Refund entry</span><span className="font-mono text-xs">{result.refund_entry_id}</span></div>
            <div className="flex justify-between"><span className="text-muted-foreground">Idempotent replay</span><span>{result.idempotent_replay ? "yes" : "no"}</span></div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
