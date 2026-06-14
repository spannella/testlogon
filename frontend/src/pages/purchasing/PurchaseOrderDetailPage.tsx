import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams } from "react-router-dom";
import { toast } from "sonner";
import { ArrowLeft } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import {
  getPurchaseOrder,
  getApPayable,
  submitPurchaseOrder,
  approvePurchaseOrder,
  rejectPurchaseOrder,
  orderPurchaseOrder,
  cancelPurchaseOrder,
  receivePurchaseOrder,
  settlePoPayment,
  formatCents,
  type PurchaseOrder,
  type PoReceiveLinePayload,
} from "@/api/endpoints/purchasing";
import { ApiError } from "@/api/client";
import { PoStatusBadge, fmtTs } from "./poStatus";

// ─── Receive dialog ───────────────────────────────────────────────────────────

function ReceiveDialog({
  po,
  open,
  onOpenChange,
  onDone,
}: {
  po: PurchaseOrder;
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onDone: () => void;
}) {
  const [qtys, setQtys] = useState<Record<number, string>>({});

  const receiveMut = useMutation({
    mutationFn: () => {
      const lines: PoReceiveLinePayload[] = po.lines
        .map((l) => ({ line_no: l.line_no, quantity: Number(qtys[l.line_no] ?? "") || 0 }))
        .filter((l) => l.quantity > 0);
      return receivePurchaseOrder(po.po_id, { lines });
    },
    onSuccess: () => {
      toast.success("Goods received");
      setQtys({});
      onDone();
      onOpenChange(false);
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to record receipt"),
  });

  const anyQty = po.lines.some((l) => (Number(qtys[l.line_no] ?? "") || 0) > 0);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Receive Goods</DialogTitle>
          <DialogDescription>
            Enter received quantities per line. Leave blank to skip a line.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          {po.lines.map((l) => {
            const remaining = l.quantity_ordered - l.quantity_received;
            return (
              <div key={l.line_no} className="flex items-center gap-3">
                <div className="flex-1">
                  <div className="font-mono text-sm">{l.sku}</div>
                  <div className="text-xs text-muted-foreground">
                    Ordered {l.quantity_ordered} · received {l.quantity_received} · remaining {remaining}
                  </div>
                </div>
                <Input
                  className="w-24"
                  type="number"
                  min={0}
                  max={remaining}
                  placeholder="0"
                  value={qtys[l.line_no] ?? ""}
                  onChange={(e) =>
                    setQtys((p) => ({ ...p, [l.line_no]: e.target.value }))
                  }
                />
              </div>
            );
          })}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button disabled={!anyQty || receiveMut.isPending} onClick={() => receiveMut.mutate()}>
            {receiveMut.isPending ? "Recording…" : "Record receipt"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Settle payment dialog ────────────────────────────────────────────────────

function SettleDialog({
  poId,
  open,
  onOpenChange,
  onDone,
}: {
  poId: string;
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onDone: () => void;
}) {
  const [ref, setRef] = useState("");
  const [provider, setProvider] = useState("internal");

  const settleMut = useMutation({
    mutationFn: () => settlePoPayment(poId, { payment_ref: ref.trim(), provider: provider.trim() || "internal" }),
    onSuccess: () => {
      toast.success("Supplier payment settled");
      setRef("");
      onDone();
      onOpenChange(false);
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to settle payment"),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Settle Supplier Payment</DialogTitle>
          <DialogDescription>
            Record the payment reference for the accounts-payable entry on this PO.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1">
            <Label>Payment reference</Label>
            <Input value={ref} onChange={(e) => setRef(e.target.value)} placeholder="wire-12345" />
          </div>
          <div className="space-y-1">
            <Label>Provider</Label>
            <Input value={provider} onChange={(e) => setProvider(e.target.value)} />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button disabled={!ref.trim() || settleMut.isPending} onClick={() => settleMut.mutate()}>
            {settleMut.isPending ? "Settling…" : "Settle payment"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Reject dialog ────────────────────────────────────────────────────────────

function RejectDialog({
  poId,
  open,
  onOpenChange,
  onDone,
}: {
  poId: string;
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onDone: () => void;
}) {
  const [reason, setReason] = useState("");
  const rejectMut = useMutation({
    mutationFn: () => rejectPurchaseOrder(poId, { rejected_reason: reason.trim() }),
    onSuccess: () => {
      toast.success("Purchase order rejected");
      setReason("");
      onDone();
      onOpenChange(false);
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to reject PO"),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Reject Purchase Order</DialogTitle>
          <DialogDescription>Provide a reason for rejection.</DialogDescription>
        </DialogHeader>
        <div className="space-y-1">
          <Label>Reason</Label>
          <Input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reason…" />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="destructive" disabled={rejectMut.isPending} onClick={() => rejectMut.mutate()}>
            {rejectMut.isPending ? "Rejecting…" : "Reject PO"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function PurchaseOrderDetailPage() {
  const { poId = "" } = useParams<{ poId: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [receiveOpen, setReceiveOpen] = useState(false);
  const [settleOpen, setSettleOpen] = useState(false);
  const [rejectOpen, setRejectOpen] = useState(false);

  const poQuery = useQuery({
    queryKey: ["purchasing", "po", poId],
    queryFn: () => getPurchaseOrder(poId),
    enabled: !!poId,
    retry: (count, err) => !(err instanceof ApiError && err.status === 404) && count < 2,
  });

  const po = poQuery.data;

  const apQuery = useQuery({
    queryKey: ["purchasing", "po", poId, "ap-payable"],
    queryFn: () => getApPayable(poId),
    enabled: !!po && (po.status === "received" || po.status === "closed" || !!po.ledger_entry_sk),
    retry: false,
  });

  const refetchAll = () => {
    void poQuery.refetch();
    void apQuery.refetch();
    void qc.invalidateQueries({ queryKey: ["purchasing", "pos"] });
  };

  const transitionMut = useMutation({
    mutationFn: async (action: "submit" | "approve" | "order" | "cancel") => {
      if (action === "submit") return submitPurchaseOrder(poId);
      if (action === "approve") return approvePurchaseOrder(poId);
      if (action === "order") return orderPurchaseOrder(poId);
      return cancelPurchaseOrder(poId);
    },
    onSuccess: () => {
      toast.success("Purchase order updated");
      refetchAll();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to update PO"),
  });

  const actions = useMemo(() => {
    if (!po) return null;
    const busy = transitionMut.isPending;
    const buttons: React.ReactNode[] = [];
    const allowed: Record<string, string[]> = {
      draft: ["submit", "cancel"],
      submitted: ["approve", "reject", "cancel"],
      approved: ["order", "reject", "cancel"],
      ordered: ["receive", "cancel"],
      partially_received: ["receive"],
      received: ["settle"],
    };
    const acts = allowed[po.status] ?? [];
    if (acts.includes("submit"))
      buttons.push(<Button key="submit" disabled={busy} onClick={() => transitionMut.mutate("submit")}>Submit</Button>);
    if (acts.includes("approve"))
      buttons.push(<Button key="approve" disabled={busy} onClick={() => transitionMut.mutate("approve")}>Approve</Button>);
    if (acts.includes("order"))
      buttons.push(<Button key="order" disabled={busy} onClick={() => transitionMut.mutate("order")}>Mark Ordered</Button>);
    if (acts.includes("receive"))
      buttons.push(<Button key="receive" variant="secondary" onClick={() => setReceiveOpen(true)}>Receive</Button>);
    if (acts.includes("settle"))
      buttons.push(<Button key="settle" onClick={() => setSettleOpen(true)}>Settle Payment</Button>);
    if (acts.includes("reject"))
      buttons.push(<Button key="reject" variant="outline" onClick={() => setRejectOpen(true)}>Reject</Button>);
    if (acts.includes("cancel"))
      buttons.push(<Button key="cancel" variant="ghost" disabled={busy} onClick={() => transitionMut.mutate("cancel")}>Cancel PO</Button>);
    return buttons;
  }, [po, transitionMut]);

  if (poQuery.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-48 w-full" />
      </div>
    );
  }

  if (poQuery.error instanceof ApiError && poQuery.error.status === 404) {
    return (
      <Card>
        <CardContent className="py-12 text-center text-muted-foreground">
          Purchase order not found (or the Purchasing module is disabled).
          <div className="mt-4">
            <Button variant="outline" onClick={() => navigate("/purchasing")}>
              <ArrowLeft className="mr-2 h-4 w-4" /> Back to Purchasing
            </Button>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (!po) return null;

  return (
    <div className="space-y-6">
      <Button variant="ghost" size="sm" className="-ml-2" onClick={() => navigate("/purchasing")}>
        <ArrowLeft className="mr-2 h-4 w-4" /> Back
      </Button>

      <PageHeader
        title={`PO ${po.po_id}`}
        description={`Supplier ${po.supplier_id}`}
        actions={<div className="flex flex-wrap gap-2">{actions}</div>}
      />

      <div className="flex flex-wrap items-center gap-3">
        <PoStatusBadge status={po.status} />
        <span className="text-sm text-muted-foreground">
          Subtotal <span className="font-medium text-foreground">{formatCents(po.subtotal_cents, po.currency)}</span>
        </span>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Details</CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-4 text-sm sm:grid-cols-3">
          <Detail label="Currency" value={po.currency} />
          <Detail label="Expected delivery" value={po.expected_delivery_date || "—"} />
          <Detail label="Created by" value={po.created_by} />
          <Detail label="Created" value={fmtTs(po.created_at)} />
          <Detail label="Updated" value={fmtTs(po.updated_at)} />
          <Detail label="Approved by" value={po.approved_by || "—"} />
          {po.approved_at != null && <Detail label="Approved at" value={fmtTs(po.approved_at)} />}
          {po.rejected_reason && <Detail label="Rejected reason" value={po.rejected_reason} />}
          {po.paid_at != null && <Detail label="Paid at" value={fmtTs(po.paid_at)} />}
          <Detail label="Correlation ID" value={po.correlation_id} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Line Items</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>#</TableHead>
                <TableHead>SKU</TableHead>
                <TableHead className="text-right">Ordered</TableHead>
                <TableHead className="text-right">Received</TableHead>
                <TableHead className="text-right">Unit cost</TableHead>
                <TableHead className="text-right">Line total</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {po.lines.map((l) => (
                <TableRow key={l.line_no}>
                  <TableCell>{l.line_no}</TableCell>
                  <TableCell className="font-mono text-xs">{l.sku}</TableCell>
                  <TableCell className="text-right">{l.quantity_ordered}</TableCell>
                  <TableCell className="text-right">{l.quantity_received}</TableCell>
                  <TableCell className="text-right">{formatCents(l.unit_cost_cents, po.currency)}</TableCell>
                  <TableCell className="text-right font-medium">
                    {formatCents(l.line_total_cents, po.currency)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Separator />
          <div className="flex justify-end px-4 py-3 text-sm">
            <span className="text-muted-foreground">
              Subtotal:{" "}
              <span className="font-semibold text-foreground">
                {formatCents(po.subtotal_cents, po.currency)}
              </span>
            </span>
          </div>
        </CardContent>
      </Card>

      {apQuery.data && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Accounts Payable</CardTitle>
          </CardHeader>
          <CardContent className="grid grid-cols-2 gap-4 text-sm sm:grid-cols-3">
            <Detail label="Amount" value={formatCents(apQuery.data.amount_cents, po.currency)} />
            <Detail label="State" value={apQuery.data.state} />
            <Detail label="Ledger date" value={apQuery.data.ledger_date} />
            <Detail label="Entry ID" value={apQuery.data.entry_id} />
          </CardContent>
        </Card>
      )}

      <ReceiveDialog po={po} open={receiveOpen} onOpenChange={setReceiveOpen} onDone={refetchAll} />
      <SettleDialog poId={po.po_id} open={settleOpen} onOpenChange={setSettleOpen} onDone={refetchAll} />
      <RejectDialog poId={po.po_id} open={rejectOpen} onOpenChange={setRejectOpen} onDone={refetchAll} />
    </div>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="font-mono text-sm break-all">{value}</div>
    </div>
  );
}
