import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { PackageCheck, RefreshCw } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
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
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";

import {
  approveReturn,
  closeReturn,
  formatCents,
  listReturnsQueue,
  receiveReturn,
  refundReturn,
  rejectReturn,
  type ReturnRecord,
  type ReturnStatus,
} from "@/api/endpoints/erp";
import { errMessage, fmtTs, isNotEnabledError, NotEnabledCard } from "./erpShared";

const STATUS_TABS: { value: ReturnStatus; label: string }[] = [
  { value: "requested", label: "Requested" },
  { value: "approved", label: "Approved" },
  { value: "received", label: "Received" },
  { value: "refunded", label: "Refunded" },
  { value: "rejected", label: "Rejected" },
  { value: "closed", label: "Closed" },
];

function statusBadge(status: ReturnStatus) {
  switch (status) {
    case "requested":
      return <Badge variant="warning">Requested</Badge>;
    case "approved":
      return <Badge variant="default">Approved</Badge>;
    case "received":
      return <Badge variant="secondary">Received</Badge>;
    case "refunded":
      return <Badge variant="success">Refunded</Badge>;
    case "rejected":
      return <Badge variant="destructive">Rejected</Badge>;
    case "closed":
      return <Badge variant="outline">Closed</Badge>;
    default:
      return <Badge variant="outline">{status}</Badge>;
  }
}

type RmaAction = "approve" | "reject" | "receive" | "refund" | "close";

/** Which actions are available for each return status (next-state transitions). */
function actionsFor(status: ReturnStatus): RmaAction[] {
  switch (status) {
    case "requested":
      return ["approve", "reject"];
    case "approved":
      return ["receive", "reject"];
    case "received":
      return ["refund"];
    case "refunded":
      return ["close"];
    default:
      return [];
  }
}

export default function ReturnsPage() {
  const qc = useQueryClient();
  const [statusTab, setStatusTab] = useState<ReturnStatus>("requested");
  const [detail, setDetail] = useState<ReturnRecord | null>(null);

  // Note dialog for approve/reject
  const [noteDialog, setNoteDialog] = useState<{ ret: ReturnRecord; action: "approve" | "reject" } | null>(null);
  const [noteText, setNoteText] = useState("");

  const queueQuery = useQuery({
    queryKey: ["erp", "returns", "queue", statusTab],
    queryFn: () => listReturnsQueue(statusTab),
    retry: false,
  });

  const notEnabled = isNotEnabledError(queueQuery.error);

  function refresh() {
    void qc.invalidateQueries({ queryKey: ["erp", "returns"] });
  }

  const actionMut = useMutation({
    mutationFn: async ({ ret, action, note }: { ret: ReturnRecord; action: RmaAction; note?: string }) => {
      switch (action) {
        case "approve":
          return approveReturn(ret.return_id, note);
        case "reject":
          return rejectReturn(ret.return_id, note);
        case "receive":
          return receiveReturn(ret.return_id);
        case "refund":
          return refundReturn(ret.return_id);
        case "close":
          return closeReturn(ret.return_id);
      }
    },
    onSuccess: (rec) => {
      toast.success(`Return ${rec?.return_id} → ${rec?.status}`);
      setNoteDialog(null);
      setNoteText("");
      if (detail && rec && detail.return_id === rec.return_id) setDetail(rec);
      refresh();
    },
    onError: (err) => toast.error(errMessage(err, "Action failed")),
  });

  function runAction(ret: ReturnRecord, action: RmaAction) {
    if (action === "approve" || action === "reject") {
      setNoteDialog({ ret, action });
      setNoteText("");
      return;
    }
    actionMut.mutate({ ret, action });
  }

  const returns = queueQuery.data?.returns ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Returns / RMA Queue"
        description="Review and process customer return requests through the RMA lifecycle."
        actions={
          <Button variant="outline" size="sm" onClick={refresh} disabled={queueQuery.isFetching}>
            <RefreshCw className={`mr-2 h-4 w-4 ${queueQuery.isFetching ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        }
      />

      {notEnabled ? (
        <NotEnabledCard module="Returns / RMA" flag="RETURNS_RMA_ENABLED" />
      ) : (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <PackageCheck className="h-4 w-4" /> RMA queue
            </CardTitle>
            <CardDescription>Returns grouped by lifecycle status.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Tabs value={statusTab} onValueChange={(v) => setStatusTab(v as ReturnStatus)}>
              <TabsList className="flex-wrap">
                {STATUS_TABS.map((t) => (
                  <TabsTrigger key={t.value} value={t.value}>
                    {t.label}
                  </TabsTrigger>
                ))}
              </TabsList>
            </Tabs>

            {queueQuery.isLoading ? (
              <div className="space-y-2">
                <Skeleton className="h-10 w-full" />
                <Skeleton className="h-10 w-full" />
                <Skeleton className="h-10 w-full" />
              </div>
            ) : returns.length === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">
                No returns in the "{STATUS_TABS.find((t) => t.value === statusTab)?.label}" state.
              </p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Return ID</TableHead>
                    <TableHead>Order</TableHead>
                    <TableHead>Customer</TableHead>
                    <TableHead>Reason</TableHead>
                    <TableHead className="text-right">Lines</TableHead>
                    <TableHead className="text-right">Refund</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {returns.map((ret) => (
                    <TableRow
                      key={ret.return_id}
                      className="cursor-pointer"
                      onClick={() => setDetail(ret)}
                    >
                      <TableCell className="font-mono text-xs">{ret.return_id}</TableCell>
                      <TableCell className="font-mono text-xs">{ret.order_id}</TableCell>
                      <TableCell className="max-w-[140px] truncate text-xs">{ret.user_sub}</TableCell>
                      <TableCell className="max-w-[200px] truncate">{ret.reason ?? "—"}</TableCell>
                      <TableCell className="text-right">{ret.lines.length}</TableCell>
                      <TableCell className="text-right">
                        {formatCents(ret.refund_amount_cents, ret.currency)}
                      </TableCell>
                      <TableCell>{statusBadge(ret.status)}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{fmtTs(ret.created_at)}</TableCell>
                      <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                        <div className="flex justify-end gap-1">
                          {actionsFor(ret.status).map((action) => (
                            <Button
                              key={action}
                              size="sm"
                              variant={action === "reject" ? "destructive" : "outline"}
                              disabled={actionMut.isPending}
                              onClick={() => runAction(ret, action)}
                            >
                              {action.charAt(0).toUpperCase() + action.slice(1)}
                            </Button>
                          ))}
                          {actionsFor(ret.status).length === 0 && (
                            <span className="text-xs text-muted-foreground">—</span>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}

      {/* Detail drawer dialog */}
      <Dialog open={!!detail} onOpenChange={(o) => !o && setDetail(null)}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              Return {detail?.return_id} {detail && statusBadge(detail.status)}
            </DialogTitle>
            <DialogDescription>Order {detail?.order_id}</DialogDescription>
          </DialogHeader>

          {detail && (
            <ScrollArea className="max-h-[60vh] pr-3">
              <div className="space-y-4 text-sm">
                <div className="grid grid-cols-2 gap-2">
                  <Field label="Customer" value={detail.user_sub} mono />
                  <Field label="Currency" value={detail.currency.toUpperCase()} />
                  <Field label="Refund amount" value={formatCents(detail.refund_amount_cents, detail.currency)} />
                  <Field label="Provider" value={detail.provider ?? "—"} />
                  <Field label="Created" value={fmtTs(detail.created_at)} />
                  <Field label="Updated" value={fmtTs(detail.updated_at)} />
                  <Field label="Decided by" value={detail.decided_by ?? "—"} />
                  <Field label="Ledger SK" value={detail.refund_ledger_sk ?? "—"} mono />
                </div>

                <div>
                  <Label className="text-xs text-muted-foreground">Reason</Label>
                  <p className="mt-1">{detail.reason ?? "—"}</p>
                </div>

                {detail.decision_note && (
                  <div>
                    <Label className="text-xs text-muted-foreground">Decision note</Label>
                    <p className="mt-1">{detail.decision_note}</p>
                  </div>
                )}

                <div>
                  <Label className="text-xs text-muted-foreground">Lines</Label>
                  <Table className="mt-1">
                    <TableHeader>
                      <TableRow>
                        <TableHead>Item</TableHead>
                        <TableHead>SKU</TableHead>
                        <TableHead className="text-right">Qty</TableHead>
                        <TableHead className="text-right">Amount</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {detail.lines.map((ln, i) => (
                        <TableRow key={`${ln.item_id}:${i}`}>
                          <TableCell className="font-mono text-xs">{ln.item_id}</TableCell>
                          <TableCell className="font-mono text-xs">{ln.sku ?? "—"}</TableCell>
                          <TableCell className="text-right">{ln.quantity}</TableCell>
                          <TableCell className="text-right">{formatCents(ln.amount_cents, detail.currency)}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </div>
            </ScrollArea>
          )}

          {detail && actionsFor(detail.status).length > 0 && (
            <DialogFooter>
              {actionsFor(detail.status).map((action) => (
                <Button
                  key={action}
                  variant={action === "reject" ? "destructive" : "default"}
                  disabled={actionMut.isPending}
                  onClick={() => runAction(detail, action)}
                >
                  {action.charAt(0).toUpperCase() + action.slice(1)}
                </Button>
              ))}
            </DialogFooter>
          )}
        </DialogContent>
      </Dialog>

      {/* Approve/reject note dialog */}
      <Dialog open={!!noteDialog} onOpenChange={(o) => !o && setNoteDialog(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {noteDialog?.action === "approve" ? "Approve" : "Reject"} return {noteDialog?.ret.return_id}
            </DialogTitle>
            <DialogDescription>Optionally add a note explaining the decision.</DialogDescription>
          </DialogHeader>
          <div className="space-y-1">
            <Label htmlFor="rma-note">Note (optional)</Label>
            <Textarea
              id="rma-note"
              value={noteText}
              onChange={(e) => setNoteText(e.target.value)}
              placeholder="e.g. Outside 30-day window"
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setNoteDialog(null)}>
              Cancel
            </Button>
            <Button
              variant={noteDialog?.action === "reject" ? "destructive" : "default"}
              disabled={actionMut.isPending}
              onClick={() =>
                noteDialog &&
                actionMut.mutate({ ret: noteDialog.ret, action: noteDialog.action, note: noteText.trim() || undefined })
              }
            >
              {actionMut.isPending ? "Working…" : noteDialog?.action === "approve" ? "Approve" : "Reject"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <Label className="text-xs text-muted-foreground">{label}</Label>
      <p className={`mt-0.5 break-all ${mono ? "font-mono text-xs" : ""}`}>{value}</p>
    </div>
  );
}
