import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { ShieldAlert, FileText, Gavel, Link2, AlertTriangle, ArrowRightLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { EmptyState } from "@/components/shared/EmptyState";
import { Skeleton } from "@/components/ui/skeleton";
import { PageHeader } from "@/components/shared/PageHeader";
import { toast } from "sonner";
import {
  adminListDisputes,
  adminRespondDispute,
  adminResolveDispute,
} from "@/api/endpoints/billingDisputes";
import type { DisputeOut, DisputeResolveIn } from "@/api/types";

type Resolution = "refunded" | "partial" | "denied";
const MONEY_MOVING: Resolution[] = ["refunded", "partial"];

function formatCents(cents: number | null | undefined): string {
  return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" }).format((cents ?? 0) / 100);
}

function formatDate(ts: number): string {
  return new Date(ts * 1000).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function statusVariant(status: string) {
  switch (status) {
    case "open": return "warning" as const;
    case "needs_response": return "warning" as const;
    case "under_review": return "neutral" as const;
    case "escalated": return "warning" as const;
    case "resolved": return "success" as const;
    case "withdrawn": return "neutral" as const;
    default: return "neutral" as const;
  }
}

export default function AdminDisputeQueuePage() {
  const [statusFilter, setStatusFilter] = useState("under_review");
  const [respondDialog, setRespondDialog] = useState<DisputeOut | null>(null);
  const [evidence, setEvidence] = useState("");
  const [resolveDialog, setResolveDialog] = useState<DisputeOut | null>(null);
  const [resolution, setResolution] = useState<Resolution>("refunded");
  const [partialAmount, setPartialAmount] = useState("");
  const [resolveNotes, setResolveNotes] = useState("");
  const [secondApprover, setSecondApprover] = useState("");
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ["disputes", "admin-queue", { status: statusFilter }],
    queryFn: () => adminListDisputes(statusFilter, 100),
    staleTime: 30_000,
  });

  const respondMutation = useMutation({
    mutationFn: ({ id, text }: { id: string; text: string }) =>
      adminRespondDispute(id, { evidence_text: text }),
    onSuccess: () => {
      toast.success("Evidence submitted");
      setRespondDialog(null);
      setEvidence("");
      queryClient.invalidateQueries({ queryKey: ["disputes", "admin-queue"] });
    },
    onError: (err: Error & { response?: { data?: { detail?: unknown } } }) => {
      toast.error(String(err?.response?.data?.detail ?? err.message));
    },
  });

  const resolveMutation = useMutation({
    mutationFn: (body: DisputeResolveIn & { id: string }) => {
      const { id, ...rest } = body;
      return adminResolveDispute(id, rest);
    },
    onSuccess: (data) => {
      toast.success(
        data.resolution === "denied"
          ? "Dispute denied (no money moved)"
          : `Dispute resolved — ${formatCents(data.moved_cents)} moved`,
      );
      setResolveDialog(null);
      setResolveNotes("");
      setSecondApprover("");
      setPartialAmount("");
      queryClient.invalidateQueries({ queryKey: ["disputes", "admin-queue"] });
    },
    onError: (err: Error & { response?: { data?: { detail?: unknown } } }) => {
      const detail = err?.response?.data?.detail as
        | { code?: string; message?: string }
        | string
        | undefined;
      if (detail && typeof detail === "object" && detail.code === "dual_approval_required") {
        toast.error("A second payment-disputes admin must approve a refund of this size.");
      } else if (detail && typeof detail === "object" && detail.message) {
        toast.error(detail.message);
      } else {
        toast.error(String(detail ?? err.message));
      }
    },
  });

  const items = query.data?.items ?? [];

  // The dual-approval field is required when a money-moving resolution is chosen
  // and the clawback amount is at/above the threshold. We surface the field
  // conditionally; the server is the source of truth and rejects if missing.
  const resolveTarget = resolveDialog;
  const railPreview = resolveTarget?.rail_preview;
  const moneyMoving = MONEY_MOVING.includes(resolution);
  const clawback = resolution === "partial"
    ? Number(partialAmount) * 100 || 0
    : (railPreview?.clawback_cents ?? resolveTarget?.amount_cents ?? 0);

  return (
    <div className="mx-auto w-full max-w-4xl space-y-6 p-4 sm:p-6">
      <PageHeader title="Payment Dispute Queue" description="Review, respond to, and resolve payment disputes" />

      <div className="flex flex-wrap gap-2">
        {["open", "needs_response", "under_review", "escalated", "resolved"].map((s) => (
          <Button
            key={s}
            variant={statusFilter === s ? "default" : "outline"}
            size="sm"
            onClick={() => setStatusFilter(s)}
            className="capitalize"
          >
            {s.replace(/_/g, " ")}
          </Button>
        ))}
      </div>

      {query.isLoading && (
        <div className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-40 w-full rounded-lg" />
          ))}
        </div>
      )}

      {!query.isLoading && items.length === 0 && (
        <EmptyState
          icon={<ShieldAlert className="h-6 w-6" />}
          title={`No ${statusFilter.replace(/_/g, " ")} disputes`}
          description="All clear."
        />
      )}

      <div className="space-y-3">
        {items.map((d: DisputeOut) => (
          <Card key={d.dispute_id}>
            <CardContent className="p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex flex-wrap items-center gap-2">
                  <StatusBadge variant={statusVariant(d.status)} className="capitalize">
                    {d.status.replace(/_/g, " ")}
                  </StatusBadge>
                  <span className="font-medium text-sm">{formatCents(d.amount_cents)}</span>
                  {d.charge_type && (
                    <span className="rounded bg-muted px-1.5 py-0.5 text-[11px] capitalize text-muted-foreground">
                      {d.charge_type}
                    </span>
                  )}
                  {d.serial_disputer && (
                    <span className="inline-flex items-center gap-1 rounded bg-destructive/10 px-1.5 py-0.5 text-[11px] text-destructive">
                      <AlertTriangle className="h-3 w-3" /> serial disputer
                    </span>
                  )}
                </div>
                <span className="text-xs text-muted-foreground">{formatDate(d.created_at)}</span>
              </div>

              <p className="text-xs text-muted-foreground">
                Payer: {d.user_id} {d.recipient_id ? `→ Creator: ${d.recipient_id}` : ""} | ID: {d.dispute_id}
              </p>

              <p className="text-sm">
                <span className="font-medium capitalize">{d.reason.replace(/_/g, " ")}</span>
                {d.reason_detail ? ` — ${d.reason_detail}` : ""}
              </p>

              {/* DISP-021: creator rebuttal */}
              {d.creator_response && (
                <div className="rounded-md border border-border bg-muted/40 p-2 text-xs">
                  <span className="font-medium">Creator rebuttal:</span> {d.creator_response}
                </div>
              )}

              {/* DISP-022: rail preview + clawback */}
              {d.rail_preview && (
                <div className="rounded-md border border-dashed border-border p-2 text-xs">
                  <div className="flex items-center gap-1 font-medium">
                    <ArrowRightLeft className="h-3.5 w-3.5" /> Refund preview
                  </div>
                  <div className="mt-1 grid gap-0.5 text-muted-foreground">
                    <span>
                      Rail: <span className="font-mono">{d.rail_preview.rail ?? "—"}</span>
                      {d.rail_preview.rail_available ? "" : " (unavailable)"}
                    </span>
                    <span>Creator clawback: {formatCents(d.rail_preview.clawback_cents)}</span>
                    <span>Partial refund: {d.rail_preview.partial_supported ? "supported" : "not supported"}</span>
                    {d.rail_preview.note ? <span className="text-amber-600">{d.rail_preview.note}</span> : null}
                  </div>
                </div>
              )}

              {/* DISP-022: linked processor incident */}
              {d.linked_incident && (
                <div className="flex items-center gap-1 rounded-md bg-muted p-2 text-xs">
                  <Link2 className="h-3.5 w-3.5" />
                  <span className="font-medium">Processor chargeback:</span>
                  <span className="font-mono">{d.linked_incident.incident_id}</span>
                  {d.linked_incident.status ? <span className="capitalize">({d.linked_incident.status})</span> : null}
                </div>
              )}

              {d.resolution && (
                <div className="rounded-md bg-muted p-2 text-xs">
                  <span className="font-medium capitalize">Resolution:</span> {d.resolution}
                  {typeof d.moved_cents === "number" && d.moved_cents > 0
                    ? ` — ${formatCents(d.moved_cents)} moved`
                    : ""}
                </div>
              )}

              {d.status !== "resolved" && d.status !== "withdrawn" && (
                <div className="flex gap-2 pt-1">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => { setRespondDialog(d); setEvidence(""); }}
                  >
                    <FileText className="mr-1 h-3.5 w-3.5" /> Submit Evidence
                  </Button>
                  <Button
                    size="sm"
                    onClick={() => {
                      setResolveDialog(d);
                      setResolution("refunded");
                      setResolveNotes("");
                      setSecondApprover("");
                      setPartialAmount("");
                    }}
                  >
                    <Gavel className="mr-1 h-3.5 w-3.5" /> Resolve
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Evidence dialog */}
      <Dialog open={!!respondDialog} onOpenChange={(o) => { if (!o) setRespondDialog(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Submit Dispute Evidence</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <Label htmlFor="evidence-text">Evidence</Label>
            <Textarea
              id="evidence-text"
              placeholder="Describe the evidence contesting this dispute..."
              value={evidence}
              onChange={(e) => setEvidence(e.target.value)}
              rows={4}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRespondDialog(null)}>Cancel</Button>
            <Button
              onClick={() => {
                if (respondDialog) {
                  respondMutation.mutate({ id: respondDialog.dispute_id, text: evidence });
                }
              }}
              disabled={!evidence.trim() || respondMutation.isPending}
            >
              Submit
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Resolve dialog */}
      <Dialog open={!!resolveDialog} onOpenChange={(o) => { if (!o) setResolveDialog(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Resolve Dispute</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-2">
            {resolveTarget && (
              <div className="rounded-md bg-muted p-2 text-xs text-muted-foreground">
                {formatCents(resolveTarget.amount_cents)} · {resolveTarget.charge_type ?? "unclassified"}
                {" · rail "}
                <span className="font-mono">{railPreview?.rail ?? "—"}</span>
              </div>
            )}
            <div className="space-y-1">
              <Label>Decision</Label>
              <Select value={resolution} onValueChange={(v) => setResolution(v as Resolution)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="refunded">Refund (buyer refunded, creator clawed back)</SelectItem>
                  <SelectItem value="partial" disabled={!railPreview?.partial_supported}>
                    Partial refund{railPreview?.partial_supported ? "" : " (not supported for this charge)"}
                  </SelectItem>
                  <SelectItem value="denied">Deny (no money moves)</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {resolution === "partial" && (
              <div className="space-y-1">
                <Label htmlFor="partial-amt">Partial amount (USD)</Label>
                <Input
                  id="partial-amt"
                  type="number"
                  min="0.01"
                  step="0.01"
                  value={partialAmount}
                  onChange={(e) => setPartialAmount(e.target.value)}
                  placeholder="e.g. 12.50"
                />
              </div>
            )}

            {moneyMoving && (
              <div className="rounded-md border border-dashed p-2 text-xs">
                This will move <span className="font-medium">{formatCents(clawback)}</span> off the creator
                and refund the buyer.
              </div>
            )}

            {/* DISP-022: dual-approval — surfaced when a money-moving decision is large.
                The server validates the approver; this is a convenience field. */}
            {moneyMoving && (
              <div className="space-y-1">
                <Label htmlFor="second-approver">Second approver admin id (required for large refunds)</Label>
                <Input
                  id="second-approver"
                  value={secondApprover}
                  onChange={(e) => setSecondApprover(e.target.value)}
                  placeholder="admin user id of a second payment-disputes admin"
                />
              </div>
            )}

            <div className="space-y-1">
              <Label htmlFor="resolve-notes">Notes (optional)</Label>
              <Textarea
                id="resolve-notes"
                value={resolveNotes}
                onChange={(e) => setResolveNotes(e.target.value)}
                rows={3}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setResolveDialog(null)}>Cancel</Button>
            <Button
              onClick={() => {
                if (!resolveDialog) return;
                const body: DisputeResolveIn & { id: string } = {
                  id: resolveDialog.dispute_id,
                  resolution,
                  notes: resolveNotes || undefined,
                };
                if (resolution === "partial") {
                  body.override_amount_cents = Math.round(Number(partialAmount) * 100) || undefined;
                }
                if (moneyMoving && secondApprover.trim()) {
                  body.second_approver_admin_user_id = secondApprover.trim();
                }
                resolveMutation.mutate(body);
              }}
              disabled={
                resolveMutation.isPending ||
                (resolution === "partial" && !(Number(partialAmount) > 0))
              }
            >
              {resolution === "denied" ? "Deny" : "Resolve & Refund"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
