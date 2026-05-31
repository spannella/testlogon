import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { ShieldAlert, FileText, Gavel } from "lucide-react";
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
import type { DisputeOut } from "@/api/types";

function formatCents(cents: number): string {
  return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" }).format(cents / 100);
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
    case "under_review": return "neutral" as const;
    case "resolved": return "success" as const;
    default: return "neutral" as const;
  }
}

export default function AdminDisputeQueuePage() {
  const [statusFilter, setStatusFilter] = useState("open");
  const [respondDialog, setRespondDialog] = useState<DisputeOut | null>(null);
  const [evidence, setEvidence] = useState("");
  const [resolveDialog, setResolveDialog] = useState<DisputeOut | null>(null);
  const [resolution, setResolution] = useState<"won" | "lost" | "accepted">("won");
  const [resolveNotes, setResolveNotes] = useState("");
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
    onError: (err: Error & { response?: { data?: { detail?: string } } }) => {
      toast.error(String(err?.response?.data?.detail || err.message));
    },
  });

  const resolveMutation = useMutation({
    mutationFn: ({ id, res, notes }: { id: string; res: "won" | "lost" | "accepted"; notes: string }) =>
      adminResolveDispute(id, { resolution: res, notes }),
    onSuccess: () => {
      toast.success("Dispute resolved");
      setResolveDialog(null);
      setResolveNotes("");
      queryClient.invalidateQueries({ queryKey: ["disputes", "admin-queue"] });
    },
    onError: (err: Error & { response?: { data?: { detail?: string } } }) => {
      toast.error(String(err?.response?.data?.detail || err.message));
    },
  });

  const items = query.data?.items ?? [];

  return (
    <div className="mx-auto w-full max-w-4xl space-y-6 p-4 sm:p-6">
      <PageHeader title="Dispute Queue" description="Review and resolve payment disputes" />

      <div className="flex gap-2">
        {["open", "under_review", "resolved"].map((s) => (
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
            <Skeleton key={i} className="h-32 w-full rounded-lg" />
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
                <div className="flex items-center gap-2">
                  <StatusBadge variant={statusVariant(d.status)} className="capitalize">
                    {d.status.replace(/_/g, " ")}
                  </StatusBadge>
                  <span className="font-medium text-sm">{formatCents(d.amount_cents)}</span>
                  <span className="text-xs text-muted-foreground capitalize">({d.provider})</span>
                </div>
                <span className="text-xs text-muted-foreground">{formatDate(d.created_at)}</span>
              </div>

              <p className="text-xs text-muted-foreground">
                User: {d.user_id} | ID: {d.dispute_id}
              </p>

              <p className="text-sm">{d.reason}</p>

              {d.evidence_text && (
                <div className="rounded-md bg-muted p-2 text-xs">
                  <span className="font-medium">Evidence:</span> {d.evidence_text}
                </div>
              )}
              {d.resolution && (
                <div className="rounded-md bg-muted p-2 text-xs">
                  <span className="font-medium">Resolution:</span> {d.resolution}
                </div>
              )}

              {d.status !== "resolved" && (
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
                    onClick={() => { setResolveDialog(d); setResolution("won"); setResolveNotes(""); }}
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
            <div className="space-y-1">
              <Label>Resolution</Label>
              <Select value={resolution} onValueChange={(v) => setResolution(v as "won" | "lost" | "accepted")}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="won">Won</SelectItem>
                  <SelectItem value="lost">Lost</SelectItem>
                  <SelectItem value="accepted">Accepted</SelectItem>
                </SelectContent>
              </Select>
            </div>
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
                if (resolveDialog) {
                  resolveMutation.mutate({ id: resolveDialog.dispute_id, res: resolution, notes: resolveNotes });
                }
              }}
              disabled={resolveMutation.isPending}
            >
              Resolve
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
