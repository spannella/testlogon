import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { MessageSquareWarning, Send, Clock } from "lucide-react";
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
import { StatusBadge } from "@/components/shared/StatusBadge";
import { EmptyState } from "@/components/shared/EmptyState";
import { Skeleton } from "@/components/ui/skeleton";
import { PageHeader } from "@/components/shared/PageHeader";
import { toast } from "sonner";
import {
  listCreatorDisputes,
  creatorRespondDispute,
} from "@/api/endpoints/billingDisputes";
import type { DisputeOut } from "@/api/types";

function formatCents(cents: number | null | undefined): string {
  return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" }).format((cents ?? 0) / 100);
}

function formatDate(ts: number | null | undefined): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString(undefined, {
    year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

function statusVariant(status: string) {
  switch (status) {
    case "needs_response": return "warning" as const;
    case "under_review": return "neutral" as const;
    case "escalated": return "warning" as const;
    default: return "neutral" as const;
  }
}

function countdown(respondBy: number | null | undefined): string {
  if (!respondBy) return "";
  const secs = respondBy - Math.floor(Date.now() / 1000);
  if (secs <= 0) return "response window closed";
  const days = Math.floor(secs / 86400);
  const hours = Math.floor((secs % 86400) / 3600);
  if (days > 0) return `${days}d ${hours}h left to respond`;
  return `${hours}h left to respond`;
}

export default function CreatorDisputesPage() {
  const [respondFor, setRespondFor] = useState<DisputeOut | null>(null);
  const [text, setText] = useState("");
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ["disputes", "creator-queue"],
    queryFn: () => listCreatorDisputes(100),
    staleTime: 30_000,
  });

  const respondMutation = useMutation({
    mutationFn: ({ id, response_text }: { id: string; response_text: string }) =>
      creatorRespondDispute(id, { response_text }),
    onSuccess: () => {
      toast.success("Your response was submitted");
      setRespondFor(null);
      setText("");
      queryClient.invalidateQueries({ queryKey: ["disputes", "creator-queue"] });
    },
    onError: (err: Error & { response?: { data?: { detail?: unknown } } }) => {
      const detail = err?.response?.data?.detail as { message?: string } | string | undefined;
      toast.error(
        detail && typeof detail === "object" && detail.message
          ? detail.message
          : String(detail ?? err.message),
      );
    },
  });

  const items = query.data?.items ?? [];

  return (
    <div className="mx-auto w-full max-w-3xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Disputes to respond to"
        description="Buyers have disputed these charges. Submit your rebuttal within the window."
      />

      {query.isLoading && (
        <div className="space-y-3">
          {Array.from({ length: 2 }).map((_, i) => (
            <Skeleton key={i} className="h-32 w-full rounded-lg" />
          ))}
        </div>
      )}

      {!query.isLoading && items.length === 0 && (
        <EmptyState
          icon={<MessageSquareWarning className="h-6 w-6" />}
          title="No disputes"
          description="You have no open disputes against your sales."
        />
      )}

      <div className="space-y-3">
        {items.map((d: DisputeOut) => {
          const canRespond = d.status === "needs_response";
          return (
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
                  </div>
                  <span className="text-xs text-muted-foreground">{formatDate(d.created_at)}</span>
                </div>

                <p className="text-sm">
                  <span className="font-medium capitalize">{d.reason.replace(/_/g, " ")}</span>
                  {d.reason_detail ? ` — ${d.reason_detail}` : ""}
                </p>

                {d.creator_response && (
                  <div className="rounded-md border border-border bg-muted/40 p-2 text-xs">
                    <span className="font-medium">Your response:</span> {d.creator_response}
                  </div>
                )}

                {canRespond && d.respond_by ? (
                  <p className="flex items-center gap-1 text-xs text-amber-600">
                    <Clock className="h-3.5 w-3.5" /> {countdown(d.respond_by)}
                  </p>
                ) : null}

                {canRespond && (
                  <Button size="sm" onClick={() => { setRespondFor(d); setText(""); }}>
                    <Send className="mr-1 h-3.5 w-3.5" /> Respond
                  </Button>
                )}
                {!canRespond && !d.creator_response && (
                  <p className="text-xs text-muted-foreground">Awaiting admin review.</p>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>

      <Dialog open={!!respondFor} onOpenChange={(o) => { if (!o) setRespondFor(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Respond to dispute</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <p className="text-xs text-muted-foreground">
              Explain why this charge is valid. Your rebuttal is shown to the admin who decides the
              dispute.
            </p>
            <Label htmlFor="creator-response">Your rebuttal</Label>
            <Textarea
              id="creator-response"
              value={text}
              onChange={(e) => setText(e.target.value)}
              rows={5}
              placeholder="Provide delivery proof, receipts, or context showing the charge was legitimate..."
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRespondFor(null)}>Cancel</Button>
            <Button
              onClick={() => {
                if (respondFor) respondMutation.mutate({ id: respondFor.dispute_id, response_text: text });
              }}
              disabled={!text.trim() || respondMutation.isPending}
            >
              Submit response
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
