import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { AlertTriangle, Clock3 } from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { useAuthStore } from "@/stores/authStore";
import { canAccessPaymentIncidentQueue } from "@/lib/adminCapabilities";
import {
  getPaymentIncidentDetail,
  listPaymentIncidents,
  submitPaymentIncidentResponse,
  uploadPaymentIncidentEvidence,
  type PaymentIncident,
} from "@/api/endpoints/paymentIncidents";

type QueueTab = "disputes" | "payment_failures" | "needs_response_soon";

function timeBadge(dueRaw?: string) {
  if (!dueRaw) return { label: "No due date", overdue: false, urgent: false };
  const dueTs = Number(dueRaw);
  if (!Number.isFinite(dueTs)) return { label: "No due date", overdue: false, urgent: false };
  const remainingSeconds = dueTs - Math.floor(Date.now() / 1000);
  if (remainingSeconds <= 0) return { label: "Overdue", overdue: true, urgent: true };
  const hours = Math.floor(remainingSeconds / 3600);
  if (hours < 24) return { label: `${hours}h left`, overdue: false, urgent: true };
  const days = Math.floor(hours / 24);
  return { label: `${days}d left`, overdue: false, urgent: false };
}

export default function PaymentIncidentQueuePage() {
  const token = useAuthStore((s) => s.accessToken);
  const canAccess = canAccessPaymentIncidentQueue(token);

  const [tab, setTab] = useState<QueueTab>("disputes");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [evidenceSummary, setEvidenceSummary] = useState("");
  const [evidenceFiles, setEvidenceFiles] = useState("");
  const [responseSummary, setResponseSummary] = useState("");
  const [responseRationale, setResponseRationale] = useState("");

  const now = Math.floor(Date.now() / 1000);
  const listQuery = useQuery({
    queryKey: ["admin-payment-incidents", tab],
    queryFn: () => {
      if (tab === "disputes") return listPaymentIncidents({ incident_type: "dispute", limit: 100 });
      if (tab === "payment_failures") return listPaymentIncidents({ incident_type: "payment_failure", limit: 100 });
      return listPaymentIncidents({ due_before_ts: now + 48 * 3600, limit: 100 });
    },
    enabled: canAccess,
  });

  const incidents = useMemo(() => listQuery.data?.items ?? [], [listQuery.data]);
  const selectedIncidentId = selectedId ?? incidents[0]?.incident_id ?? null;

  const detailQuery = useQuery({
    queryKey: ["admin-payment-incident", selectedIncidentId],
    queryFn: () => getPaymentIncidentDetail(selectedIncidentId!),
    enabled: canAccess && !!selectedIncidentId,
  });

  const refresh = () => {
    void listQuery.refetch();
    void detailQuery.refetch();
  };

  const evidenceMutation = useMutation({
    mutationFn: () => uploadPaymentIncidentEvidence(selectedIncidentId!, {
      summary: evidenceSummary.trim() || undefined,
      file_refs: evidenceFiles.split(",").map((x) => x.trim()).filter(Boolean),
      evidence_items: [],
    }),
    onSuccess: () => {
      toast.success("Evidence uploaded");
      setEvidenceSummary("");
      setEvidenceFiles("");
      refresh();
    },
    onError: (err: unknown) => toast.error(err instanceof Error ? err.message : "Unable to upload evidence"),
  });

  const submitMutation = useMutation({
    mutationFn: () => submitPaymentIncidentResponse(selectedIncidentId!, {
      response_summary: responseSummary.trim(),
      rationale: responseRationale.trim() || undefined,
    }),
    onSuccess: () => {
      toast.success("Response submitted");
      setResponseSummary("");
      setResponseRationale("");
      refresh();
    },
    onError: (err: unknown) => toast.error(err instanceof Error ? err.message : "Unable to submit response"),
  });

  if (!canAccess) {
    return (
      <div className="space-y-6 p-4 md:p-6 lg:p-8">
        <PageHeader title="Payment incidents" description="Queue and dispute-response workflow." />
        <Card>
          <CardHeader><CardTitle>Unauthorized</CardTitle></CardHeader>
          <CardContent className="text-sm text-muted-foreground">You need billing support admin permissions to access payment incidents.</CardContent>
        </Card>
      </div>
    );
  }

  const selected = detailQuery.data;

  return (
    <div className="space-y-6 p-4 md:p-6 lg:p-8">
      <PageHeader title="Payment incidents" description="Review disputes, payment failures, and deadlines." />

      <div className="flex flex-wrap gap-2">
        <Button variant={tab === "disputes" ? "default" : "outline"} onClick={() => setTab("disputes")}>Disputes</Button>
        <Button variant={tab === "payment_failures" ? "default" : "outline"} onClick={() => setTab("payment_failures")}>Payment failures</Button>
        <Button variant={tab === "needs_response_soon" ? "default" : "outline"} onClick={() => setTab("needs_response_soon")}>Needs response soon</Button>
      </div>

      <div className="grid gap-4 lg:grid-cols-[1.1fr,1.3fr]">
        <Card>
          <CardHeader>
            <CardTitle>Queue</CardTitle>
            <CardDescription>Select an incident to inspect timeline and actions.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {incidents.length === 0 && !listQuery.isLoading && (
              <div className="text-sm text-muted-foreground">No incidents for this queue.</div>
            )}
            <div className="max-h-[540px] space-y-2 overflow-auto">
              {incidents.map((incident: PaymentIncident) => {
                const badge = timeBadge(incident.response_due_at);
                return (
                  <button
                    key={incident.incident_id}
                    className={`w-full rounded-md border p-3 text-left text-sm ${selectedIncidentId === incident.incident_id ? "border-primary bg-primary/5" : "hover:bg-muted/40"}`}
                    onClick={() => setSelectedId(incident.incident_id)}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <div className="font-medium">{incident.incident_id}</div>
                      <Badge variant={badge.overdue ? "destructive" : "secondary"}>
                        {badge.overdue ? <AlertTriangle className="mr-1 h-3 w-3" /> : <Clock3 className="mr-1 h-3 w-3" />}
                        {badge.label}
                      </Badge>
                    </div>
                    <div className="mt-1 text-xs text-muted-foreground">
                      {incident.provider} • {incident.incident_type} • {incident.status} • {incident.amount || "0"} {incident.currency || "usd"}
                    </div>
                  </button>
                );
              })}
            </div>
            <Button variant="outline" onClick={refresh} disabled={listQuery.isFetching}>Refresh</Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Incident detail</CardTitle>
            <CardDescription>{selectedIncidentId ?? "No incident selected"}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {selected && (
              <>
                <div className="flex flex-wrap gap-2 text-xs">
                  <Badge variant="outline">{selected.status}</Badge>
                  <span>Customer: {selected.customer_id || "—"}</span>
                  <span>Provider: {selected.provider}</span>
                </div>

                <div className="rounded-md border p-3">
                  <div className="mb-2 text-sm font-medium">Timeline</div>
                  <div className="max-h-[140px] space-y-2 overflow-auto">
                    {(selected.events || []).map((evt) => (
                      <div key={`${evt.event_type}-${evt.event_id || evt.created_at || "event"}`} className="rounded bg-muted/40 p-2 text-xs">
                        <div className="font-medium">{evt.event_type}</div>
                        <div className="text-muted-foreground">{evt.created_at || "—"}</div>
                      </div>
                    ))}
                    {(selected.events || []).length === 0 && <div className="text-xs text-muted-foreground">No timeline events yet.</div>}
                  </div>
                </div>

                <div className="rounded-md border p-3">
                  <div className="mb-2 text-sm font-medium">Evidence</div>
                  <div className="mb-2 max-h-[120px] space-y-2 overflow-auto">
                    {(selected.evidence_versions || []).map((ev) => (
                      <div key={ev.version} className="rounded bg-muted/40 p-2 text-xs">
                        Version {ev.version} • {ev.created_at || "—"}
                      </div>
                    ))}
                    {(selected.evidence_versions || []).length === 0 && <div className="text-xs text-muted-foreground">No evidence uploaded.</div>}
                  </div>
                  <Textarea
                    placeholder="Evidence summary"
                    value={evidenceSummary}
                    onChange={(e) => setEvidenceSummary(e.target.value)}
                    className="mb-2"
                  />
                  <Input
                    placeholder="File refs (comma-separated)"
                    value={evidenceFiles}
                    onChange={(e) => setEvidenceFiles(e.target.value)}
                    className="mb-2"
                  />
                  <Button
                    onClick={() => evidenceMutation.mutate()}
                    disabled={!selectedIncidentId || evidenceMutation.isPending}
                  >
                    Upload evidence
                  </Button>
                </div>

                <div className="rounded-md border p-3">
                  <div className="mb-2 text-sm font-medium">Submit response</div>
                  <Textarea
                    placeholder="Response summary"
                    value={responseSummary}
                    onChange={(e) => setResponseSummary(e.target.value)}
                    className="mb-2"
                  />
                  <Textarea
                    placeholder="Rationale (optional)"
                    value={responseRationale}
                    onChange={(e) => setResponseRationale(e.target.value)}
                    className="mb-2"
                  />
                  <Button
                    onClick={() => submitMutation.mutate()}
                    disabled={!selectedIncidentId || !responseSummary.trim() || submitMutation.isPending}
                  >
                    Submit response
                  </Button>
                </div>

                <div className="rounded-md border p-3 text-xs">
                  <div className="mb-1 text-sm font-medium">Ticket link</div>
                  {selected.ticket_link ? (
                    <div>
                      <div>Ticket: {selected.ticket_link.ticket_id}</div>
                      <div className="text-muted-foreground">Linked by {selected.ticket_link.linked_by || "unknown"}</div>
                    </div>
                  ) : (
                    <div className="text-muted-foreground">No linked ticket.</div>
                  )}
                </div>
              </>
            )}
            {!selected && <div className="text-sm text-muted-foreground">Select an incident from the queue.</div>}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
