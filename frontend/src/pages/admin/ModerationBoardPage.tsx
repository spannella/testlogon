import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { toast } from "sonner";

import { PageHeader } from "@/components/shared/PageHeader";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuthStore } from "@/stores/authStore";
import { canAccessModerationBoard } from "@/lib/adminCapabilities";
import {
  claimModerationTicket,
  resolveModerationTicket,
  getModerationTicketDetail,
  listModerationTickets,
  type ModerationTicket,
} from "@/api/endpoints/moderation";

const QUEUES = ["newsfeed", "messages", "profile"] as const;

function fmt(ts?: number) {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

export default function ModerationBoardPage() {
  const token = useAuthStore((s) => s.accessToken);
  const currentUserSub = useAuthStore((s) => s.userId);
  const canAccess = canAccessModerationBoard(token);

  const [queue, setQueue] = useState<string>("newsfeed");
  const [status, setStatus] = useState<string>("open");
  const [topic, setTopic] = useState<string>("");
  const [assignee, setAssignee] = useState<string>("");
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [selectedTicketId, setSelectedTicketId] = useState<string | null>(null);
  const [resolution, setResolution] = useState<"no_violation" | "content_removed">("no_violation");
  const [enforcementAction, setEnforcementAction] = useState<"none" | "warn" | "ban">("none");
  const [decisionNote, setDecisionNote] = useState<string>("");

  const listQuery = useQuery({
    queryKey: ["moderation-board", queue, status, topic, assignee, cursor],
    queryFn: () =>
      listModerationTickets({
        queue,
        status: status || undefined,
        topic: (topic || undefined) as "sexual" | "extortion" | "criminal" | "spam" | "racist" | undefined,
        assignee: assignee || undefined,
        cursor,
        limit: 20,
      }),
    enabled: canAccess,
  });

  const selectedId = selectedTicketId || listQuery.data?.items?.[0]?.ticket_id || null;

  const detailQuery = useQuery({
    queryKey: ["moderation-board", "detail", selectedId],
    queryFn: () => getModerationTicketDetail(selectedId!),
    enabled: canAccess && !!selectedId,
  });

  const claimMutation = useMutation({
    mutationFn: (ticketId: string) => claimModerationTicket(ticketId),
    onSuccess: () => {
      toast.success("Ticket claimed");
      void listQuery.refetch();
      void detailQuery.refetch();
    },
    onError: (err: unknown) => toast.error(err instanceof Error ? err.message : "Unable to claim ticket"),
  });


  const decisionMutation = useMutation({
    mutationFn: (input: { ticketId: string; resolution: "no_violation" | "content_removed"; enforcement_action: "none" | "warn" | "ban"; note?: string }) =>
      resolveModerationTicket(input.ticketId, { resolution: input.resolution, enforcement_action: input.enforcement_action, note: input.note }),
    onSuccess: () => {
      toast.success("Decision recorded");
      setDecisionNote("");
      void listQuery.refetch();
      void detailQuery.refetch();
    },
    onError: (err: unknown) => toast.error(err instanceof Error ? err.message : "Unable to apply decision"),
  });

  const tickets = listQuery.data?.items ?? [];

  const queueCounts = useMemo(() => {
    const out: Record<string, number> = { newsfeed: 0, messages: 0, profile: 0 };
    for (const t of tickets) out[t.queue] = (out[t.queue] || 0) + 1;
    return out;
  }, [tickets]);

  if (!canAccess) {
    return (
      <div className="space-y-6 p-4 md:p-6 lg:p-8">
        <PageHeader title="Moderation Board" description="Review and assign moderation tickets." />
        <Card>
          <CardHeader><CardTitle>Unauthorized</CardTitle></CardHeader>
          <CardContent className="text-sm text-muted-foreground">You need content moderation admin permissions to access this board.</CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-4 md:p-6 lg:p-8">
      <PageHeader title="Moderation Board" description="Browse queues, filter tickets, and claim work." />

      <div className="grid gap-3 md:grid-cols-3">
        {QUEUES.map((q) => (
          <Button key={q} variant={queue === q ? "default" : "outline"} onClick={() => { setQueue(q); setCursor(undefined); }}>
            {q} <span className="ml-2 text-xs opacity-80">{queueCounts[q] ?? 0}</span>
          </Button>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Filters</CardTitle>
          <CardDescription>Refine by status/topic/assignee.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 md:grid-cols-4">
          <div className="space-y-1">
            <Label htmlFor="mod-status">Status</Label>
            <select id="mod-status" className="h-9 w-full rounded-md border bg-background px-3 text-sm" value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="">All</option>
              <option value="open">open</option>
              <option value="in_review">in_review</option>
              <option value="closed">closed</option>
            </select>
          </div>
          <div className="space-y-1">
            <Label htmlFor="mod-topic">Topic</Label>
            <select id="mod-topic" className="h-9 w-full rounded-md border bg-background px-3 text-sm" value={topic} onChange={(e) => setTopic(e.target.value)}>
              <option value="">All</option>
              <option value="sexual">sexual</option>
              <option value="extortion">extortion</option>
              <option value="criminal">criminal</option>
              <option value="spam">spam</option>
              <option value="racist">racist</option>
            </select>
          </div>
          <div className="space-y-1">
            <Label htmlFor="mod-assignee">Assignee</Label>
            <Input id="mod-assignee" value={assignee} onChange={(e) => setAssignee(e.target.value)} placeholder="admin_user_sub" />
          </div>
          <div className="flex items-end gap-2">
            <Button variant="secondary" onClick={() => { setCursor(undefined); void listQuery.refetch(); }}>Apply</Button>
            <Button variant="outline" onClick={() => { setStatus("open"); setTopic(""); setAssignee(""); setCursor(undefined); }}>Reset</Button>
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-[1.1fr,1.3fr]">
        <Card>
          <CardHeader>
            <CardTitle>Tickets</CardTitle>
            <CardDescription>{listQuery.isLoading ? "Loading moderation tickets..." : "Select a ticket to review."}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {listQuery.isError && <div className="text-sm text-destructive">Failed to load tickets.</div>}
            {!listQuery.isLoading && tickets.length === 0 && <div className="text-sm text-muted-foreground">No tickets found for current filters.</div>}
            <div className="max-h-[460px] space-y-2 overflow-auto">
              {tickets.map((t: ModerationTicket) => (
                <button key={t.ticket_id} className={`w-full rounded-md border p-2 text-left text-sm ${selectedId === t.ticket_id ? "border-primary bg-primary/5" : "hover:bg-muted/30"}`} onClick={() => setSelectedTicketId(t.ticket_id)}>
                  <div className="flex items-center justify-between">
                    <div className="font-medium">{t.ticket_id}</div>
                    <Badge variant="outline">{t.status}</Badge>
                  </div>
                  <div className="mt-1 text-xs text-muted-foreground">{t.queue} • {t.content_type} • reports {t.report_count}</div>
                </button>
              ))}
            </div>
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => void listQuery.refetch()} disabled={listQuery.isFetching}>Refresh</Button>
              <Button variant="outline" onClick={() => setCursor(listQuery.data?.next_cursor || undefined)} disabled={!listQuery.data?.next_cursor}>Next page</Button>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Ticket Detail</CardTitle>
            <CardDescription>{selectedId || "No ticket selected"}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {detailQuery.isLoading && <div className="text-sm text-muted-foreground">Loading ticket detail...</div>}
            {detailQuery.isError && <div className="text-sm text-destructive">Failed to load ticket detail.</div>}
            {detailQuery.data && (
              <>
                <div className="flex flex-wrap gap-2 text-xs">
                  <Badge variant="secondary">{detailQuery.data.ticket.priority}</Badge>
                  <span>Queue: {detailQuery.data.ticket.queue}</span>
                  <span>Assigned: {detailQuery.data.ticket.assigned_admin_user_id || "unassigned"}</span>
                  <span>Updated: {fmt(detailQuery.data.ticket.updated_at)}</span>
                </div>
                <div className="rounded-md border p-3 text-sm">
                  <div className="mb-1 font-medium">Content snapshot</div>
                  <pre className="overflow-auto text-xs">{JSON.stringify(detailQuery.data.content_snapshot, null, 2)}</pre>
                </div>
                <div className="rounded-md border p-3">
                  <div className="mb-2 font-medium text-sm">Linked reports</div>
                  <div className="max-h-[180px] space-y-2 overflow-auto">
                    {detailQuery.data.linked_reports.map((r) => (
                      <div key={r.report_id} className="rounded bg-muted/40 p-2 text-xs">
                        <div className="font-medium">{r.report_id} • {r.reporter_user_id}</div>
                        <div>topics: {r.topics.join(", ") || "—"}</div>
                        <div>{r.reason_text}</div>
                      </div>
                    ))}
                    {detailQuery.data.linked_reports.length === 0 && <div className="text-xs text-muted-foreground">No linked reports.</div>}
                  </div>
                </div>
                <div className="rounded-md border p-3 text-xs">
                  <div>Offender: {detailQuery.data.offender_history_summary.offender_user_id || "unknown"}</div>
                  <div>Total tickets: {detailQuery.data.offender_history_summary.total_tickets}</div>
                  <div>Open tickets: {detailQuery.data.offender_history_summary.open_tickets}</div>
                  <div>Total reports: {detailQuery.data.offender_history_summary.total_reports}</div>
                </div>
                <div className="rounded-md border p-3 text-xs">
                  <div className="mb-2 font-medium text-sm">Prior enforcement history</div>
                  <div className="max-h-[120px] space-y-1 overflow-auto">
                    {detailQuery.data.prior_enforcement_history.length === 0 && (
                      <div className="text-muted-foreground">No prior enforcement actions.</div>
                    )}
                    {detailQuery.data.prior_enforcement_history.map((h) => (
                      <div key={`${h.ticket_id}-${h.decided_at}`} className="rounded bg-muted/40 p-2">
                        <div>{h.ticket_id} • {h.decision} • {h.decided_by || "unknown"}</div>
                        <div className="text-muted-foreground">{h.note || "—"}</div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="rounded-md border p-3 space-y-2">
                  <div className="font-medium text-sm">Decision panel</div>
                  <select
                    className="h-9 w-full rounded-md border bg-background px-3 text-sm"
                    value={resolution}
                    onChange={(e) => {
                      const v = e.target.value as "no_violation" | "content_removed";
                      setResolution(v);
                      if (v === "no_violation") setEnforcementAction("none");
                    }}
                  >
                    <option value="no_violation">no_violation</option>
                    <option value="content_removed">content_removed</option>
                  </select>
                  <select
                    className="h-9 w-full rounded-md border bg-background px-3 text-sm"
                    value={enforcementAction}
                    onChange={(e) => setEnforcementAction(e.target.value as "none" | "warn" | "ban")}
                    disabled={resolution === "no_violation"}
                  >
                    <option value="none">none</option>
                    <option value="warn">warn</option>
                    <option value="ban">ban</option>
                  </select>
                  <Input
                    value={decisionNote}
                    onChange={(e) => setDecisionNote(e.target.value)}
                    placeholder="Decision note (optional)"
                  />
                  <div className="flex gap-2">
                    <Button
                      onClick={() =>
                        selectedId &&
                        decisionMutation.mutate({
                          ticketId: selectedId,
                          resolution,
                          enforcement_action: resolution === "no_violation" ? "none" : enforcementAction,
                          note: decisionNote.trim() || undefined,
                        })
                      }
                      disabled={!selectedId || decisionMutation.isPending}
                    >
                      Apply decision
                    </Button>
                    <Button
                      variant="outline"
                      onClick={() => selectedId && claimMutation.mutate(selectedId)}
                      disabled={!selectedId || claimMutation.isPending || detailQuery.data.ticket.assigned_admin_user_id === currentUserSub}
                    >
                      {detailQuery.data.ticket.assigned_admin_user_id === currentUserSub ? "Claimed by you" : "Claim ticket"}
                    </Button>
                  </div>
                </div>
              </>
            )}
            {!detailQuery.isLoading && !detailQuery.data && !detailQuery.isError && (
              <div className="text-sm text-muted-foreground">Select a ticket from the list to begin moderation.</div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
