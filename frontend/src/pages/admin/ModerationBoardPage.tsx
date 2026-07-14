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
  bulkModerationAction,
  claimModerationTicket,
  confirmModerationCase,
  dismissModerationCase,
  finalCallModerationCase,
  getModerationKpis,
  getModerationTicketDetail,
  listModerationBans,
  liftModerationBan,
  listModerationTickets,
  type ModerationTicket,
  type ModerationTopic,
} from "@/api/endpoints/moderation";

// MODX-17 (D2): "All" omits the queue filter so video/video_comment/syndicate_post tickets
// (which fall to the `general` queue) are no longer invisible; the General tab surfaces them.
const QUEUE_TABS: Array<{ key: string; label: string; queue?: string }> = [
  { key: "all", label: "All", queue: undefined },
  { key: "newsfeed", label: "Newsfeed", queue: "newsfeed" },
  { key: "messages", label: "Messages", queue: "messages" },
  { key: "profile", label: "Profile", queue: "profile" },
  { key: "general", label: "Video / Syndicate / General", queue: "general" },
];

// MODX-18 (D5): live 6-category taxonomy + illegal lane.
const TOPICS: ModerationTopic[] = ["sexual", "violence_threats", "hate", "harassment", "spam", "other", "illegal"];

function fmt(ts?: number | null) {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

function holdCountdown(holdUntil?: number | null): string {
  if (!holdUntil) return "—";
  const secs = holdUntil - Math.floor(Date.now() / 1000);
  if (secs <= 0) return "expired";
  const days = Math.floor(secs / 86400);
  const hours = Math.floor((secs % 86400) / 3600);
  return `${days}d ${hours}h remaining`;
}

export default function ModerationBoardPage() {
  const token = useAuthStore((s) => s.accessToken);
  const currentUserSub = useAuthStore((s) => s.userId);
  const canAccess = canAccessModerationBoard(token);

  const [queueKey, setQueueKey] = useState<string>("all");
  const [status, setStatus] = useState<string>("open");
  const [topic, setTopic] = useState<string>("");
  const [assignee, setAssignee] = useState<string>("");
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [selectedTicketId, setSelectedTicketId] = useState<string | null>(null);
  const [note, setNote] = useState<string>("");
  const [banOnDelete, setBanOnDelete] = useState<boolean>(false);
  const [banDurationDays, setBanDurationDays] = useState<string>("");
  const [secondApprover, setSecondApprover] = useState<string>("");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [showBans, setShowBans] = useState<boolean>(false);

  const activeQueue = QUEUE_TABS.find((t) => t.key === queueKey)?.queue;

  const kpiQuery = useQuery({ queryKey: ["moderation-kpis"], queryFn: getModerationKpis, enabled: canAccess });

  const listQuery = useQuery({
    queryKey: ["moderation-board", queueKey, status, topic, assignee, cursor],
    queryFn: () =>
      listModerationTickets({
        queue: activeQueue,
        status: status || undefined,
        topic: (topic || undefined) as ModerationTopic | undefined,
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

  const bansQuery = useQuery({ queryKey: ["moderation-bans"], queryFn: () => listModerationBans(false), enabled: canAccess && showBans });

  const refetchAll = () => {
    void listQuery.refetch();
    void detailQuery.refetch();
    void kpiQuery.refetch();
  };

  const claimMutation = useMutation({
    mutationFn: (ticketId: string) => claimModerationTicket(ticketId),
    onSuccess: () => { toast.success("Ticket claimed"); refetchAll(); },
    onError: (err: unknown) => toast.error(err instanceof Error ? err.message : "Unable to claim ticket"),
  });

  // MODX-17 (D1): the STATE-MACHINE actions (dismiss / confirm-30d-hold / final-call).
  const dismissMutation = useMutation({
    mutationFn: (ticketId: string) => dismissModerationCase(ticketId),
    onSuccess: () => { toast.success("Case dismissed (content restored)"); setNote(""); refetchAll(); },
    onError: (err: unknown) => toast.error(err instanceof Error ? err.message : "Unable to dismiss case"),
  });

  const confirmMutation = useMutation({
    mutationFn: (ticketId: string) => confirmModerationCase(ticketId),
    onSuccess: () => { toast.success("Violation confirmed — 30-day hold started"); refetchAll(); },
    onError: (err: unknown) => toast.error(err instanceof Error ? err.message : "Unable to confirm violation"),
  });

  const finalCallMutation = useMutation({
    mutationFn: (input: { ticketId: string; action: "reinstate" | "delete" }) =>
      finalCallModerationCase(input.ticketId, {
        action: input.action,
        note: note.trim() || undefined,
        ban: input.action === "delete" ? banOnDelete : false,
        ban_duration_days: input.action === "delete" && banOnDelete ? Number(banDurationDays || 0) : undefined,
        second_approver_admin_user_id: secondApprover.trim() || undefined,
      }),
    onSuccess: (_data, vars) => {
      toast.success(vars.action === "reinstate" ? "Content reinstated" : "Content deleted");
      setNote("");
      refetchAll();
    },
    onError: (err: unknown) => toast.error(err instanceof Error ? err.message : "Unable to complete final call"),
  });

  const bulkMutation = useMutation({
    mutationFn: (action: "dismiss" | "confirm" | "reinstate" | "delete") =>
      bulkModerationAction({ ticket_ids: [...selectedIds], action, note: note.trim() || undefined }),
    onSuccess: (res) => {
      toast.success(`${res.action}: ${res.succeeded} done, ${res.failed} failed`);
      setSelectedIds(new Set());
      refetchAll();
    },
    onError: (err: unknown) => toast.error(err instanceof Error ? err.message : "Bulk action failed"),
  });

  const liftBanMutation = useMutation({
    mutationFn: (userId: string) => liftModerationBan(userId, "lifted from board"),
    onSuccess: () => { toast.success("Ban lifted"); void bansQuery.refetch(); },
    onError: (err: unknown) => toast.error(err instanceof Error ? err.message : "Unable to lift ban"),
  });

  const tickets = listQuery.data?.items ?? [];
  const kpis = kpiQuery.data;

  const toggleSelected = (id: string) =>
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const detail = detailQuery.data;
  const caseState = detail?.case_state ?? "";
  const canDismissConfirm = caseState === "under_review" || caseState === "visible";
  const canFinalCall = caseState === "hold" || caseState === "awaiting_final";

  const banList = bansQuery.data?.items ?? [];

  const kpiCards = useMemo(
    () =>
      kpis
        ? [
            { label: "Open backlog", value: kpis.open_ticket_count, hint: "excludes parked holds" },
            { label: "On hold", value: kpis.on_hold_count, hint: "30-day poster holds" },
            { label: "Critical", value: kpis.critical_backlog },
            { label: "Oldest open", value: `${kpis.oldest_open_age_minutes}m` },
            { label: "Resolved (window)", value: kpis.resolution_count },
            { label: "P95 latency", value: `${Math.round(kpis.resolution_latency_p95_seconds / 60)}m` },
          ]
        : [],
    [kpis],
  );

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
      <PageHeader title="Moderation Board" description="Drive the 30-day-hold state machine, filter queues, and manage bans." />

      {/* MODX-18 (D12): KPI header strip (backlog now excludes parked holds). */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-6">
        {kpiCards.map((k) => (
          <Card key={k.label}>
            <CardContent className="p-3">
              <div className="text-xs text-muted-foreground">{k.label}</div>
              <div className="text-xl font-semibold">{k.value}</div>
              {k.hint && <div className="text-[10px] text-muted-foreground">{k.hint}</div>}
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="flex flex-wrap gap-2">
        {QUEUE_TABS.map((t) => (
          <Button key={t.key} variant={queueKey === t.key ? "default" : "outline"} onClick={() => { setQueueKey(t.key); setCursor(undefined); }}>
            {t.label}
          </Button>
        ))}
        <Button variant={showBans ? "default" : "secondary"} onClick={() => setShowBans((v) => !v)}>
          Ban management
        </Button>
      </div>

      {showBans && (
        <Card>
          <CardHeader>
            <CardTitle>Active bans</CardTitle>
            <CardDescription>Lift a wrongful or permanent ban (restores account + closes the enforcement row).</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {bansQuery.isLoading && <div className="text-sm text-muted-foreground">Loading bans…</div>}
            {!bansQuery.isLoading && banList.length === 0 && <div className="text-sm text-muted-foreground">No active bans.</div>}
            {banList.map((b) => (
              <div key={`${b.user_id}-${b.enforcement_id}`} className="flex items-center justify-between rounded-md border p-2 text-sm">
                <div>
                  <div className="font-medium">{b.user_id}</div>
                  <div className="text-xs text-muted-foreground">{b.permanent ? "permanent" : `${b.duration_days}d`} • {b.note || "—"}</div>
                </div>
                <Button size="sm" variant="outline" onClick={() => liftBanMutation.mutate(b.user_id)} disabled={liftBanMutation.isPending}>
                  Lift ban
                </Button>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

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
              <option value="closed">closed</option>
            </select>
          </div>
          <div className="space-y-1">
            <Label htmlFor="mod-topic">Topic</Label>
            <select id="mod-topic" className="h-9 w-full rounded-md border bg-background px-3 text-sm" value={topic} onChange={(e) => setTopic(e.target.value)}>
              <option value="">All</option>
              {TOPICS.map((tp) => (
                <option key={tp} value={tp}>{tp.replace(/_/g, " ")}</option>
              ))}
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

      {/* MODX-22 (D11): bulk selection bar. */}
      {selectedIds.size > 0 && (
        <Card>
          <CardContent className="flex flex-wrap items-center gap-2 p-3 text-sm">
            <span className="mr-2 font-medium">{selectedIds.size} selected</span>
            <Button size="sm" onClick={() => bulkMutation.mutate("dismiss")} disabled={bulkMutation.isPending}>Dismiss</Button>
            <Button size="sm" onClick={() => bulkMutation.mutate("confirm")} disabled={bulkMutation.isPending}>Confirm hold</Button>
            <Button size="sm" variant="outline" onClick={() => bulkMutation.mutate("reinstate")} disabled={bulkMutation.isPending}>Reinstate</Button>
            <Button size="sm" variant="destructive" onClick={() => bulkMutation.mutate("delete")} disabled={bulkMutation.isPending}>Delete</Button>
            <Button size="sm" variant="ghost" onClick={() => setSelectedIds(new Set())}>Clear</Button>
          </CardContent>
        </Card>
      )}

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
                <div key={t.ticket_id} className={`flex items-start gap-2 rounded-md border p-2 text-sm ${selectedId === t.ticket_id ? "border-primary bg-primary/5" : "hover:bg-muted/30"}`}>
                  <input
                    type="checkbox"
                    className="mt-1"
                    checked={selectedIds.has(t.ticket_id)}
                    onChange={() => toggleSelected(t.ticket_id)}
                    aria-label={`select ${t.ticket_id}`}
                  />
                  <button className="flex-1 text-left" onClick={() => setSelectedTicketId(t.ticket_id)}>
                    <div className="flex items-center justify-between">
                      <div className="font-medium">{t.ticket_id}</div>
                      <Badge variant="outline">{t.status}</Badge>
                    </div>
                    <div className="mt-1 text-xs text-muted-foreground">{t.queue} • {t.content_type} • reports {t.report_count}</div>
                  </button>
                </div>
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
            {detail && (
              <>
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <Badge variant="secondary">{detail.ticket.priority}</Badge>
                  <Badge variant={detail.illegal_lane ? "destructive" : "outline"}>state: {detail.case_state || "—"}</Badge>
                  {detail.illegal_lane && <Badge variant="destructive">illegal / CSAM lane</Badge>}
                  <span>Queue: {detail.ticket.queue}</span>
                  <span>Assigned: {detail.ticket.assigned_admin_user_id || "unassigned"}</span>
                  <span>Distinct reporters: {detail.distinct_reporter_count}</span>
                  {canFinalCall && <span>Hold: {holdCountdown(detail.hold_until)}</span>}
                </div>

                <div className="rounded-md border p-3 text-sm">
                  <div className="mb-1 font-medium">Content snapshot</div>
                  <pre className="overflow-auto text-xs">{JSON.stringify(detail.content_snapshot, null, 2)}</pre>
                </div>

                {detail.poster_response && (
                  <div className="rounded-md border border-amber-300 bg-amber-50 p-3 text-sm">
                    <div className="mb-1 font-medium">Poster's response</div>
                    <div className="text-xs">{detail.poster_response}</div>
                    <div className="mt-1 text-[10px] text-muted-foreground">responded {fmt(detail.responded_at)}</div>
                  </div>
                )}

                <div className="rounded-md border p-3">
                  <div className="mb-2 text-sm font-medium">Linked reports</div>
                  <div className="max-h-[180px] space-y-2 overflow-auto">
                    {detail.linked_reports.map((r) => (
                      <div key={r.report_id} className="rounded bg-muted/40 p-2 text-xs">
                        <div className="font-medium">{r.report_id} • {r.reporter_user_id}</div>
                        <div>topics: {r.topics.join(", ") || "—"}</div>
                        <div>{r.reason_text}</div>
                      </div>
                    ))}
                    {detail.linked_reports.length === 0 && <div className="text-xs text-muted-foreground">No linked reports.</div>}
                  </div>
                </div>

                <div className="rounded-md border p-3 text-xs">
                  <div>Offender: {detail.offender_history_summary.offender_user_id || "unknown"}</div>
                  <div>Total tickets: {detail.offender_history_summary.total_tickets}</div>
                  <div>Active enforcements: {detail.offender_history_summary.open_tickets}</div>
                  <div>Total reports: {detail.offender_history_summary.total_reports}</div>
                  {typeof detail.offender_history_summary.total_enforcements === "number" && (
                    <div>Total enforcements: {detail.offender_history_summary.total_enforcements}</div>
                  )}
                </div>

                {/* MODX-17 (D7): prior enforcement rows now read the REAL projected fields. */}
                <div className="rounded-md border p-3 text-xs">
                  <div className="mb-2 text-sm font-medium">Prior enforcement history</div>
                  <div className="max-h-[120px] space-y-1 overflow-auto">
                    {detail.prior_enforcement_history.length === 0 && (
                      <div className="text-muted-foreground">No prior enforcement actions.</div>
                    )}
                    {detail.prior_enforcement_history.map((h) => (
                      <div key={h.enforcement_id} className="rounded bg-muted/40 p-2">
                        <div>
                          {h.enforcement_type} • <span className="uppercase">{h.status}</span>
                          {h.duration_days > 0 ? ` • ${h.duration_days}d` : ""} • {h.created_by_admin_user_id || "system"}
                        </div>
                        <div className="text-muted-foreground">
                          {h.source_ticket_id} • {fmt(h.created_at)} • {h.note || "—"}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* MODX-17 (D1): the state-machine action panel. */}
                <div className="space-y-2 rounded-md border p-3">
                  <div className="text-sm font-medium">Case actions</div>
                  <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Decision note (optional)" />

                  <div className="flex flex-wrap gap-2">
                    <Button
                      variant="outline"
                      onClick={() => selectedId && claimMutation.mutate(selectedId)}
                      disabled={!selectedId || claimMutation.isPending || detail.ticket.assigned_admin_user_id === currentUserSub}
                    >
                      {detail.ticket.assigned_admin_user_id === currentUserSub ? "Claimed by you" : "Claim ticket"}
                    </Button>
                    <Button onClick={() => selectedId && dismissMutation.mutate(selectedId)} disabled={!selectedId || !canDismissConfirm || dismissMutation.isPending}>
                      Dismiss (restore)
                    </Button>
                    <Button variant="secondary" onClick={() => selectedId && confirmMutation.mutate(selectedId)} disabled={!selectedId || !canDismissConfirm || confirmMutation.isPending}>
                      Confirm violation (30-day hold)
                    </Button>
                  </div>

                  {canFinalCall && (
                    <div className="space-y-2 rounded-md border border-dashed p-2">
                      <div className="text-xs font-medium">Final call ({detail.case_state})</div>
                      <label className="flex items-center gap-2 text-xs">
                        <input type="checkbox" checked={banOnDelete} onChange={(e) => setBanOnDelete(e.target.checked)} />
                        Ban the owner on delete
                      </label>
                      {banOnDelete && (
                        <div className="grid grid-cols-2 gap-2">
                          <Input value={banDurationDays} onChange={(e) => setBanDurationDays(e.target.value)} placeholder="Ban days (0 = permanent)" />
                          <Input value={secondApprover} onChange={(e) => setSecondApprover(e.target.value)} placeholder="2nd approver (permanent ban)" />
                        </div>
                      )}
                      <div className="flex flex-wrap gap-2">
                        <Button variant="outline" onClick={() => selectedId && finalCallMutation.mutate({ ticketId: selectedId, action: "reinstate" })} disabled={!selectedId || finalCallMutation.isPending}>
                          Reinstate
                        </Button>
                        <Button variant="destructive" onClick={() => selectedId && finalCallMutation.mutate({ ticketId: selectedId, action: "delete" })} disabled={!selectedId || finalCallMutation.isPending}>
                          Delete{banOnDelete ? " + ban" : ""}
                        </Button>
                      </div>
                    </div>
                  )}
                </div>
              </>
            )}
            {!detailQuery.isLoading && !detail && !detailQuery.isError && (
              <div className="text-sm text-muted-foreground">Select a ticket from the list to begin moderation.</div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
