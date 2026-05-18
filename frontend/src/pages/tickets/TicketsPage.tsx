import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { toast } from "sonner";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useAuthStore } from "@/stores/authStore";
import { getRoleFromAccessToken } from "@/lib/adminCapabilities";
import {
  addTicketMessage,
  assignTicket,
  createTicket,
  getAdminTicketSummary,
  getTicket,
  listTickets,
  setTicketStatus,
  type Ticket,
  type TicketStatus,
} from "@/api/endpoints/tickets";
import { JiraLinkedPanel } from "./JiraLinkedPanel";

const POLL_MS = 15000;

function fmt(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

export default function TicketsPage() {
  const token = useAuthStore((s) => s.accessToken);
  const currentUserSub = useAuthStore((s) => s.userId);
  const role = getRoleFromAccessToken(token);
  const isAdmin = role === "admin" || role === "root";

  const [subject, setSubject] = useState("");
  const [description, setDescription] = useState("");

  const [ticketCursor, setTicketCursor] = useState<string | undefined>(undefined);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [replyBody, setReplyBody] = useState("");

  const [statusFilter, setStatusFilter] = useState<"" | TicketStatus>("");
  const [assigneeFilter, setAssigneeFilter] = useState("");
  const [ownerFilter, setOwnerFilter] = useState("");
  const [assignTarget, setAssignTarget] = useState("");

  const listQuery = useQuery({
    queryKey: ["tickets", { ticketCursor, statusFilter, assigneeFilter, ownerFilter, isAdmin }],
    queryFn: () =>
      listTickets({
        cursor: ticketCursor,
        limit: 20,
        status: statusFilter || undefined,
        assignee_admin_sub: isAdmin && assigneeFilter.trim() ? assigneeFilter.trim() : undefined,
        owner_sub: isAdmin && ownerFilter.trim() ? ownerFilter.trim() : undefined,
      }),
  });

  const summaryQuery = useQuery({
    queryKey: ["tickets", "admin-summary"],
    queryFn: () => getAdminTicketSummary(),
    enabled: isAdmin,
  });

  const selectedTicketQuery = useQuery({
    queryKey: ["tickets", "detail", selectedId],
    queryFn: () => getTicket(selectedId!),
    enabled: !!selectedId,
  });

  const selectedTicket = selectedTicketQuery.data?.ticket;

  const createMut = useMutation({
    mutationFn: () => createTicket({ subject: subject.trim(), description: description.trim() }),
    onSuccess: (res) => {
      toast.success("Ticket created");
      setSubject("");
      setDescription("");
      setSelectedId(res.ticket.ticket_id);
      setTicketCursor(undefined);
      void listQuery.refetch();
    },
    onError: (err: unknown) => toast.error(err instanceof Error ? err.message : "Unable to create ticket"),
  });

  const replyMut = useMutation({
    mutationFn: () => addTicketMessage(selectedId!, replyBody.trim()),
    onSuccess: () => {
      toast.success("Reply posted");
      setReplyBody("");
      void selectedTicketQuery.refetch();
      void listQuery.refetch();
      if (isAdmin) void summaryQuery.refetch();
    },
    onError: (err: unknown) => toast.error(err instanceof Error ? err.message : "Unable to add reply"),
  });

  const assignMut = useMutation({
    mutationFn: (assignee: string) => assignTicket(selectedId!, assignee),
    onSuccess: () => {
      toast.success("Ticket assigned");
      void selectedTicketQuery.refetch();
      void listQuery.refetch();
      if (isAdmin) void summaryQuery.refetch();
    },
    onError: (err: unknown) => toast.error(err instanceof Error ? err.message : "Unable to assign ticket"),
  });

  const statusMut = useMutation({
    mutationFn: (status: "done" | "reopened") => setTicketStatus(selectedId!, status),
    onSuccess: () => {
      toast.success("Ticket status updated");
      void selectedTicketQuery.refetch();
      void listQuery.refetch();
      if (isAdmin) void summaryQuery.refetch();
    },
    onError: (err: unknown) => toast.error(err instanceof Error ? err.message : "Unable to update status"),
  });

  useEffect(() => {
    if (!listQuery.data?.items?.length) return;
    if (!selectedId) {
      setSelectedId(listQuery.data.items[0]!.ticket_id);
      return;
    }
    const stillVisible = listQuery.data.items.some((t) => t.ticket_id === selectedId);
    if (!stillVisible) {
      setSelectedId(listQuery.data.items[0]!.ticket_id);
    }
  }, [listQuery.data, selectedId]);

  useEffect(() => {
    const id = window.setInterval(() => {
      if (document.hidden) return;
      void listQuery.refetch();
      if (selectedId) void selectedTicketQuery.refetch();
      if (isAdmin) void summaryQuery.refetch();
    }, POLL_MS);
    return () => window.clearInterval(id);
  }, [isAdmin, listQuery, selectedId, selectedTicketQuery, summaryQuery]);

  const listItems = listQuery.data?.items ?? [];

  const doneDisabled = !selectedTicket || selectedTicket.status === "done";
  const reopenDisabled = !selectedTicket || selectedTicket.status !== "done";
  const assignToSelfDisabled = !selectedTicket || !currentUserSub || selectedTicket.assigned_admin_sub === currentUserSub || assignMut.isPending;

  const statusCounts = useMemo(() => summaryQuery.data?.summary.by_status ?? {}, [summaryQuery.data]);

  return (
    <div className="space-y-6 p-4 md:p-6 lg:p-8">
      <PageHeader title="Support Tickets" description="Open, track, and resolve support issues." />

      {isAdmin && (
        <div className="grid gap-3 md:grid-cols-4">
          <Card><CardHeader><CardTitle className="text-sm">Open</CardTitle></CardHeader><CardContent>{statusCounts.open ?? 0}</CardContent></Card>
          <Card><CardHeader><CardTitle className="text-sm">In progress</CardTitle></CardHeader><CardContent>{statusCounts.in_progress ?? 0}</CardContent></Card>
          <Card><CardHeader><CardTitle className="text-sm">Waiting on user</CardTitle></CardHeader><CardContent>{statusCounts.waiting_on_user ?? 0}</CardContent></Card>
          <Card><CardHeader><CardTitle className="text-sm">Unassigned</CardTitle></CardHeader><CardContent>{summaryQuery.data?.summary.unassigned_count ?? 0}</CardContent></Card>
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>Open a ticket</CardTitle>
            <CardDescription>Users and admins can create tickets. Views auto-refresh every 15 seconds.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-2">
              <Label htmlFor="ticket-subject">Subject</Label>
              <Input id="ticket-subject" value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="Login issue" />
            </div>
            <div className="space-y-2">
              <Label htmlFor="ticket-description">Description</Label>
              <Textarea id="ticket-description" rows={4} value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Describe the issue..." />
            </div>
            <Button
              onClick={() => createMut.mutate()}
              disabled={createMut.isPending || subject.trim().length < 3 || description.trim().length < 1}
            >
              Create ticket
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>{isAdmin ? "Admin queue" : "My tickets"}</CardTitle>
            <CardDescription>Choose a ticket to view and reply.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {isAdmin && (
              <div className="grid gap-2">
                <Input value={ownerFilter} onChange={(e) => setOwnerFilter(e.target.value)} placeholder="Filter owner_sub" />
                <Input value={assigneeFilter} onChange={(e) => setAssigneeFilter(e.target.value)} placeholder="Filter assignee_admin_sub" />
                <select
                  className="h-9 rounded-md border bg-background px-3 text-sm"
                  value={statusFilter}
                  onChange={(e) => setStatusFilter((e.target.value as TicketStatus) || "")}
                >
                  <option value="">All statuses</option>
                  <option value="open">open</option>
                  <option value="in_progress">in_progress</option>
                  <option value="waiting_on_user">waiting_on_user</option>
                  <option value="done">done</option>
                </select>
                <Button variant="secondary" onClick={() => { setTicketCursor(undefined); void listQuery.refetch(); }}>Apply filters</Button>
              </div>
            )}

            <div className="space-y-2 max-h-[380px] overflow-auto">
              {listItems.map((ticket) => (
                <TicketRow key={ticket.ticket_id} ticket={ticket} selected={selectedId === ticket.ticket_id} onSelect={() => setSelectedId(ticket.ticket_id)} />
              ))}
              {!listItems.length && <p className="text-sm text-muted-foreground">No tickets found.</p>}
            </div>

            <div className="flex gap-2">
              <Button variant="outline" onClick={() => void listQuery.refetch()} disabled={listQuery.isFetching}>Refresh</Button>
              <Button
                variant="outline"
                onClick={() => setTicketCursor(listQuery.data?.next_cursor ?? undefined)}
                disabled={!listQuery.data?.next_cursor}
              >
                Next page
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Ticket thread</CardTitle>
            <CardDescription>{selectedTicket ? `${selectedTicket.ticket_id} • ${selectedTicket.subject}` : "Select a ticket"}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {selectedTicket ? (
              <>
                <div className="flex flex-wrap gap-2 text-xs">
                  <Badge variant="secondary">{selectedTicket.status}</Badge>
                  <span>Owner: {selectedTicket.owner_sub}</span>
                  <span>Assigned: {selectedTicket.assigned_admin_sub || "unassigned"}</span>
                  <span>Updated: {fmt(selectedTicket.updated_at)}</span>
                </div>

                {isAdmin && (
                  <div className="space-y-2 rounded-md border p-3">
                    <Label htmlFor="assign-target">Assign admin sub</Label>
                    <Input id="assign-target" value={assignTarget} onChange={(e) => setAssignTarget(e.target.value)} placeholder="admin_sub" />
                    <div className="flex flex-wrap gap-2">
                      <Button size="sm" variant="outline" onClick={() => assignMut.mutate(assignTarget.trim())} disabled={!assignTarget.trim() || assignMut.isPending}>Assign</Button>
                      <Button size="sm" variant="secondary" onClick={() => currentUserSub && assignMut.mutate(currentUserSub)} disabled={assignToSelfDisabled}>Assign to me</Button>
                      <Button size="sm" variant="outline" onClick={() => statusMut.mutate("done")} disabled={doneDisabled || statusMut.isPending}>Mark done</Button>
                      <Button size="sm" variant="outline" onClick={() => statusMut.mutate("reopened")} disabled={reopenDisabled || statusMut.isPending}>Reopen</Button>
                    </div>
                  </div>
                )}

                <div className="max-h-[240px] space-y-2 overflow-auto rounded-md border p-3">
                  {selectedTicket.messages.map((m) => (
                    <div key={m.message_id} className="rounded bg-muted/40 p-2 text-sm">
                      <div className="mb-1 text-xs text-muted-foreground">{m.sender_role} • {m.sender_sub} • {fmt(m.created_at)}</div>
                      <div>{m.body}</div>
                    </div>
                  ))}
                </div>

                <div className="space-y-2">
                  <Textarea rows={3} value={replyBody} onChange={(e) => setReplyBody(e.target.value)} placeholder="Reply to ticket..." />
                  <Button onClick={() => replyMut.mutate()} disabled={!replyBody.trim() || replyMut.isPending}>Send reply</Button>
                </div>

                <JiraLinkedPanel ticketId={selectedTicket.ticket_id} currentTicket={selectedTicket as unknown as Record<string, unknown>} />
              </>
            ) : (
              <p className="text-sm text-muted-foreground">No ticket selected.</p>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function TicketRow({ ticket, selected, onSelect }: { ticket: Ticket; selected: boolean; onSelect: () => void }) {
  return (
    <button
      type="button"
      onClick={onSelect}
      className={`w-full rounded-md border p-2 text-left text-sm ${selected ? "border-primary bg-primary/5" : "hover:bg-muted/40"}`}
    >
      <div className="flex items-center justify-between gap-2">
        <div className="font-medium truncate">{ticket.subject}</div>
        <Badge variant="outline">{ticket.status}</Badge>
      </div>
      <div className="mt-1 text-xs text-muted-foreground">{ticket.ticket_id} • owner {ticket.owner_sub}</div>
    </button>
  );
}
