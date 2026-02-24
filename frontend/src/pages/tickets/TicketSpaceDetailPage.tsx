import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { toast } from "sonner";

import {
  addSpaceTicketMessage,
  addTicketSpaceMember,
  assignSpaceTicket,
  getSpaceTicket,
  getTicketSpace,
  listSpaceTickets,
  removeTicketSpaceMember,
  setSpaceTicketStatus,
  type SpaceRole,
  type Ticket,
  type TicketStatus,
} from "@/api/endpoints/tickets";
import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { useAuthStore } from "@/stores/authStore";

const POLL_MS = 15000;

function fmt(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

export default function TicketSpaceDetailPage() {
  const { spaceId = "" } = useParams();
  const currentUserSub = useAuthStore((s) => s.userId);

  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [statusFilter, setStatusFilter] = useState<"" | TicketStatus>("");
  const [assigneeFilter, setAssigneeFilter] = useState<"" | "mine" | "unassigned" | "custom">("");
  const [customAssignee, setCustomAssignee] = useState("");

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [replyBody, setReplyBody] = useState("");
  const [assignTarget, setAssignTarget] = useState("");

  const [memberModalOpen, setMemberModalOpen] = useState(false);
  const [memberSubInput, setMemberSubInput] = useState("");
  const [memberRoleInput, setMemberRoleInput] = useState<SpaceRole>("viewer");

  const resolvedAssignee = useMemo(() => {
    if (assigneeFilter === "mine") return currentUserSub || undefined;
    if (assigneeFilter === "unassigned") return "unassigned";
    if (assigneeFilter === "custom") return customAssignee.trim() || undefined;
    return undefined;
  }, [assigneeFilter, currentUserSub, customAssignee]);

  const spaceQuery = useQuery({
    queryKey: ["ticket-space", spaceId],
    queryFn: () => getTicketSpace(spaceId),
    enabled: !!spaceId,
  });

  const listQuery = useQuery({
    queryKey: ["space-ticket-list", { spaceId, cursor, statusFilter, resolvedAssignee }],
    queryFn: () =>
      listSpaceTickets(spaceId, {
        cursor,
        limit: 20,
        status: statusFilter || undefined,
        assignee_sub: resolvedAssignee,
      }),
    enabled: !!spaceId,
  });

  const detailQuery = useQuery({
    queryKey: ["space-ticket-detail", { spaceId, selectedId }],
    queryFn: () => getSpaceTicket(spaceId, selectedId as string),
    enabled: !!spaceId && !!selectedId,
  });

  const addMemberMut = useMutation({
    mutationFn: async () => addTicketSpaceMember(spaceId, { member_sub: memberSubInput.trim(), role: memberRoleInput }),
    onSuccess: async () => {
      toast.success("Member added");
      setMemberSubInput("");
      await spaceQuery.refetch();
    },
    onError: (e: Error) => toast.error(e.message || "Unable to add member"),
  });

  const removeMemberMut = useMutation({
    mutationFn: async (memberSub: string) => removeTicketSpaceMember(spaceId, memberSub),
    onSuccess: async () => {
      toast.success("Member removed");
      await spaceQuery.refetch();
    },
    onError: (e: Error) => toast.error(e.message || "Unable to remove member"),
  });

  const assignMut = useMutation({
    mutationFn: async () => assignSpaceTicket(spaceId, selectedId as string, assignTarget.trim()),
    onSuccess: async (resp) => {
      toast.success("Assigned");
      setAssignTarget("");
      await Promise.all([listQuery.refetch(), detailQuery.refetch()]);
      setSelectedId(resp.ticket.ticket_id);
    },
    onError: (e: Error) => toast.error(e.message || "Unable to assign"),
  });

  const replyMut = useMutation({
    mutationFn: async () => addSpaceTicketMessage(spaceId, selectedId as string, replyBody.trim()),
    onSuccess: async () => {
      toast.success("Reply sent");
      setReplyBody("");
      await Promise.all([listQuery.refetch(), detailQuery.refetch()]);
    },
    onError: (e: Error) => toast.error(e.message || "Unable to reply"),
  });

  const statusMut = useMutation({
    mutationFn: async (status: "done" | "reopened") => setSpaceTicketStatus(spaceId, selectedId as string, status),
    onSuccess: async () => {
      await Promise.all([listQuery.refetch(), detailQuery.refetch()]);
    },
    onError: (e: Error) => toast.error(e.message || "Unable to update status"),
  });

  useEffect(() => {
    if (!spaceId) return;
    const id = window.setInterval(() => {
      void listQuery.refetch();
      if (selectedId) void detailQuery.refetch();
    }, POLL_MS);
    return () => window.clearInterval(id);
  }, [spaceId, selectedId]);

  const space = spaceQuery.data?.space;
  const items = listQuery.data?.items ?? [];
  const selected = detailQuery.data?.ticket ?? null;
  const members = space?.members ?? [];

  return (
    <div className="space-y-6">
      <PageHeader title="Ticket Space Board" description="Filter and triage space tickets with live refresh." />

      {!space && !spaceQuery.isLoading && (
        <Card>
          <CardContent className="pt-6 text-sm text-muted-foreground">Space not found.</CardContent>
        </Card>
      )}

      {space && (
        <>
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center justify-between gap-2">
                <span>{space.name}</span>
                <Badge variant="outline">{space.visibility}</Badge>
              </CardTitle>
              <CardDescription>{space.space_id}</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-wrap gap-2">
              <Button asChild variant="outline" size="sm">
                <Link to="/tickets/spaces">Back to spaces</Link>
              </Button>
              <Button asChild size="sm">
                <Link to="/tickets">Helpdesk tickets</Link>
              </Button>

              <Dialog open={memberModalOpen} onOpenChange={setMemberModalOpen}>
                <DialogTrigger asChild>
                  <Button variant="outline" size="sm">Manage members</Button>
                </DialogTrigger>
                <DialogContent className="max-w-2xl">
                  <DialogHeader>
                    <DialogTitle>Member management</DialogTitle>
                    <DialogDescription>Add/remove members for this space.</DialogDescription>
                  </DialogHeader>

                  <div className="space-y-3">
                    <div className="grid gap-2 sm:grid-cols-[1fr_160px_auto]">
                      <Input
                        value={memberSubInput}
                        onChange={(e) => setMemberSubInput(e.target.value)}
                        placeholder="member sub"
                      />
                      <select
                        className="h-10 rounded-md border bg-background px-3 text-sm"
                        value={memberRoleInput}
                        onChange={(e) => setMemberRoleInput(e.target.value as SpaceRole)}
                      >
                        <option value="viewer">viewer</option>
                        <option value="editor">editor</option>
                        <option value="owner">owner</option>
                      </select>
                      <Button
                        onClick={() => addMemberMut.mutate()}
                        disabled={!memberSubInput.trim() || addMemberMut.isPending}
                      >
                        Add member
                      </Button>
                    </div>

                    <div className="max-h-72 space-y-2 overflow-auto rounded-md border p-2">
                      {members.map((member) => (
                        <div key={member.member_sub} className="flex items-center justify-between rounded border p-2 text-sm">
                          <div className="min-w-0">
                            <div className="truncate font-medium">{member.member_sub}</div>
                            <div className="text-xs text-muted-foreground">role {member.role} • updated {fmt(member.updated_at)}</div>
                          </div>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => removeMemberMut.mutate(member.member_sub)}
                            disabled={removeMemberMut.isPending || member.member_sub === space.owner_sub}
                          >
                            Remove
                          </Button>
                        </div>
                      ))}
                    </div>
                  </div>
                </DialogContent>
              </Dialog>
            </CardContent>
          </Card>

          <div className="grid gap-4 lg:grid-cols-[360px_1fr]">
            <Card>
              <CardHeader>
                <CardTitle>Board queue</CardTitle>
                <CardDescription>Auto-refreshes every 15s.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="grid gap-2">
                  <div className="flex gap-2">
                    <Button variant={statusFilter === "" ? "default" : "outline"} size="sm" onClick={() => setStatusFilter("")}>All</Button>
                    <Button variant={statusFilter === "open" ? "default" : "outline"} size="sm" onClick={() => setStatusFilter("open")}>Open</Button>
                    <Button variant={statusFilter === "in_progress" ? "default" : "outline"} size="sm" onClick={() => setStatusFilter("in_progress")}>In progress</Button>
                  </div>
                  <div className="flex gap-2">
                    <Button variant={statusFilter === "waiting_on_user" ? "default" : "outline"} size="sm" onClick={() => setStatusFilter("waiting_on_user")}>Waiting</Button>
                    <Button variant={statusFilter === "done" ? "default" : "outline"} size="sm" onClick={() => setStatusFilter("done")}>Done</Button>
                  </div>
                </div>

                <div className="grid gap-2">
                  <div className="flex flex-wrap gap-2">
                    <Button size="sm" variant={assigneeFilter === "" ? "default" : "outline"} onClick={() => setAssigneeFilter("")}>All assignees</Button>
                    <Button size="sm" variant={assigneeFilter === "mine" ? "default" : "outline"} onClick={() => setAssigneeFilter("mine")}>Mine</Button>
                    <Button size="sm" variant={assigneeFilter === "unassigned" ? "default" : "outline"} onClick={() => setAssigneeFilter("unassigned")}>Unassigned</Button>
                    <Button size="sm" variant={assigneeFilter === "custom" ? "default" : "outline"} onClick={() => setAssigneeFilter("custom")}>Custom</Button>
                  </div>
                  {assigneeFilter === "custom" && (
                    <Input value={customAssignee} onChange={(e) => setCustomAssignee(e.target.value)} placeholder="Assignee sub" />
                  )}
                </div>

                <div className="space-y-2">
                  {items.map((ticket) => (
                    <TicketRow key={ticket.ticket_id} ticket={ticket} selected={selectedId === ticket.ticket_id} onSelect={() => setSelectedId(ticket.ticket_id)} />
                  ))}
                  {!items.length && <p className="text-sm text-muted-foreground">No space tickets match current filters.</p>}
                </div>

                <Button
                  variant="outline"
                  size="sm"
                  disabled={!listQuery.data?.next_cursor || listQuery.isFetching}
                  onClick={() => setCursor(listQuery.data?.next_cursor ?? undefined)}
                >
                  Load more
                </Button>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Ticket detail</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {!selected && <p className="text-sm text-muted-foreground">Select a ticket to view thread and actions.</p>}
                {selected && (
                  <>
                    <div className="space-y-1">
                      <div className="font-medium">{selected.subject}</div>
                      <div className="text-xs text-muted-foreground">
                        {selected.ticket_id} • owner {selected.owner_sub} • updated {fmt(selected.updated_at)}
                      </div>
                      <div className="text-xs text-muted-foreground">
                        status {selected.status} • assigned {selected.assigned_to_sub || "unassigned"}
                      </div>
                    </div>

                    <div className="flex flex-wrap gap-2">
                      <select
                        className="h-10 rounded-md border bg-background px-3 text-sm min-w-56"
                        value={assignTarget}
                        onChange={(e) => setAssignTarget(e.target.value)}
                      >
                        <option value="">Select assignee</option>
                        {members.map((member) => (
                          <option key={member.member_sub} value={member.member_sub}>
                            {member.member_sub} ({member.role})
                          </option>
                        ))}
                      </select>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => setAssignTarget(currentUserSub || "")}
                        disabled={!currentUserSub}
                      >
                        Assign to me
                      </Button>
                      <Button size="sm" onClick={() => assignMut.mutate()} disabled={!assignTarget.trim() || assignMut.isPending}>Assign</Button>
                      <Button size="sm" variant="outline" onClick={() => statusMut.mutate("done")} disabled={statusMut.isPending}>Mark done</Button>
                      <Button size="sm" variant="outline" onClick={() => statusMut.mutate("reopened")} disabled={statusMut.isPending}>Reopen</Button>
                    </div>

                    <div className="space-y-2 rounded-md border p-2 max-h-72 overflow-auto">
                      {(selected.messages || []).map((m) => (
                        <div key={m.message_id} className="rounded border p-2 text-sm">
                          <div className="text-xs text-muted-foreground">{m.sender_sub} • {fmt(m.created_at)}</div>
                          <div>{m.body}</div>
                        </div>
                      ))}
                    </div>

                    <div className="space-y-2">
                      <Textarea rows={3} value={replyBody} onChange={(e) => setReplyBody(e.target.value)} placeholder="Reply in thread..." />
                      <Button onClick={() => replyMut.mutate()} disabled={!replyBody.trim() || replyMut.isPending}>Send reply</Button>
                    </div>
                  </>
                )}
              </CardContent>
            </Card>
          </div>
        </>
      )}
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
      <div className="mt-1 text-xs text-muted-foreground">
        {ticket.ticket_id} • owner {ticket.owner_sub} • assignee {ticket.assigned_to_sub || "unassigned"}
      </div>
    </button>
  );
}
