import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { toast } from "sonner";

import {
  addBoardMember,
  createBoardTicket,
  getBoard,
  listBoardTickets,
  removeBoardMember,
  updateBoardColumns,
  type BoardColumn,
  type BoardColumnInput,
  type BoardRole,
} from "@/api/endpoints/tickets";
import { BoardKanban } from "./BoardKanban";
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
import { UserProfileLink } from "@/components/shared/UserProfileLink";

const STATUS_KEYS = ["open", "in_progress", "waiting_on_user", "done"] as const;

function fmt(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

export default function BoardDetailPage() {
  const { boardId = "" } = useParams();

  const [memberModalOpen, setMemberModalOpen] = useState(false);
  const [memberSubInput, setMemberSubInput] = useState("");
  const [memberRoleInput, setMemberRoleInput] = useState<BoardRole>("viewer");

  const [columnModalOpen, setColumnModalOpen] = useState(false);
  const [draftColumns, setDraftColumns] = useState<BoardColumnInput[]>([]);

  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [ticketSubject, setTicketSubject] = useState("");
  const [ticketDescription, setTicketDescription] = useState("");

  const boardQueryKey = ["board", boardId];
  const ticketsQueryKey = ["board-tickets", boardId];

  const boardQuery = useQuery({
    queryKey: boardQueryKey,
    queryFn: () => getBoard(boardId),
    enabled: !!boardId,
  });

  const ticketsQuery = useQuery({
    queryKey: ticketsQueryKey,
    queryFn: () => listBoardTickets(boardId, { limit: 100 }),
    enabled: !!boardId,
  });

  const addMemberMut = useMutation({
    mutationFn: async () => addBoardMember(boardId, { member_sub: memberSubInput.trim(), role: memberRoleInput }),
    onSuccess: async () => {
      toast.success("Member added");
      setMemberSubInput("");
      await boardQuery.refetch();
    },
    onError: (e: Error) => toast.error(e.message || "Unable to add member"),
  });

  const removeMemberMut = useMutation({
    mutationFn: async (memberSub: string) => removeBoardMember(boardId, memberSub),
    onSuccess: async () => {
      toast.success("Member removed");
      await boardQuery.refetch();
    },
    onError: (e: Error) => toast.error(e.message || "Unable to remove member"),
  });

  const columnsMut = useMutation({
    mutationFn: async () =>
      updateBoardColumns(
        boardId,
        draftColumns.map((c, idx) => ({ ...c, order: idx })),
      ),
    onSuccess: async () => {
      toast.success("Columns updated");
      setColumnModalOpen(false);
      await boardQuery.refetch();
    },
    onError: (e: Error) => toast.error(e.message || "Unable to update columns"),
  });

  const createTicketMut = useMutation({
    mutationFn: async () =>
      createBoardTicket(boardId, { subject: ticketSubject.trim(), description: ticketDescription.trim() }),
    onSuccess: async () => {
      toast.success("Ticket created");
      setTicketSubject("");
      setTicketDescription("");
      setCreateModalOpen(false);
      await ticketsQuery.refetch();
    },
    onError: (e: Error) => toast.error(e.message || "Unable to create ticket"),
  });

  const board = boardQuery.data?.board;
  const tickets = ticketsQuery.data?.items ?? [];
  const members = board?.members ?? [];

  function openColumnEditor(columns: BoardColumn[]) {
    setDraftColumns(
      columns.map((c) => ({
        column_id: c.column_id,
        title: c.title,
        status_key: c.status_key,
        order: c.order,
        wip_limit: c.wip_limit ?? null,
        color: c.color ?? null,
      })),
    );
    setColumnModalOpen(true);
  }

  return (
    <div className="space-y-6 p-4 md:p-6 lg:p-8">
      <PageHeader title="Board" description="Kanban board with drag-and-drop, columns, and members." />

      {!board && !boardQuery.isLoading && (
        <Card>
          <CardContent className="pt-6 text-sm text-muted-foreground">Board not found.</CardContent>
        </Card>
      )}

      {board && (
        <>
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center justify-between gap-2">
                <span>{board.name}</span>
                <Badge variant="outline">{board.visibility}</Badge>
              </CardTitle>
              <CardDescription>{board.board_id}</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-wrap gap-2">
              <Button asChild variant="outline" size="sm">
                <Link to="/tickets/boards">Back to boards</Link>
              </Button>

              <Dialog open={createModalOpen} onOpenChange={setCreateModalOpen}>
                <DialogTrigger asChild>
                  <Button size="sm">New ticket</Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>New board ticket</DialogTitle>
                    <DialogDescription>Add a ticket to this board.</DialogDescription>
                  </DialogHeader>
                  <div className="space-y-3">
                    <Input
                      value={ticketSubject}
                      onChange={(e) => setTicketSubject(e.target.value)}
                      placeholder="Subject"
                    />
                    <Textarea
                      rows={4}
                      value={ticketDescription}
                      onChange={(e) => setTicketDescription(e.target.value)}
                      placeholder="Description"
                    />
                    <Button
                      onClick={() => createTicketMut.mutate()}
                      disabled={ticketSubject.trim().length < 3 || !ticketDescription.trim() || createTicketMut.isPending}
                    >
                      Create ticket
                    </Button>
                  </div>
                </DialogContent>
              </Dialog>

              <Button variant="outline" size="sm" onClick={() => openColumnEditor(board.columns)}>
                Configure columns
              </Button>

              <Dialog open={memberModalOpen} onOpenChange={setMemberModalOpen}>
                <DialogTrigger asChild>
                  <Button variant="outline" size="sm">Manage members</Button>
                </DialogTrigger>
                <DialogContent className="max-w-2xl">
                  <DialogHeader>
                    <DialogTitle>Member management</DialogTitle>
                    <DialogDescription>Add/remove members for this board.</DialogDescription>
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
                        onChange={(e) => setMemberRoleInput(e.target.value as BoardRole)}
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
                            <UserProfileLink
                              userId={member.member_sub}
                              displayName={member.member_sub}
                              className="truncate font-medium hover:underline"
                              ariaLabel={`Open ${member.member_sub} profile`}
                            />
                            <div className="text-xs text-muted-foreground">role {member.role} • updated {fmt(member.updated_at)}</div>
                          </div>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => removeMemberMut.mutate(member.member_sub)}
                            disabled={removeMemberMut.isPending || member.member_sub === board.owner_sub}
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

          <Card>
            <CardHeader>
              <CardTitle>Kanban</CardTitle>
              <CardDescription>Drag a card to a column to change its status.</CardDescription>
            </CardHeader>
            <CardContent>
              {ticketsQuery.isLoading ? (
                <p className="text-sm text-muted-foreground">Loading tickets…</p>
              ) : (
                <BoardKanban board={board} tickets={tickets} ticketsQueryKey={ticketsQueryKey} />
              )}
            </CardContent>
          </Card>
        </>
      )}

      {/* Column config editor (TKB-008 driven) */}
      <Dialog open={columnModalOpen} onOpenChange={setColumnModalOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Configure columns</DialogTitle>
            <DialogDescription>
              Rename, reorder, add, or remove columns. Each column maps to an underlying ticket status.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            {draftColumns.map((col, idx) => (
              <div key={idx} className="grid items-center gap-2 sm:grid-cols-[1fr_160px_auto]">
                <Input
                  value={col.title}
                  onChange={(e) =>
                    setDraftColumns((prev) => prev.map((c, i) => (i === idx ? { ...c, title: e.target.value } : c)))
                  }
                  placeholder="Column title"
                />
                <select
                  className="h-10 rounded-md border bg-background px-3 text-sm"
                  value={col.status_key}
                  onChange={(e) =>
                    setDraftColumns((prev) => prev.map((c, i) => (i === idx ? { ...c, status_key: e.target.value } : c)))
                  }
                >
                  {STATUS_KEYS.map((k) => (
                    <option key={k} value={k}>
                      {k}
                    </option>
                  ))}
                </select>
                <div className="flex gap-1">
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    disabled={idx === 0}
                    onClick={() =>
                      setDraftColumns((prev) => {
                        const next = [...prev];
                        [next[idx - 1], next[idx]] = [next[idx], next[idx - 1]];
                        return next;
                      })
                    }
                  >
                    ↑
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    disabled={idx === draftColumns.length - 1}
                    onClick={() =>
                      setDraftColumns((prev) => {
                        const next = [...prev];
                        [next[idx + 1], next[idx]] = [next[idx], next[idx + 1]];
                        return next;
                      })
                    }
                  >
                    ↓
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    onClick={() => setDraftColumns((prev) => prev.filter((_, i) => i !== idx))}
                  >
                    ✕
                  </Button>
                </div>
              </div>
            ))}
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() =>
                setDraftColumns((prev) => [
                  ...prev,
                  { title: "New column", status_key: "open", order: prev.length },
                ])
              }
            >
              Add column
            </Button>
            <div className="pt-2">
              <Button
                onClick={() => columnsMut.mutate()}
                disabled={!draftColumns.length || columnsMut.isPending}
              >
                Save columns
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
