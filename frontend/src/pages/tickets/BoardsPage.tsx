import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { toast } from "sonner";

import { createBoard, listBoards, type Board } from "@/api/endpoints/tickets";
import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { UserProfileLink } from "@/components/shared/UserProfileLink";

function fmt(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

export default function BoardsPage() {
  const [name, setName] = useState("");
  const [visibility, setVisibility] = useState<"private" | "shared">("private");
  const [cursor, setCursor] = useState<string | undefined>(undefined);

  const boardsQuery = useQuery({
    queryKey: ["boards", { cursor }],
    queryFn: () => listBoards({ cursor, limit: 20 }),
  });

  const createMut = useMutation({
    mutationFn: async () => createBoard({ name: name.trim(), visibility }),
    onSuccess: async () => {
      toast.success("Board created");
      setName("");
      setCursor(undefined);
      await boardsQuery.refetch();
    },
    onError: (e: Error) => toast.error(e.message || "Unable to create board"),
  });

  const items = boardsQuery.data?.items ?? [];

  return (
    <div className="space-y-6 p-4 md:p-6 lg:p-8">
      <PageHeader title="Boards" description="Create Kanban boards and browse boards you own or share." />

      <Card>
        <CardHeader>
          <CardTitle>Create board</CardTitle>
          <CardDescription>Start a new private or shared Kanban board.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Board name" />
          <div className="flex items-center gap-2">
            <Button
              type="button"
              variant={visibility === "private" ? "default" : "outline"}
              onClick={() => setVisibility("private")}
            >
              Private
            </Button>
            <Button
              type="button"
              variant={visibility === "shared" ? "default" : "outline"}
              onClick={() => setVisibility("shared")}
            >
              Shared
            </Button>
            <Button onClick={() => createMut.mutate()} disabled={!name.trim() || createMut.isPending}>
              Create board
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Owned + shared boards</CardTitle>
          <CardDescription>Boards where you are owner, editor, or viewer.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          {boardsQuery.isLoading && <p className="text-sm text-muted-foreground">Loading boards…</p>}
          {!boardsQuery.isLoading && !items.length && (
            <p className="text-sm text-muted-foreground">No boards yet.</p>
          )}
          {items.map((board) => (
            <BoardRow key={board.board_id} board={board} />
          ))}

          <div className="pt-2">
            <Button
              variant="outline"
              disabled={!boardsQuery.data?.next_cursor || boardsQuery.isFetching}
              onClick={() => setCursor(boardsQuery.data?.next_cursor ?? undefined)}
            >
              Load more
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function BoardRow({ board }: { board: Board }) {
  return (
    <div className="rounded-md border p-3">
      <div className="flex items-center justify-between gap-2">
        <div className="font-medium">{board.name}</div>
        <Badge variant="outline">{board.visibility}</Badge>
      </div>
      <div className="mt-1 text-xs text-muted-foreground">
        {board.board_id} • owner{" "}
        <UserProfileLink
          userId={board.owner_sub}
          displayName={board.owner_sub}
          className="font-medium hover:underline"
          ariaLabel={`Open ${board.owner_sub} profile`}
        />{" "}
        • updated {fmt(board.updated_at)}
      </div>
      <div className="mt-2">
        <Button asChild size="sm" variant="outline">
          <Link to={`/tickets/boards/${board.board_id}`}>Open board</Link>
        </Button>
      </div>
    </div>
  );
}
