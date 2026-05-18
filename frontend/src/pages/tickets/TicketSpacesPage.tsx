import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { toast } from "sonner";

import { createTicketSpace, listTicketSpaces, type TicketSpace } from "@/api/endpoints/tickets";
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

export default function TicketSpacesPage() {
  const [name, setName] = useState("");
  const [visibility, setVisibility] = useState<"private" | "shared">("private");
  const [cursor, setCursor] = useState<string | undefined>(undefined);

  const spacesQuery = useQuery({
    queryKey: ["ticket-spaces", { cursor }],
    queryFn: () => listTicketSpaces({ cursor, limit: 20 }),
  });

  const createMut = useMutation({
    mutationFn: async () => createTicketSpace({ name: name.trim(), visibility }),
    onSuccess: async () => {
      toast.success("Ticket space created");
      setName("");
      setCursor(undefined);
      await spacesQuery.refetch();
    },
    onError: (e: Error) => toast.error(e.message || "Unable to create space"),
  });

  const items = spacesQuery.data?.items ?? [];

  return (
    <div className="space-y-6">
      <PageHeader title="Ticket Spaces" description="Create spaces and browse spaces you own or share." />

      <Card>
        <CardHeader>
          <CardTitle>Create ticket space</CardTitle>
          <CardDescription>Start a new private or shared space board.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Space name" />
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
              Create space
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Owned + shared spaces</CardTitle>
          <CardDescription>Spaces where you are owner, editor, or viewer.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          {spacesQuery.isLoading && <p className="text-sm text-muted-foreground">Loading spaces…</p>}
          {!spacesQuery.isLoading && !items.length && (
            <p className="text-sm text-muted-foreground">No spaces yet.</p>
          )}
          {items.map((space) => (
            <SpaceRow key={space.space_id} space={space} />
          ))}

          <div className="pt-2">
            <Button
              variant="outline"
              disabled={!spacesQuery.data?.next_cursor || spacesQuery.isFetching}
              onClick={() => setCursor(spacesQuery.data?.next_cursor ?? undefined)}
            >
              Load more
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function SpaceRow({ space }: { space: TicketSpace }) {
  return (
    <div className="rounded-md border p-3">
      <div className="flex items-center justify-between gap-2">
        <div className="font-medium">{space.name}</div>
        <Badge variant="outline">{space.visibility}</Badge>
      </div>
      <div className="mt-1 text-xs text-muted-foreground">
        {space.space_id} • owner{" "}
        <UserProfileLink
          userId={space.owner_sub}
          displayName={space.owner_sub}
          className="font-medium hover:underline"
          ariaLabel={`Open ${space.owner_sub} profile`}
        />{" "}
        • updated {fmt(space.updated_at)}
      </div>
      <div className="mt-2">
        <Button asChild size="sm" variant="outline">
          <Link to={`/tickets/spaces/${space.space_id}`}>Open space</Link>
        </Button>
      </div>
    </div>
  );
}
