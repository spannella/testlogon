import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Users, Plus, UserPlus, Compass } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  listMySyndicates,
  listMyInvites,
  discoverSyndicates,
  createSyndicate,
  respondToInvite,
  requestToJoin,
} from "@/api/endpoints/syndicates";

export default function SyndicatesPage() {

  const { data: mySyndicates = [] } = useQuery({
    queryKey: ["syndicates", "mine"],
    queryFn: () => listMySyndicates(),
  });

  const { data: invites = [] } = useQuery({
    queryKey: ["syndicates", "invites"],
    queryFn: () => listMyInvites(),
  });

  const { data: discoverList = [] } = useQuery({
    queryKey: ["syndicates", "discover"],
    queryFn: () => discoverSyndicates(),
  });

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center gap-3">
        <Users className="h-6 w-6" />
        <h1 className="text-2xl font-bold">Syndicates</h1>
      </div>

      {/* My Syndicates */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle>My Syndicates</CardTitle>
          <CreateSyndicateDialog />
        </CardHeader>
        <CardContent>
          {mySyndicates.length === 0 ? (
            <p className="text-muted-foreground">You are not a member of any syndicates yet.</p>
          ) : (
            <div className="space-y-3">
              {mySyndicates.map((s) => (
                <Link
                  key={s.syndicate_id}
                  to={`/syndicates/${s.syndicate_id}`}
                  className="flex items-center justify-between rounded-lg border p-3 hover:bg-accent transition-colors"
                >
                  <div>
                    <p className="font-medium">{s.syndicate_name}</p>
                    <p className="text-sm text-muted-foreground">Joined {new Date((s.joined_at ?? 0) * 1000).toLocaleDateString()}</p>
                  </div>
                  <Badge variant={s.role === "admin" ? "default" : "secondary"}>
                    {s.role}
                  </Badge>
                </Link>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Pending Invites */}
      {invites.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Pending Invites</CardTitle>
          </CardHeader>
          <CardContent>
            <PendingInvitesCard invites={invites} />
          </CardContent>
        </Card>
      )}

      {/* Discover Syndicates */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Compass className="h-5 w-5" />
            Discover Syndicates
          </CardTitle>
        </CardHeader>
        <CardContent>
          {discoverList.length === 0 ? (
            <p className="text-muted-foreground">No syndicates available to discover.</p>
          ) : (
            <div className="space-y-3">
              {discoverList.map((s) => (
                <DiscoverSyndicateRow key={s.syndicate_id} syndicate={s} />
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function CreateSyndicateDialog() {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const queryClient = useQueryClient();

  const createMut = useMutation({
    mutationFn: () => createSyndicate({ name, description }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["syndicates"] });
      setOpen(false);
      setName("");
      setDescription("");
    },
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">
          <Plus className="h-4 w-4 mr-1" /> Create Syndicate
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create Syndicate</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <label className="text-sm font-medium">Name</label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Syndicate name"
              maxLength={100}
            />
          </div>
          <div>
            <label className="text-sm font-medium">Description</label>
            <Textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="What is this syndicate about?"
              maxLength={500}
            />
          </div>
        </div>
        <DialogFooter>
          <Button
            onClick={() => createMut.mutate()}
            disabled={name.length < 2 || createMut.isPending}
          >
            {createMut.isPending ? "Creating..." : "Create"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function PendingInvitesCard({ invites }: { invites: Array<{ syndicate_id: string; syndicate_name?: string; invited_by: string; status: string }> }) {
  const queryClient = useQueryClient();

  const respondMut = useMutation({
    mutationFn: ({ syndicateId, accept }: { syndicateId: string; accept: boolean }) =>
      respondToInvite(syndicateId, accept),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["syndicates"] });
    },
  });

  return (
    <div className="space-y-3">
      {invites.map((inv) => (
        <div key={inv.syndicate_id} className="flex items-center justify-between rounded-lg border p-3">
          <div>
            <p className="font-medium">{inv.syndicate_name}</p>
            <p className="text-sm text-muted-foreground">Invited by {inv.invited_by}</p>
          </div>
          <div className="flex gap-2">
            <Button
              size="sm"
              onClick={() => respondMut.mutate({ syndicateId: inv.syndicate_id, accept: true })}
              disabled={respondMut.isPending}
            >
              Accept
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => respondMut.mutate({ syndicateId: inv.syndicate_id, accept: false })}
              disabled={respondMut.isPending}
            >
              Decline
            </Button>
          </div>
        </div>
      ))}
    </div>
  );
}

function DiscoverSyndicateRow({ syndicate }: { syndicate: { syndicate_id: string; name: string; description?: string; member_count?: number } }) {
  const queryClient = useQueryClient();
  const [requested, setRequested] = useState(false);

  const joinMut = useMutation({
    mutationFn: () => requestToJoin(syndicate.syndicate_id),
    onSuccess: () => {
      setRequested(true);
      queryClient.invalidateQueries({ queryKey: ["syndicates"] });
    },
  });

  return (
    <div className="flex items-center justify-between rounded-lg border p-3">
      <div>
        <Link to={`/syndicates/${syndicate.syndicate_id}`} className="font-medium hover:underline">
          {syndicate.name}
        </Link>
        {syndicate.description && (
          <p className="text-sm text-muted-foreground">{syndicate.description}</p>
        )}
        <p className="text-xs text-muted-foreground">{syndicate.member_count} member(s)</p>
      </div>
      <Button
        size="sm"
        variant="outline"
        onClick={() => joinMut.mutate()}
        disabled={joinMut.isPending || requested}
      >
        <UserPlus className="h-4 w-4 mr-1" />
        {requested ? "Requested" : "Request to Join"}
      </Button>
    </div>
  );
}
