import { useState } from "react";
import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  listGroupFundraisers,
  createGroupFundraiser,
  updateGroupFundraiser,
  listGroupDonations,
} from "@/api/endpoints/groups";
import type { GroupFundraiser } from "@/api/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Loader2, Plus, Target, Copy, PauseCircle, PlayCircle, Users } from "lucide-react";
import { toast } from "sonner";

function fmt(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

function ProgressBar({ raised, goal }: { raised: number; goal?: number | null }) {
  if (!goal || goal <= 0) {
    return (
      <div className="text-sm text-muted-foreground" data-testid="fundraiser-open-ended">
        {fmt(raised)} raised (open-ended)
      </div>
    );
  }
  const pct = Math.min(100, Math.round((raised / goal) * 100));
  return (
    <div data-testid="fundraiser-progress">
      <div className="flex items-center justify-between text-sm">
        <span className="font-medium">{fmt(raised)}</span>
        <span className="text-muted-foreground">of {fmt(goal)}</span>
      </div>
      <div className="mt-1 h-2 rounded-full bg-muted">
        <div
          className="h-full rounded-full bg-primary transition-all"
          style={{ width: `${pct}%` }}
        />
      </div>
      <div className="mt-1 text-xs text-muted-foreground">{pct}% of goal</div>
    </div>
  );
}

export default function GroupFundraisingPage() {
  const { groupId } = useParams<{ groupId: string }>();
  const qc = useQueryClient();

  const [createOpen, setCreateOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [goal, setGoal] = useState("");
  const [donationsFor, setDonationsFor] = useState<GroupFundraiser | null>(null);

  const fundraisersQ = useQuery({
    queryKey: ["group-fundraisers", groupId],
    queryFn: () => listGroupFundraisers(groupId!),
    enabled: !!groupId,
    staleTime: 10_000,
  });

  const donationsQ = useQuery({
    queryKey: ["group-donations", groupId, donationsFor?.fundraiser_id],
    queryFn: () => listGroupDonations(groupId!, donationsFor!.fundraiser_id),
    enabled: !!groupId && !!donationsFor,
    staleTime: 10_000,
  });

  const createMut = useMutation({
    mutationFn: () =>
      createGroupFundraiser(groupId!, {
        title,
        description: description || undefined,
        goal_cents: goal ? Math.round(parseFloat(goal) * 100) : undefined,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["group-fundraisers", groupId] });
      setCreateOpen(false);
      setTitle("");
      setDescription("");
      setGoal("");
    },
    onError: (e) => toast.error((e as Error)?.message || "Failed to create fundraiser"),
  });

  const statusMut = useMutation({
    mutationFn: ({ id, status }: { id: string; status: "active" | "paused" }) =>
      updateGroupFundraiser(groupId!, id, { status }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["group-fundraisers", groupId] }),
    onError: (e) => toast.error((e as Error)?.message || "Update failed"),
  });

  if (!groupId) return <div>Missing group ID</div>;

  const fundraisers = fundraisersQ.data?.fundraisers ?? [];

  const copyShareLink = (id: string) => {
    const url = `${window.location.origin}/donate/${id}`;
    navigator.clipboard?.writeText(url).catch(() => {});
    toast.success("Share link copied");
  };

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-6" data-testid="group-fundraising-page">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Fundraising</h1>
        <Button onClick={() => setCreateOpen(true)} data-testid="create-fundraiser-button">
          <Plus className="mr-1 h-4 w-4" />
          New Fundraiser
        </Button>
      </div>

      {fundraisersQ.isLoading ? (
        <div className="flex justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin" />
        </div>
      ) : fundraisers.length ? (
        <div className="space-y-4">
          {fundraisers.map((f) => (
            <Card key={f.fundraiser_id} data-testid="fundraiser-card">
              <CardHeader>
                <CardTitle className="flex items-center justify-between gap-2">
                  <span className="flex items-center gap-2">
                    <Target className="h-5 w-5" />
                    {f.title}
                  </span>
                  <span
                    className="rounded-full bg-muted px-2 py-0.5 text-xs"
                    data-testid="fundraiser-status"
                  >
                    {f.status}
                  </span>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {f.description && (
                  <p className="text-sm text-muted-foreground">{f.description}</p>
                )}
                <ProgressBar raised={f.raised_cents} goal={f.goal_cents} />
                <div className="text-xs text-muted-foreground" data-testid="donation-count">
                  {f.donation_count} donation{f.donation_count !== 1 ? "s" : ""}
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => copyShareLink(f.fundraiser_id)}
                    data-testid="copy-share-link"
                  >
                    <Copy className="mr-1 h-4 w-4" />
                    Share Link
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setDonationsFor(f)}
                    data-testid="view-donations-button"
                  >
                    <Users className="mr-1 h-4 w-4" />
                    Donations
                  </Button>
                  {f.status === "active" ? (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => statusMut.mutate({ id: f.fundraiser_id, status: "paused" })}
                      data-testid="pause-fundraiser-button"
                    >
                      <PauseCircle className="mr-1 h-4 w-4" />
                      Pause
                    </Button>
                  ) : f.status === "paused" ? (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => statusMut.mutate({ id: f.fundraiser_id, status: "active" })}
                      data-testid="resume-fundraiser-button"
                    >
                      <PlayCircle className="mr-1 h-4 w-4" />
                      Resume
                    </Button>
                  ) : null}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      ) : (
        <p className="text-center text-muted-foreground" data-testid="fundraisers-empty">
          No fundraisers yet. Create one to start collecting donations.
        </p>
      )}

      {/* Create dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent data-testid="create-fundraiser-dialog">
          <DialogHeader>
            <DialogTitle>Create Fundraiser</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="fr-title">Title</Label>
              <Input
                id="fr-title"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="Community Server Fund"
                data-testid="fundraiser-title-input"
              />
            </div>
            <div>
              <Label htmlFor="fr-desc">Description</Label>
              <Input
                id="fr-desc"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="What are you raising money for?"
                data-testid="fundraiser-description-input"
              />
            </div>
            <div>
              <Label htmlFor="fr-goal">Goal ($, optional)</Label>
              <Input
                id="fr-goal"
                type="number"
                min="1"
                step="0.01"
                value={goal}
                onChange={(e) => setGoal(e.target.value)}
                placeholder="500.00"
                data-testid="fundraiser-goal-input"
              />
            </div>
            <Button
              onClick={() => createMut.mutate()}
              disabled={createMut.isPending || title.trim().length < 3}
              data-testid="submit-fundraiser-button"
            >
              {createMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : "Create"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      {/* Donations dialog */}
      <Dialog open={!!donationsFor} onOpenChange={(o) => !o && setDonationsFor(null)}>
        <DialogContent data-testid="donations-dialog">
          <DialogHeader>
            <DialogTitle>Donations — {donationsFor?.title}</DialogTitle>
          </DialogHeader>
          {donationsQ.isLoading ? (
            <div className="flex justify-center py-4">
              <Loader2 className="h-6 w-6 animate-spin" />
            </div>
          ) : donationsQ.data?.donations?.length ? (
            <div className="space-y-2">
              {donationsQ.data.donations.map((d) => (
                <div
                  key={d.donation_id}
                  className="flex items-center justify-between rounded-lg border p-3"
                  data-testid="donation-row"
                >
                  <div>
                    <div className="font-medium">{d.donor_name || "Anonymous"}</div>
                    <div className="text-xs text-muted-foreground">{d.status}</div>
                  </div>
                  <div className="font-semibold text-green-600">{fmt(d.amount_cents)}</div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-center text-muted-foreground">No donations yet</p>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
