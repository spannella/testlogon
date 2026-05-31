import { useState } from "react";
import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  listGroupCampaigns,
  createGroupCampaign,
  updateGroupCampaign,
} from "@/api/endpoints/groups";
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
import { Loader2, Plus, Megaphone, PauseCircle, PlayCircle } from "lucide-react";
import { toast } from "sonner";

function fmt(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

export default function GroupAdsPage() {
  const { groupId } = useParams<{ groupId: string }>();
  const qc = useQueryClient();

  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [daily, setDaily] = useState("5");
  const [lifetime, setLifetime] = useState("50");
  const [creativeText, setCreativeText] = useState("");

  const campaignsQ = useQuery({
    queryKey: ["group-campaigns", groupId],
    queryFn: () => listGroupCampaigns(groupId!),
    enabled: !!groupId,
    staleTime: 30_000,
  });

  const createMut = useMutation({
    mutationFn: () =>
      createGroupCampaign(groupId!, {
        name,
        daily_budget_cents: Math.round(parseFloat(daily) * 100),
        lifetime_budget_cents: Math.round(parseFloat(lifetime) * 100),
        creative_text: creativeText || undefined,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["group-campaigns", groupId] });
      setCreateOpen(false);
      setName("");
      setCreativeText("");
    },
    onError: (e) => toast.error((e as Error)?.message || "Failed to create campaign"),
  });

  const statusMut = useMutation({
    mutationFn: ({ id, status }: { id: string; status: "active" | "paused" }) =>
      updateGroupCampaign(groupId!, id, { status }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["group-campaigns", groupId] }),
    onError: (e) => toast.error((e as Error)?.message || "Update failed"),
  });

  if (!groupId) return <div>Missing group ID</div>;

  const campaigns = campaignsQ.data?.campaigns ?? [];

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-6" data-testid="group-ads-page">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Advertising Campaigns</h1>
        <Button onClick={() => setCreateOpen(true)} data-testid="create-campaign-button">
          <Plus className="mr-1 h-4 w-4" />
          New Campaign
        </Button>
      </div>

      {campaignsQ.isLoading ? (
        <div className="flex justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin" />
        </div>
      ) : campaigns.length ? (
        <div className="space-y-4">
          {campaigns.map((c) => {
            const pct =
              c.lifetime_budget_cents > 0
                ? Math.min(100, Math.round((c.spent_cents / c.lifetime_budget_cents) * 100))
                : 0;
            const ctr = c.impressions > 0 ? (c.clicks / c.impressions) * 100 : 0;
            return (
              <Card key={c.campaign_id} data-testid="campaign-card">
                <CardHeader>
                  <CardTitle className="flex items-center justify-between gap-2">
                    <span className="flex items-center gap-2">
                      <Megaphone className="h-5 w-5" />
                      {c.name}
                    </span>
                    <span
                      className="rounded-full bg-muted px-2 py-0.5 text-xs"
                      data-testid="campaign-status"
                    >
                      {c.status}
                    </span>
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div>
                    <div className="flex items-center justify-between text-sm">
                      <span>{fmt(c.spent_cents)} spent</span>
                      <span className="text-muted-foreground">
                        of {fmt(c.lifetime_budget_cents)}
                      </span>
                    </div>
                    <div className="mt-1 h-2 rounded-full bg-muted">
                      <div
                        className="h-full rounded-full bg-primary transition-all"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-3 gap-4 text-sm" data-testid="campaign-stats">
                    <div>
                      <span className="text-muted-foreground">Impressions</span>
                      <div className="font-semibold">{c.impressions}</div>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Clicks</span>
                      <div className="font-semibold">{c.clicks}</div>
                    </div>
                    <div>
                      <span className="text-muted-foreground">CTR</span>
                      <div className="font-semibold">{ctr.toFixed(2)}%</div>
                    </div>
                  </div>
                  <div className="flex gap-2">
                    {c.status === "active" ? (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => statusMut.mutate({ id: c.campaign_id, status: "paused" })}
                        data-testid="pause-campaign-button"
                      >
                        <PauseCircle className="mr-1 h-4 w-4" />
                        Pause
                      </Button>
                    ) : (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => statusMut.mutate({ id: c.campaign_id, status: "active" })}
                        data-testid="resume-campaign-button"
                      >
                        <PlayCircle className="mr-1 h-4 w-4" />
                        Resume
                      </Button>
                    )}
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      ) : (
        <p className="text-center text-muted-foreground" data-testid="campaigns-empty">
          No campaigns yet.
        </p>
      )}

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent data-testid="create-campaign-dialog">
          <DialogHeader>
            <DialogTitle>Create Campaign</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="camp-name">Name</Label>
              <Input
                id="camp-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Summer Membership Drive"
                data-testid="campaign-name-input"
              />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <Label htmlFor="camp-daily">Daily Budget ($)</Label>
                <Input
                  id="camp-daily"
                  type="number"
                  min="1"
                  step="0.01"
                  value={daily}
                  onChange={(e) => setDaily(e.target.value)}
                  data-testid="campaign-daily-input"
                />
              </div>
              <div>
                <Label htmlFor="camp-lifetime">Lifetime Budget ($)</Label>
                <Input
                  id="camp-lifetime"
                  type="number"
                  min="10"
                  step="0.01"
                  value={lifetime}
                  onChange={(e) => setLifetime(e.target.value)}
                  data-testid="campaign-lifetime-input"
                />
              </div>
            </div>
            <div>
              <Label htmlFor="camp-creative">Creative Text</Label>
              <Input
                id="camp-creative"
                value={creativeText}
                onChange={(e) => setCreativeText(e.target.value)}
                placeholder="Join our community!"
                data-testid="campaign-creative-input"
              />
            </div>
            <Button
              onClick={() => createMut.mutate()}
              disabled={createMut.isPending || name.trim().length < 3}
              data-testid="submit-campaign-button"
            >
              {createMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : "Create"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
