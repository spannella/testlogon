import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Megaphone } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  getSyndicateCampaign,
  getSyndicateCampaignAnalytics,
  addSyndicateCampaignBudget,
  updateSyndicateCampaignStatus,
} from "@/api/endpoints/syndicateAdvertising";
import { getSyndicate } from "@/api/endpoints/syndicates";
import { useAuthStore } from "@/stores/authStore";

export default function SyndicateAdvertisingDetailPage() {
  const { syndicateId, campaignId } = useParams<{ syndicateId: string; campaignId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const userId = useAuthStore((s) => s.userId);
  const [topUp, setTopUp] = useState("");

  const { data: syndicate } = useQuery({
    queryKey: ["syndicates", syndicateId],
    queryFn: () => getSyndicate(syndicateId!),
    enabled: !!syndicateId,
  });

  const { data: campaign } = useQuery({
    queryKey: ["syndicate-campaign", syndicateId, campaignId],
    queryFn: () => getSyndicateCampaign(syndicateId!, campaignId!),
    enabled: !!syndicateId && !!campaignId,
  });

  const { data: analytics } = useQuery({
    queryKey: ["syndicate-campaign-analytics", syndicateId, campaignId],
    queryFn: () => getSyndicateCampaignAnalytics(syndicateId!, campaignId!),
    enabled: !!syndicateId && !!campaignId,
  });

  const isAdmin = syndicate?.admin_user_id === userId;

  const addBudgetMut = useMutation({
    mutationFn: (cents: number) => addSyndicateCampaignBudget(syndicateId!, campaignId!, cents),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["syndicate-campaign", syndicateId, campaignId] });
      queryClient.invalidateQueries({ queryKey: ["syndicate-treasury", syndicateId] });
      setTopUp("");
    },
  });

  const statusMut = useMutation({
    mutationFn: (status: "active" | "paused" | "cancelled") =>
      updateSyndicateCampaignStatus(syndicateId!, campaignId!, status),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["syndicate-campaign", syndicateId, campaignId] });
      queryClient.invalidateQueries({ queryKey: ["syndicate-treasury", syndicateId] });
    },
  });

  if (!campaign) {
    return <div className="p-6">Loading...</div>;
  }

  const totals = (analytics?.totals ?? {}) as {
    impressions?: number;
    clicks?: number;
    ctr?: number;
    spend_cents?: number;
  };
  const creative = campaign.creative as {
    headline?: string;
    body?: string;
    cta_text?: string;
    cta_url?: string;
  };
  const pct = campaign.budget_cents > 0 ? Math.min(100, (campaign.spent_cents / campaign.budget_cents) * 100) : 0;

  return (
    <div className="space-y-6 p-6">
      <Button variant="ghost" size="sm" onClick={() => navigate(`/syndicates/${syndicateId}/manage`)}>
        <ArrowLeft className="h-4 w-4 mr-1" /> Back to Syndicate
      </Button>

      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Megaphone className="h-6 w-6" />
          {campaign.name}
        </h1>
        <Badge>{campaign.status}</Badge>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Impressions" value={String(totals.impressions ?? 0)} />
        <StatCard label="Clicks" value={String(totals.clicks ?? 0)} />
        <StatCard label="CTR" value={`${totals.ctr ?? 0}%`} />
        <StatCard label="Spend" value={`$${((totals.spend_cents ?? 0) / 100).toFixed(2)}`} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Daily Analytics</CardTitle>
        </CardHeader>
        <CardContent>
          {!analytics || analytics.daily.length === 0 ? (
            <p className="text-muted-foreground">No analytics data yet.</p>
          ) : (
            <div className="space-y-2">
              {analytics.daily.map((d) => (
                <div key={d.date} className="flex items-center justify-between text-sm border-b py-1">
                  <span className="font-medium">{d.date}</span>
                  <div className="flex gap-4 text-muted-foreground">
                    <span>{d.impressions} impr</span>
                    <span>{d.clicks} clicks</span>
                    <span>${(d.spend_cents / 100).toFixed(2)}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Creative</CardTitle>
        </CardHeader>
        <CardContent className="space-y-1">
          <p className="font-semibold">{creative.headline}</p>
          <p className="text-sm text-muted-foreground">{creative.body}</p>
          <p className="text-sm">
            CTA: <span className="font-medium">{creative.cta_text}</span> → {creative.cta_url}
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Budget</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex justify-between text-sm mb-1">
            <span>
              ${(campaign.spent_cents / 100).toFixed(2)} spent of ${(campaign.budget_cents / 100).toFixed(2)}
            </span>
            <span>${(campaign.remaining_cents / 100).toFixed(2)} remaining</span>
          </div>
          <div className="h-2 w-full rounded-full bg-muted mb-4">
            <div className="h-2 rounded-full bg-primary" style={{ width: `${pct}%` }} />
          </div>
          {isAdmin && campaign.status !== "cancelled" && campaign.status !== "completed" && (
            <div className="flex items-end gap-2">
              <div>
                <label className="text-xs font-medium">Add budget (USD)</label>
                <Input
                  type="number"
                  value={topUp}
                  onChange={(e) => setTopUp(e.target.value)}
                  placeholder="10.00"
                  min={1}
                  step={0.01}
                  className="w-32"
                />
              </div>
              <Button
                size="sm"
                onClick={() => addBudgetMut.mutate(Math.round(parseFloat(topUp || "0") * 100))}
                disabled={!topUp || parseFloat(topUp) < 1 || addBudgetMut.isPending}
              >
                Add Budget
              </Button>
            </div>
          )}
          {isAdmin && (campaign.status === "active" || campaign.status === "paused") && (
            <div className="flex gap-2 mt-3">
              {campaign.status === "active" && (
                <Button size="sm" variant="outline" onClick={() => statusMut.mutate("paused")}>
                  Pause
                </Button>
              )}
              {campaign.status === "paused" && (
                <Button size="sm" variant="outline" onClick={() => statusMut.mutate("active")}>
                  Resume
                </Button>
              )}
              <Button
                size="sm"
                variant="outline"
                className="text-destructive"
                onClick={() => statusMut.mutate("cancelled")}
              >
                Cancel
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <Card>
      <CardContent className="p-4">
        <p className="text-xs text-muted-foreground">{label}</p>
        <p className="text-2xl font-bold">{value}</p>
      </CardContent>
    </Card>
  );
}
