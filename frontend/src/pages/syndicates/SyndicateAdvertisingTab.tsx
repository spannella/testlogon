import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Megaphone } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  listSyndicateCampaigns,
  updateSyndicateCampaignStatus,
} from "@/api/endpoints/syndicateAdvertising";
import { getTreasuryBalance } from "@/api/endpoints/syndicateTreasury";
import type { SyndicateCampaignOut } from "@/api/types";
import SyndicateAdvertisingCreateDialog from "./SyndicateAdvertisingCreateDialog";

const STATUS_VARIANT: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
  active: "default",
  paused: "secondary",
  completed: "outline",
  cancelled: "destructive",
  draft: "secondary",
};

export default function SyndicateAdvertisingTab({
  syndicateId,
  isAdmin,
}: {
  syndicateId: string;
  isAdmin: boolean;
}) {
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const { data: campaigns = [] } = useQuery({
    queryKey: ["syndicate-campaigns", syndicateId],
    queryFn: () => listSyndicateCampaigns(syndicateId),
    enabled: !!syndicateId,
  });

  const { data: balance } = useQuery({
    queryKey: ["syndicate-treasury", syndicateId],
    queryFn: () => getTreasuryBalance(syndicateId),
    enabled: !!syndicateId,
  });

  const statusMut = useMutation({
    mutationFn: ({ campaignId, status }: { campaignId: string; status: "active" | "paused" | "cancelled" }) =>
      updateSyndicateCampaignStatus(syndicateId, campaignId, status),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["syndicate-campaigns", syndicateId] });
      queryClient.invalidateQueries({ queryKey: ["syndicate-treasury", syndicateId] });
    },
  });

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="flex items-center gap-2">
          <Megaphone className="h-5 w-5" />
          Advertising Campaigns
        </CardTitle>
        <div className="flex items-center gap-3">
          {balance && (
            <span className="text-sm text-muted-foreground" data-testid="treasury-available">
              ${(balance.balance_cents / 100).toFixed(2)} available
            </span>
          )}
          {isAdmin && (
            <SyndicateAdvertisingCreateDialog
              syndicateId={syndicateId}
              treasuryCents={balance?.balance_cents ?? 0}
            />
          )}
        </div>
      </CardHeader>
      <CardContent>
        {campaigns.length === 0 ? (
          <div className="text-center py-6">
            <p className="text-muted-foreground">No advertising campaigns yet</p>
            {isAdmin && (
              <p className="text-sm text-muted-foreground mt-1">
                Create a campaign funded by the syndicate treasury
              </p>
            )}
          </div>
        ) : (
          <div className="space-y-3">
            {campaigns.map((c: SyndicateCampaignOut) => {
              const pct = c.budget_cents > 0 ? Math.min(100, (c.spent_cents / c.budget_cents) * 100) : 0;
              const summary = c.stats_summary as { impressions?: number; clicks?: number };
              return (
                <div key={c.campaign_id} className="rounded-lg border p-4">
                  <div className="flex items-center justify-between mb-2">
                    <button
                      className="font-semibold text-left hover:underline"
                      onClick={() =>
                        navigate(`/syndicates/${syndicateId}/campaigns/${c.campaign_id}`)
                      }
                    >
                      {c.name}
                    </button>
                    <Badge variant={STATUS_VARIANT[c.status] ?? "secondary"}>{c.status}</Badge>
                  </div>
                  {c.description && (
                    <p className="text-sm text-muted-foreground mb-2">{c.description}</p>
                  )}
                  <div className="mb-2">
                    <div className="flex justify-between text-xs text-muted-foreground mb-1">
                      <span>
                        ${(c.spent_cents / 100).toFixed(2)} spent of ${(c.budget_cents / 100).toFixed(2)}
                      </span>
                      <span>{pct.toFixed(0)}%</span>
                    </div>
                    <div className="h-2 w-full rounded-full bg-muted" data-testid="budget-progress">
                      <div
                        className="h-2 rounded-full bg-primary"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                  <div className="flex items-center gap-4 text-xs text-muted-foreground">
                    <span>{summary.impressions ?? 0} impressions</span>
                    <span>{summary.clicks ?? 0} clicks</span>
                  </div>
                  {isAdmin && (c.status === "active" || c.status === "paused") && (
                    <div className="flex gap-2 mt-3">
                      {c.status === "active" && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() =>
                            statusMut.mutate({ campaignId: c.campaign_id, status: "paused" })
                          }
                          disabled={statusMut.isPending}
                        >
                          Pause
                        </Button>
                      )}
                      {c.status === "paused" && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() =>
                            statusMut.mutate({ campaignId: c.campaign_id, status: "active" })
                          }
                          disabled={statusMut.isPending}
                        >
                          Resume
                        </Button>
                      )}
                      <Button
                        size="sm"
                        variant="outline"
                        className="text-destructive"
                        onClick={() =>
                          statusMut.mutate({ campaignId: c.campaign_id, status: "cancelled" })
                        }
                        disabled={statusMut.isPending}
                      >
                        Cancel
                      </Button>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
