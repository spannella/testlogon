import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Gauge, RefreshCw } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import AdOptimizationRecommendationCards from "@/components/ads/AdOptimizationRecommendationCards";
import AdOptimizationABTestResults from "@/components/ads/AdOptimizationABTestResults";
import {
  applyRecommendation,
  dismissRecommendation,
  generateRecommendations,
  getABTestResults,
  getBudgetRecommendation,
  getSuggestedBid,
  listRecommendations,
  updateOptimizationConfig,
} from "@/api/endpoints/adOptimization";

export default function AdOptimizationPanel() {
  const [params] = useSearchParams();
  const campaignId = params.get("campaign") ?? "";
  const queryClient = useQueryClient();

  const [creativeA, setCreativeA] = useState("");
  const [creativeB, setCreativeB] = useState("");
  const [desiredReach, setDesiredReach] = useState(1000);
  const [ctrThreshold, setCtrThreshold] = useState(0.005);

  const recsKey = ["ad-opt-recs", campaignId];

  const { data: recs } = useQuery({
    queryKey: recsKey,
    queryFn: () => listRecommendations(campaignId),
    enabled: !!campaignId,
  });

  const { data: suggestedBid } = useQuery({
    queryKey: ["ad-opt-bid", campaignId],
    queryFn: () => getSuggestedBid(campaignId),
    enabled: !!campaignId,
  });

  const { data: budget } = useQuery({
    queryKey: ["ad-opt-budget", campaignId, desiredReach],
    queryFn: () => getBudgetRecommendation(campaignId, desiredReach),
    enabled: !!campaignId,
  });

  const { data: abTest } = useQuery({
    queryKey: ["ad-opt-abtest", campaignId, creativeA, creativeB],
    queryFn: () =>
      getABTestResults(campaignId, {
        creative_a_id: creativeA,
        creative_b_id: creativeB,
      }),
    enabled: !!campaignId && !!creativeA && !!creativeB,
  });

  const invalidateRecs = () =>
    queryClient.invalidateQueries({ queryKey: recsKey });

  const generateMut = useMutation({
    mutationFn: () => generateRecommendations(campaignId),
    onSuccess: invalidateRecs,
  });

  const applyMut = useMutation({
    mutationFn: (recId: string) => applyRecommendation(campaignId, recId),
    onSuccess: invalidateRecs,
  });

  const dismissMut = useMutation({
    mutationFn: (recId: string) => dismissRecommendation(campaignId, recId),
    onSuccess: invalidateRecs,
  });

  const configMut = useMutation({
    mutationFn: () =>
      updateOptimizationConfig(campaignId, {
        auto_optimize_enabled: true,
        ctr_threshold: ctrThreshold,
      }),
    onSuccess: invalidateRecs,
  });

  return (
    <div className="space-y-6 p-4" data-testid="ad-optimization-panel">
      <div className="flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-2xl font-semibold">
          <Gauge className="h-6 w-6" /> Ad Optimization
        </h1>
        <Button
          onClick={() => generateMut.mutate()}
          disabled={!campaignId || generateMut.isPending}
          data-testid="ad-opt-generate"
        >
          <RefreshCw className="mr-2 h-4 w-4" /> Run Optimization
        </Button>
      </div>

      {!campaignId ? (
        <p className="text-sm text-muted-foreground">
          Provide a campaign via the <code>?campaign=</code> query parameter.
        </p>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Recommendations</CardTitle>
        </CardHeader>
        <CardContent>
          <AdOptimizationRecommendationCards
            recommendations={recs?.recommendations ?? []}
            onApply={(id) => applyMut.mutate(id)}
            onDismiss={(id) => dismissMut.mutate(id)}
            pending={applyMut.isPending || dismissMut.isPending}
          />
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Suggested Bid</CardTitle>
          </CardHeader>
          <CardContent className="space-y-1 text-sm">
            {suggestedBid ? (
              <>
                <div>Min: {suggestedBid.min_bid_cpm_cents}c</div>
                <div data-testid="ad-opt-suggested-bid">
                  Suggested: {suggestedBid.suggested_bid_cpm_cents}c
                </div>
                <div>Max: {suggestedBid.max_bid_cpm_cents}c</div>
                <div>Competition: {suggestedBid.competition_level}</div>
              </>
            ) : (
              <span className="text-muted-foreground">No data</span>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Budget Recommendation</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <div className="flex items-end gap-2">
              <div className="flex-1">
                <Label htmlFor="reach">Desired daily reach</Label>
                <Input
                  id="reach"
                  type="number"
                  value={desiredReach}
                  onChange={(e) => setDesiredReach(Number(e.target.value))}
                />
              </div>
            </div>
            {budget ? (
              <div data-testid="ad-opt-budget">
                Recommended: {budget.recommended_daily_budget_cents}c/day
              </div>
            ) : null}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">A/B Test Creatives</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid gap-2 md:grid-cols-2">
            <div>
              <Label htmlFor="cra">Creative A</Label>
              <Input
                id="cra"
                value={creativeA}
                onChange={(e) => setCreativeA(e.target.value)}
              />
            </div>
            <div>
              <Label htmlFor="crb">Creative B</Label>
              <Input
                id="crb"
                value={creativeB}
                onChange={(e) => setCreativeB(e.target.value)}
              />
            </div>
          </div>
          <AdOptimizationABTestResults
            result={abTest}
            creativeAId={creativeA}
            creativeBId={creativeB}
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Optimization Config</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <div>
            <Label htmlFor="ctr">Auto-pause CTR threshold</Label>
            <Input
              id="ctr"
              type="number"
              step="0.001"
              value={ctrThreshold}
              onChange={(e) => setCtrThreshold(Number(e.target.value))}
            />
          </div>
          <Button
            onClick={() => configMut.mutate()}
            disabled={!campaignId || configMut.isPending}
            data-testid="ad-opt-save-config"
          >
            Enable Auto-Optimize
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
