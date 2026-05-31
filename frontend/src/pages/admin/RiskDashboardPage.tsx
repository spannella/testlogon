import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  fetchRiskDistribution,
  fetchHighRiskUsers,
  fetchUserRiskProfile,
  fetchUsersByTier,
  overrideUserRiskScore,
} from "@/api/endpoints/risk-scoring";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { ShieldAlert, TrendingUp, TrendingDown, Users } from "lucide-react";
import type { RiskScoreOut } from "@/api/types";

const TIER_COLORS: Record<string, string> = {
  low: "bg-green-100 text-green-800",
  medium: "bg-yellow-100 text-yellow-800",
  high: "bg-orange-100 text-orange-800",
  critical: "bg-red-100 text-red-800",
};

function TierBadge({ tier }: { tier: string }) {
  return (
    <Badge className={TIER_COLORS[tier] || "bg-gray-100 text-gray-800"}>
      {tier.charAt(0).toUpperCase() + tier.slice(1)} Risk
    </Badge>
  );
}

function ScoreGauge({ score }: { score: number }) {
  let color = "text-green-600";
  if (score > 80) color = "text-red-600";
  else if (score > 60) color = "text-orange-600";
  else if (score > 30) color = "text-yellow-600";
  return (
    <div className="flex flex-col items-center gap-1">
      <span className={`text-4xl font-bold ${color}`}>{score}</span>
      <span className="text-sm text-muted-foreground">/ 100</span>
    </div>
  );
}

export default function RiskDashboardPage() {
  const queryClient = useQueryClient();
  const [selectedTier, setSelectedTier] = useState<string | null>(null);
  const [overrideTarget, setOverrideTarget] = useState<string | null>(null);
  const [overrideScore, setOverrideScore] = useState("");
  const [overrideReason, setOverrideReason] = useState("");
  const [profileUser, setProfileUser] = useState<string | null>(null);

  const { data: distribution, isLoading: distLoading } = useQuery({
    queryKey: ["risk", "distribution"],
    queryFn: fetchRiskDistribution,
  });

  const { data: highRisk, isLoading: highRiskLoading } = useQuery({
    queryKey: ["risk", "high-risk"],
    queryFn: () => fetchHighRiskUsers({ threshold: 70, limit: 50 }),
  });

  const { data: tierUsers } = useQuery({
    queryKey: ["risk", "tier", selectedTier],
    queryFn: () => fetchUsersByTier(selectedTier!, 50),
    enabled: !!selectedTier,
  });

  const { data: userProfile } = useQuery({
    queryKey: ["risk", "profile", profileUser],
    queryFn: () => fetchUserRiskProfile(profileUser!),
    enabled: !!profileUser,
  });

  const overrideMut = useMutation({
    mutationFn: ({ userId, score, reason }: { userId: string; score: number; reason: string }) =>
      overrideUserRiskScore(userId, { score, reason }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["risk"] });
      setOverrideTarget(null);
      setOverrideScore("");
      setOverrideReason("");
    },
  });

  const dist = distribution?.distribution ?? { low: 0, medium: 0, high: 0, critical: 0 };
  const totalScored = distribution?.total_scored ?? 0;

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center gap-3">
        <ShieldAlert className="h-7 w-7 text-red-600" />
        <h1 className="text-2xl font-bold">Risk Scoring Dashboard</h1>
      </div>

      {/* Distribution cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {(["low", "medium", "high", "critical"] as const).map((tier) => (
          <Card
            key={tier}
            className="cursor-pointer hover:shadow-md transition-shadow"
            onClick={() => setSelectedTier(tier)}
          >
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">
                <TierBadge tier={tier} />
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold">{dist[tier] ?? 0}</div>
              <p className="text-xs text-muted-foreground">
                {totalScored > 0
                  ? `${Math.round(((dist[tier] ?? 0) / totalScored) * 100)}% of total`
                  : "No data"}
              </p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Rates */}
      <div className="grid gap-4 sm:grid-cols-2">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <TrendingDown className="h-4 w-4 text-green-500" />
              Auto-Approve Rate
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {distribution ? `${Math.round(distribution.auto_approve_rate * 100)}%` : "--"}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <TrendingUp className="h-4 w-4 text-red-500" />
              Auto-Escalate Rate
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {distribution ? `${Math.round(distribution.auto_escalate_rate * 100)}%` : "--"}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* High-risk users */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Users className="h-5 w-5" />
            High-Risk Users
          </CardTitle>
        </CardHeader>
        <CardContent>
          {highRiskLoading ? (
            <p className="text-muted-foreground">Loading...</p>
          ) : !highRisk?.items?.length ? (
            <p className="text-muted-foreground">No high-risk users found.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead>Score</TableHead>
                  <TableHead>Tier</TableHead>
                  <TableHead>Trigger</TableHead>
                  <TableHead>Auto Action</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {highRisk.items.map((item: RiskScoreOut) => (
                  <TableRow key={`${item.user_sub}-${item.created_at}`}>
                    <TableCell className="font-mono text-sm">{item.user_sub}</TableCell>
                    <TableCell>
                      <span className="font-bold">{item.total_score}</span>
                    </TableCell>
                    <TableCell>
                      <TierBadge tier={item.risk_tier} />
                    </TableCell>
                    <TableCell>{item.trigger}</TableCell>
                    <TableCell>{item.auto_action_taken}</TableCell>
                    <TableCell className="space-x-1">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setProfileUser(item.user_sub)}
                      >
                        Profile
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setOverrideTarget(item.user_sub)}
                      >
                        Override
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Tier list dialog */}
      <Dialog open={!!selectedTier} onOpenChange={() => setSelectedTier(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>
              {selectedTier && <TierBadge tier={selectedTier} />} Users
            </DialogTitle>
          </DialogHeader>
          {tierUsers?.items?.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead>Score</TableHead>
                  <TableHead>Trigger</TableHead>
                  <TableHead>Date</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tierUsers.items.map((item: RiskScoreOut) => (
                  <TableRow key={`${item.user_sub}-${item.created_at}`}>
                    <TableCell className="font-mono text-sm">{item.user_sub}</TableCell>
                    <TableCell>{item.total_score}</TableCell>
                    <TableCell>{item.trigger}</TableCell>
                    <TableCell>
                      {new Date(item.created_at * 1000).toLocaleDateString()}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <p className="text-muted-foreground py-4">No users in this tier.</p>
          )}
        </DialogContent>
      </Dialog>

      {/* Override dialog */}
      <Dialog open={!!overrideTarget} onOpenChange={() => setOverrideTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Override Risk Score</DialogTitle>
          </DialogHeader>
          <p className="text-sm text-muted-foreground">
            User: <span className="font-mono">{overrideTarget}</span>
          </p>
          <div className="space-y-3">
            <div>
              <label className="text-sm font-medium">Score (0-100)</label>
              <Input
                type="number"
                min={0}
                max={100}
                value={overrideScore}
                onChange={(e) => setOverrideScore(e.target.value)}
              />
            </div>
            <div>
              <label className="text-sm font-medium">Reason</label>
              <Input
                value={overrideReason}
                onChange={(e) => setOverrideReason(e.target.value)}
                placeholder="Reason for override"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOverrideTarget(null)}>
              Cancel
            </Button>
            <Button
              onClick={() =>
                overrideTarget &&
                overrideMut.mutate({
                  userId: overrideTarget,
                  score: Number(overrideScore),
                  reason: overrideReason,
                })
              }
              disabled={!overrideScore || !overrideReason || overrideMut.isPending}
            >
              Override
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* User profile dialog */}
      <Dialog open={!!profileUser} onOpenChange={() => setProfileUser(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Risk Profile: {profileUser}</DialogTitle>
          </DialogHeader>
          {userProfile?.latest_score ? (
            <div className="space-y-4">
              <div className="flex items-center gap-4">
                <ScoreGauge score={userProfile.latest_score.total_score} />
                <TierBadge tier={userProfile.latest_score.risk_tier} />
              </div>
              <h3 className="font-semibold">Factor Breakdown</h3>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Factor</TableHead>
                    <TableHead>Raw Value</TableHead>
                    <TableHead>Weight</TableHead>
                    <TableHead>Score</TableHead>
                    <TableHead>Weighted</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {Object.entries(userProfile.latest_score.factors).map(
                    ([name, data]) => (
                      <TableRow key={name}>
                        <TableCell className="font-mono text-xs">{name}</TableCell>
                        <TableCell>{data.raw_value}</TableCell>
                        <TableCell>{data.weight}</TableCell>
                        <TableCell>{data.score}</TableCell>
                        <TableCell>{data.weighted_score}</TableCell>
                      </TableRow>
                    ),
                  )}
                </TableBody>
              </Table>
              {userProfile.history.length > 1 && (
                <>
                  <h3 className="font-semibold">Score History</h3>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Date</TableHead>
                        <TableHead>Score</TableHead>
                        <TableHead>Tier</TableHead>
                        <TableHead>Trigger</TableHead>
                        <TableHead>Auto Action</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {userProfile.history.map((entry: Record<string, unknown>, i: number) => (
                        <TableRow key={i}>
                          <TableCell>
                            {new Date((entry.created_at as number) * 1000).toLocaleString()}
                          </TableCell>
                          <TableCell className="font-bold">
                            {entry.total_score as number}
                          </TableCell>
                          <TableCell>
                            <TierBadge tier={entry.risk_tier as string} />
                          </TableCell>
                          <TableCell>{entry.trigger as string}</TableCell>
                          <TableCell>{entry.auto_action_taken as string}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </>
              )}
            </div>
          ) : (
            <p className="text-muted-foreground py-4">No risk score computed yet.</p>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
