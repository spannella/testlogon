import { useState } from "react";
import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getTreasuryBalance,
  getTreasuryLedger,
  getTreasuryContributors,
  contributeToTreasury,
  spendTreasury,
  setFundraisingGoal,
} from "@/api/endpoints/groups";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Loader2, ArrowUpCircle, ArrowDownCircle, DollarSign, Target, Users } from "lucide-react";

function fmt(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

export default function GroupTreasuryPage() {
  const { groupId } = useParams<{ groupId: string }>();
  const qc = useQueryClient();

  // State
  const [contributeAmount, setContributeAmount] = useState("");
  const [spendAmount, setSpendAmount] = useState("");
  const [spendReason, setSpendReason] = useState("");
  const [spendCategory, setSpendCategory] = useState("ad_spend");
  const [goalAmount, setGoalAmount] = useState("");
  const [activeTab, setActiveTab] = useState<"ledger" | "contributors" | "contribute">("contribute");

  // Queries
  const balanceQ = useQuery({
    queryKey: ["treasury-balance", groupId],
    queryFn: () => getTreasuryBalance(groupId!),
    enabled: !!groupId,
    staleTime: 10_000,
  });

  const ledgerQ = useQuery({
    queryKey: ["treasury-ledger", groupId],
    queryFn: () => getTreasuryLedger(groupId!, { limit: 50 }),
    enabled: !!groupId && activeTab === "ledger",
    staleTime: 30_000,
  });

  const contributorsQ = useQuery({
    queryKey: ["treasury-contributors", groupId],
    queryFn: () => getTreasuryContributors(groupId!),
    enabled: !!groupId && activeTab === "contributors",
    staleTime: 60_000,
  });

  // Mutations
  const contributeMut = useMutation({
    mutationFn: (cents: number) => contributeToTreasury(groupId!, cents),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["treasury-balance", groupId] });
      qc.invalidateQueries({ queryKey: ["treasury-ledger", groupId] });
      qc.invalidateQueries({ queryKey: ["treasury-contributors", groupId] });
      setContributeAmount("");
    },
  });

  const spendMut = useMutation({
    mutationFn: () =>
      spendTreasury(groupId!, {
        amount_cents: Math.round(parseFloat(spendAmount) * 100),
        reason: spendReason,
        category: spendCategory,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["treasury-balance", groupId] });
      qc.invalidateQueries({ queryKey: ["treasury-ledger", groupId] });
      setSpendAmount("");
      setSpendReason("");
    },
  });

  const goalMut = useMutation({
    mutationFn: (cents: number | null) => setFundraisingGoal(groupId!, cents),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["treasury-balance", groupId] });
      setGoalAmount("");
    },
  });

  if (!groupId) return <div>Missing group ID</div>;

  const balance = balanceQ.data;
  const isLoading = balanceQ.isLoading;

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-6" data-testid="group-treasury-page">
      <h1 className="text-2xl font-bold">Group Treasury</h1>

      {isLoading ? (
        <div className="flex justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin" />
        </div>
      ) : balance ? (
        <>
          {/* Balance Card */}
          <Card data-testid="treasury-balance-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <DollarSign className="h-5 w-5" />
                Treasury Balance
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold" data-testid="balance-amount">
                {fmt(balance.balance_cents)}
              </div>
              <div className="mt-4 grid grid-cols-3 gap-4 text-sm">
                <div>
                  <span className="text-muted-foreground">Contributed</span>
                  <div className="font-semibold text-green-600" data-testid="total-contributed">
                    {fmt(balance.total_contributed_cents)}
                  </div>
                </div>
                <div>
                  <span className="text-muted-foreground">Donated</span>
                  <div className="font-semibold text-blue-600" data-testid="total-donated">
                    {fmt(balance.total_donated_cents)}
                  </div>
                </div>
                <div>
                  <span className="text-muted-foreground">Spent</span>
                  <div className="font-semibold text-red-600" data-testid="total-spent">
                    {fmt(balance.total_spent_cents)}
                  </div>
                </div>
              </div>

              {/* Goal Progress */}
              {balance.fundraising_goal_cents != null && balance.fundraising_goal_cents > 0 && (
                <div className="mt-4" data-testid="goal-progress">
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <Target className="h-4 w-4" />
                    Goal: {fmt(balance.fundraising_goal_cents)}
                  </div>
                  <div className="mt-1 h-2 rounded-full bg-muted">
                    <div
                      className="h-full rounded-full bg-primary transition-all"
                      style={{
                        width: `${Math.min(100, (balance.balance_cents / balance.fundraising_goal_cents) * 100)}%`,
                      }}
                    />
                  </div>
                  <div className="mt-1 text-xs text-muted-foreground">
                    {Math.round((balance.balance_cents / balance.fundraising_goal_cents) * 100)}% of goal
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Tab Navigation */}
          <div className="flex gap-2" data-testid="treasury-tabs">
            <Button
              variant={activeTab === "contribute" ? "default" : "outline"}
              size="sm"
              onClick={() => setActiveTab("contribute")}
            >
              Contribute
            </Button>
            <Button
              variant={activeTab === "ledger" ? "default" : "outline"}
              size="sm"
              onClick={() => setActiveTab("ledger")}
            >
              Transactions
            </Button>
            <Button
              variant={activeTab === "contributors" ? "default" : "outline"}
              size="sm"
              onClick={() => setActiveTab("contributors")}
            >
              <Users className="mr-1 h-4 w-4" />
              Contributors
            </Button>
          </div>

          {/* Contribute Section */}
          {activeTab === "contribute" && (
            <Card data-testid="contribute-section">
              <CardHeader>
                <CardTitle>Contribute to Treasury</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-2">
                  {[1000, 2500, 5000, 10000].map((cents) => (
                    <Button
                      key={cents}
                      variant="outline"
                      size="sm"
                      onClick={() => setContributeAmount((cents / 100).toString())}
                    >
                      {fmt(cents)}
                    </Button>
                  ))}
                </div>
                <div className="flex items-end gap-2">
                  <div className="flex-1">
                    <Label htmlFor="contribute-amount">Amount ($)</Label>
                    <Input
                      id="contribute-amount"
                      type="number"
                      min="1"
                      step="0.01"
                      value={contributeAmount}
                      onChange={(e) => setContributeAmount(e.target.value)}
                      placeholder="0.00"
                      data-testid="contribute-amount-input"
                    />
                  </div>
                  <Button
                    onClick={() => {
                      const cents = Math.round(parseFloat(contributeAmount) * 100);
                      if (cents >= 100) contributeMut.mutate(cents);
                    }}
                    disabled={
                      contributeMut.isPending ||
                      !contributeAmount ||
                      parseFloat(contributeAmount) < 1
                    }
                    data-testid="contribute-button"
                  >
                    {contributeMut.isPending ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      "Contribute"
                    )}
                  </Button>
                </div>
                {contributeMut.isError && (
                  <p className="text-sm text-destructive">
                    {(contributeMut.error as Error)?.message || "Contribution failed"}
                  </p>
                )}
              </CardContent>
            </Card>
          )}

          {/* Ledger / Transactions */}
          {activeTab === "ledger" && (
            <Card data-testid="ledger-section">
              <CardHeader>
                <CardTitle>Transaction History</CardTitle>
              </CardHeader>
              <CardContent>
                {ledgerQ.isLoading ? (
                  <div className="flex justify-center py-4">
                    <Loader2 className="h-6 w-6 animate-spin" />
                  </div>
                ) : ledgerQ.data?.entries?.length ? (
                  <div className="space-y-2">
                    {ledgerQ.data.entries.map((entry) => (
                      <div
                        key={entry.entry_id}
                        className="flex items-center justify-between rounded-lg border p-3"
                        data-testid="ledger-entry"
                      >
                        <div className="flex items-center gap-3">
                          {entry.direction === "credit" ? (
                            <ArrowUpCircle className="h-5 w-5 text-green-500" />
                          ) : (
                            <ArrowDownCircle className="h-5 w-5 text-red-500" />
                          )}
                          <div>
                            <div className="font-medium">{entry.reason}</div>
                            <div className="text-xs text-muted-foreground">
                              {entry.category}
                              {entry.actor_display_name && ` by ${entry.actor_display_name}`}
                            </div>
                          </div>
                        </div>
                        <div
                          className={`font-semibold ${entry.direction === "credit" ? "text-green-600" : "text-red-600"}`}
                        >
                          {entry.direction === "credit" ? "+" : "-"}
                          {fmt(entry.amount_cents)}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-center text-muted-foreground">No transactions yet</p>
                )}
              </CardContent>
            </Card>
          )}

          {/* Contributors */}
          {activeTab === "contributors" && (
            <Card data-testid="contributors-section">
              <CardHeader>
                <CardTitle>Contributors ({contributorsQ.data?.count ?? 0})</CardTitle>
              </CardHeader>
              <CardContent>
                {contributorsQ.isLoading ? (
                  <div className="flex justify-center py-4">
                    <Loader2 className="h-6 w-6 animate-spin" />
                  </div>
                ) : contributorsQ.data?.contributors?.length ? (
                  <div className="space-y-2">
                    {contributorsQ.data.contributors.map((c, i) => (
                      <div
                        key={c.user_id}
                        className="flex items-center justify-between rounded-lg border p-3"
                        data-testid="contributor-row"
                      >
                        <div>
                          <div className="font-medium">
                            #{i + 1} {c.display_name}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {c.contribution_count} contribution{c.contribution_count !== 1 ? "s" : ""}
                          </div>
                        </div>
                        <div className="font-semibold text-green-600">
                          {fmt(c.total_contributed_cents)}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-center text-muted-foreground">No contributors yet</p>
                )}
              </CardContent>
            </Card>
          )}

          {/* Admin Spend Section */}
          <Card data-testid="spend-section">
            <CardHeader>
              <CardTitle>Spend Treasury (Admin)</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label htmlFor="spend-amount">Amount ($)</Label>
                <Input
                  id="spend-amount"
                  type="number"
                  min="0.01"
                  step="0.01"
                  value={spendAmount}
                  onChange={(e) => setSpendAmount(e.target.value)}
                  placeholder="0.00"
                  data-testid="spend-amount-input"
                />
              </div>
              <div>
                <Label htmlFor="spend-reason">Reason</Label>
                <Input
                  id="spend-reason"
                  value={spendReason}
                  onChange={(e) => setSpendReason(e.target.value)}
                  placeholder="Enter reason for spending"
                  data-testid="spend-reason-input"
                />
              </div>
              <div>
                <Label htmlFor="spend-category">Category</Label>
                <Select value={spendCategory} onValueChange={setSpendCategory}>
                  <SelectTrigger data-testid="spend-category-select">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="ad_spend">Ad Spend</SelectItem>
                    <SelectItem value="event">Event</SelectItem>
                    <SelectItem value="premium_feature">Premium Feature</SelectItem>
                    <SelectItem value="other">Other</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <Button
                onClick={() => spendMut.mutate()}
                disabled={
                  spendMut.isPending ||
                  !spendAmount ||
                  parseFloat(spendAmount) <= 0 ||
                  !spendReason ||
                  spendReason.length < 3
                }
                data-testid="spend-button"
              >
                {spendMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : "Spend"}
              </Button>
              {spendMut.isError && (
                <p className="text-sm text-destructive">
                  {(spendMut.error as Error)?.message || "Spend failed"}
                </p>
              )}
            </CardContent>
          </Card>

          {/* Goal Setting */}
          <Card data-testid="goal-section">
            <CardHeader>
              <CardTitle>Fundraising Goal (Admin)</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-end gap-2">
                <div className="flex-1">
                  <Label htmlFor="goal-amount">Goal Amount ($)</Label>
                  <Input
                    id="goal-amount"
                    type="number"
                    min="0"
                    step="1"
                    value={goalAmount}
                    onChange={(e) => setGoalAmount(e.target.value)}
                    placeholder="0"
                    data-testid="goal-amount-input"
                  />
                </div>
                <Button
                  onClick={() => {
                    const cents = goalAmount
                      ? Math.round(parseFloat(goalAmount) * 100)
                      : null;
                    goalMut.mutate(cents);
                  }}
                  disabled={goalMut.isPending}
                  data-testid="set-goal-button"
                >
                  {goalMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : "Set Goal"}
                </Button>
                {balance.fundraising_goal_cents != null && (
                  <Button
                    variant="outline"
                    onClick={() => goalMut.mutate(null)}
                    disabled={goalMut.isPending}
                    data-testid="clear-goal-button"
                  >
                    Clear Goal
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>
        </>
      ) : (
        <p className="text-muted-foreground">Unable to load treasury data.</p>
      )}
    </div>
  );
}
