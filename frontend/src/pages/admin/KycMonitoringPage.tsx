import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getMonitoringDashboard,
  runReviewCheck,
  runRescreening,
  getMyTriggers,
} from "@/api/endpoints/kycMonitoring";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

function fmtDate(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}

function tierBadge(tier: string) {
  const variant =
    tier === "critical" || tier === "high" ? "destructive" : "secondary";
  return <Badge variant={variant as "destructive" | "secondary"}>{tier}</Badge>;
}

export default function KycMonitoringPage() {
  const queryClient = useQueryClient();
  const [lastRun, setLastRun] = useState<string | null>(null);

  const dashboardQuery = useQuery({
    queryKey: ["kyc-monitoring", "dashboard"],
    queryFn: getMonitoringDashboard,
  });

  const triggersQuery = useQuery({
    queryKey: ["kyc-monitoring", "my-triggers"],
    queryFn: getMyTriggers,
  });

  const reviewCheckMut = useMutation({
    mutationFn: () => runReviewCheck(false),
    onSuccess: (res) => {
      setLastRun(
        `Review check: ${res.entered_grace_period} entered grace, ${res.auto_downgraded} downgraded`,
      );
      queryClient.invalidateQueries({ queryKey: ["kyc-monitoring"] });
    },
  });

  const rescreenMut = useMutation({
    mutationFn: () => runRescreening(false),
    onSuccess: (res) => {
      setLastRun(
        `Re-screening: ${res.total_screened} screened, ${res.matches_found} matches, ${res.triggers_created} triggers`,
      );
      queryClient.invalidateQueries({ queryKey: ["kyc-monitoring"] });
    },
  });

  const dashboard = dashboardQuery.data;

  return (
    <div className="space-y-6 p-6" data-testid="kyc-monitoring-page">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">KYC Monitoring</h1>
        <div className="flex gap-2">
          <Button
            onClick={() => reviewCheckMut.mutate()}
            disabled={reviewCheckMut.isPending}
            data-testid="run-review-check"
          >
            {reviewCheckMut.isPending ? "Running…" : "Run Review Check"}
          </Button>
          <Button
            variant="outline"
            onClick={() => rescreenMut.mutate()}
            disabled={rescreenMut.isPending}
            data-testid="run-rescreening"
          >
            {rescreenMut.isPending ? "Running…" : "Run Re-screening"}
          </Button>
        </div>
      </div>

      {lastRun && (
        <div
          className="rounded-md bg-muted px-4 py-2 text-sm"
          data-testid="last-run-result"
        >
          {lastRun}
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>
            Upcoming Reviews ({dashboard?.upcoming_reviews.length ?? 0})
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Table data-testid="upcoming-reviews-table">
            <TableHeader>
              <TableRow>
                <TableHead>User</TableHead>
                <TableHead>Risk Tier</TableHead>
                <TableHead>Next Review</TableHead>
                <TableHead>Days Until Due</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(dashboard?.upcoming_reviews ?? []).map((r) => (
                <TableRow key={r.user_sub}>
                  <TableCell>{r.user_sub}</TableCell>
                  <TableCell>{tierBadge(r.risk_tier)}</TableCell>
                  <TableCell>{fmtDate(r.next_review_date)}</TableCell>
                  <TableCell>{r.days_until_due}</TableCell>
                </TableRow>
              ))}
              {(dashboard?.upcoming_reviews.length ?? 0) === 0 && (
                <TableRow>
                  <TableCell colSpan={4} className="text-muted-foreground">
                    No upcoming reviews.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>
            Overdue Reviews ({dashboard?.overdue_reviews.length ?? 0})
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Table data-testid="overdue-reviews-table">
            <TableHeader>
              <TableRow>
                <TableHead>User</TableHead>
                <TableHead>Risk Tier</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Days Overdue</TableHead>
                <TableHead>Grace Deadline</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(dashboard?.overdue_reviews ?? []).map((r) => (
                <TableRow key={`${r.user_sub}-${r.status}`}>
                  <TableCell>{r.user_sub}</TableCell>
                  <TableCell>{tierBadge(r.risk_tier)}</TableCell>
                  <TableCell>
                    <Badge variant="destructive">{r.status}</Badge>
                  </TableCell>
                  <TableCell>{r.days_overdue}</TableCell>
                  <TableCell>{fmtDate(r.grace_deadline)}</TableCell>
                </TableRow>
              ))}
              {(dashboard?.overdue_reviews.length ?? 0) === 0 && (
                <TableRow>
                  <TableCell colSpan={5} className="text-muted-foreground">
                    No overdue reviews.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>
            My Trigger Event Log ({triggersQuery.data?.events.length ?? 0})
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Table data-testid="trigger-events-table">
            <TableHeader>
              <TableRow>
                <TableHead>Type</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>By</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(triggersQuery.data?.events ?? []).map((e) => (
                <TableRow key={e.sk}>
                  <TableCell>
                    <Badge variant="outline">{e.trigger_type}</Badge>
                  </TableCell>
                  <TableCell>{fmtDate(e.created_at)}</TableCell>
                  <TableCell>{e.created_by}</TableCell>
                </TableRow>
              ))}
              {(triggersQuery.data?.events.length ?? 0) === 0 && (
                <TableRow>
                  <TableCell colSpan={3} className="text-muted-foreground">
                    No trigger events.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
