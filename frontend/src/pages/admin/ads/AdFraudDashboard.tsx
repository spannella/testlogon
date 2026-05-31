import { Fragment, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getFraudSummary,
  getFraudEvents,
  getFraudAccounts,
  reviewFraudEvent,
  suspendFraudAccount,
  unsuspendFraudAccount,
} from "@/api/endpoints/adFraud";
import type { AdFraudEvent } from "@/api/types";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ShieldAlert, Ban, Check, X, RefreshCw } from "lucide-react";
import { toast } from "sonner";

function topRule(ev: AdFraudEvent): string {
  const scores = ev.rule_scores || {};
  let best = "";
  let bestScore = -1;
  for (const [rule, score] of Object.entries(scores)) {
    if (Number(score) > bestScore) {
      bestScore = Number(score);
      best = rule;
    }
  }
  return best || "—";
}

function fmtRate(bps: number): string {
  return `${(bps / 100).toFixed(1)}%`;
}

export default function AdFraudDashboard() {
  const queryClient = useQueryClient();
  const [expanded, setExpanded] = useState<string | null>(null);

  const summary = useQuery({
    queryKey: ["ad-fraud", "summary"],
    queryFn: () => getFraudSummary(),
  });
  const events = useQuery({
    queryKey: ["ad-fraud", "events"],
    queryFn: () => getFraudEvents({ limit: 200 }),
  });
  const accounts = useQuery({
    queryKey: ["ad-fraud", "accounts"],
    queryFn: () => getFraudAccounts(),
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["ad-fraud"] });
  };

  const reviewMut = useMutation({
    mutationFn: ({ id, decision }: { id: string; decision: "confirm" | "dismiss" }) =>
      reviewFraudEvent(id, decision),
    onSuccess: (_d, v) => {
      toast.success(`Event ${v.decision}ed`);
      invalidate();
    },
    onError: () => toast.error("Review failed"),
  });

  const suspendMut = useMutation({
    mutationFn: (accountId: string) => suspendFraudAccount(accountId, "manual_admin_review"),
    onSuccess: () => {
      toast.success("Account suspended");
      invalidate();
    },
    onError: () => toast.error("Suspend failed"),
  });

  const unsuspendMut = useMutation({
    mutationFn: (accountId: string) => unsuspendFraudAccount(accountId),
    onSuccess: () => {
      toast.success("Account reactivated");
      invalidate();
    },
    onError: () => toast.error("Unsuspend failed"),
  });

  const s = summary.data;

  return (
    <div className="space-y-6 p-4">
      <div className="flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-2xl font-bold">
          <ShieldAlert className="h-6 w-6" /> Ad Fraud Prevention
        </h1>
        <Button variant="outline" size="sm" onClick={invalidate}>
          <RefreshCw className="mr-1 h-4 w-4" /> Refresh
        </Button>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground">Flagged Today</CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-bold">
            {s?.flagged_events_today ?? "—"}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground">Total Events</CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-bold">{s?.total_events ?? "—"}</CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground">Fraud Rate</CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-bold">
            {s ? fmtRate(s.fraud_rate_bps) : "—"}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground">Suspended Accounts</CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-bold">
            {s?.suspended_accounts ?? "—"}
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="events">
        <TabsList>
          <TabsTrigger value="events">Flagged Events</TabsTrigger>
          <TabsTrigger value="accounts">Account Risk</TabsTrigger>
        </TabsList>

        {/* Flagged events table */}
        <TabsContent value="events">
          <Card>
            <CardContent className="pt-4">
              {events.data && events.data.length === 0 && (
                <p className="py-6 text-center text-muted-foreground">
                  No flagged fraud events today.
                </p>
              )}
              {events.data && events.data.length > 0 && (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Time</TableHead>
                      <TableHead>User</TableHead>
                      <TableHead>Campaign</TableHead>
                      <TableHead>Score</TableHead>
                      <TableHead>Top Rule</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {events.data.map((ev) => (
                      <Fragment key={ev.event_id}>
                        <TableRow
                          className="cursor-pointer"
                          onClick={() =>
                            setExpanded(expanded === ev.event_id ? null : ev.event_id)
                          }
                        >
                          <TableCell>
                            {new Date(ev.created_at * 1000).toLocaleTimeString()}
                          </TableCell>
                          <TableCell className="max-w-[140px] truncate">{ev.user_id}</TableCell>
                          <TableCell className="max-w-[140px] truncate">
                            {ev.campaign_id}
                          </TableCell>
                          <TableCell>
                            <Badge variant="destructive">{ev.fraud_score}</Badge>
                          </TableCell>
                          <TableCell>{topRule(ev)}</TableCell>
                          <TableCell>
                            <Badge variant="outline">{ev.status}</Badge>
                          </TableCell>
                          <TableCell onClick={(e) => e.stopPropagation()}>
                            <div className="flex gap-1">
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() =>
                                  reviewMut.mutate({ id: ev.event_id, decision: "confirm" })
                                }
                              >
                                <Check className="h-3 w-3" />
                              </Button>
                              <Button
                                size="sm"
                                variant="ghost"
                                onClick={() =>
                                  reviewMut.mutate({ id: ev.event_id, decision: "dismiss" })
                                }
                              >
                                <X className="h-3 w-3" />
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                        {expanded === ev.event_id && (
                          <TableRow>
                            <TableCell colSpan={7} className="bg-muted/40">
                              <div className="space-y-1 text-xs">
                                <div className="font-semibold">Rule breakdown:</div>
                                {Object.entries(ev.rule_scores || {}).map(([rule, score]) => (
                                  <div key={rule} className="flex justify-between">
                                    <span>{rule}</span>
                                    <span>{Number(score)}</span>
                                  </div>
                                ))}
                                <div className="pt-1 text-muted-foreground">
                                  IP: {ev.ip_address || "—"} · Creative: {ev.creative_id || "—"}
                                </div>
                              </div>
                            </TableCell>
                          </TableRow>
                        )}
                      </Fragment>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Account risk table */}
        <TabsContent value="accounts">
          <Card>
            <CardContent className="pt-4">
              {accounts.data && accounts.data.length === 0 && (
                <p className="py-6 text-center text-muted-foreground">
                  No accounts with ad-fraud activity yet.
                </p>
              )}
              {accounts.data && accounts.data.length > 0 && (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Account</TableHead>
                      <TableHead>Fraud Rate</TableHead>
                      <TableHead>Flagged / Total</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {accounts.data.map((a) => (
                      <TableRow key={a.account_id}>
                        <TableCell className="max-w-[180px] truncate">{a.account_id}</TableCell>
                        <TableCell>{fmtRate(a.fraud_rate_bps)}</TableCell>
                        <TableCell>
                          {a.flagged_events} / {a.total_events}
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant={a.status === "suspended" ? "destructive" : "outline"}
                          >
                            {a.status}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          {a.status === "suspended" ? (
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => unsuspendMut.mutate(a.account_id)}
                            >
                              Reactivate
                            </Button>
                          ) : (
                            <Button
                              size="sm"
                              variant="destructive"
                              onClick={() => suspendMut.mutate(a.account_id)}
                            >
                              <Ban className="mr-1 h-3 w-3" /> Suspend
                            </Button>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
