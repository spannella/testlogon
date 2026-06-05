import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  listAdvertiserAccounts,
  listAdCreatives,
  getModerationQueue,
  getPlatformMetrics,
  getRevenueSeries,
  getTopSpenders,
  moderateAccount,
  moderateCreative,
  getKillSwitchState,
  toggleKillSwitch,
} from "@/api/endpoints/adminAdPlatform";
import type { AdminAdModerationAction } from "@/api/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Megaphone, Check, X, Ban, RefreshCw, AlertTriangle, Power } from "lucide-react";
import { toast } from "sonner";
import { useAuthStore } from "@/stores/authStore";
import { canSeeRootRoleManagement } from "@/lib/adminCapabilities";

function money(cents: number): string {
  return `$${((cents || 0) / 100).toFixed(2)}`;
}

function statusVariant(status: string): "default" | "secondary" | "destructive" | "outline" {
  if (status === "active" || status === "approved") return "default";
  if (status === "pending_review") return "secondary";
  if (status === "rejected" || status === "suspended") return "destructive";
  return "outline";
}

export default function AdPlatformDashboard() {
  const qc = useQueryClient();
  const [statusFilter, setStatusFilter] = useState("");
  // The kill-switch toggle is ROOT-only (enforced server-side); only surface the
  // Emergency Controls tab to ROOT operators to avoid a confusing 403.
  const accessToken = useAuthStore((s) => s.accessToken);
  const isRoot = canSeeRootRoleManagement(accessToken);

  const metricsQ = useQuery({
    queryKey: ["adPlatform", "metrics"],
    queryFn: () => getPlatformMetrics(),
  });
  const seriesQ = useQuery({
    queryKey: ["adPlatform", "revenue-series"],
    queryFn: () => getRevenueSeries(),
  });
  const spendersQ = useQuery({
    queryKey: ["adPlatform", "top-spenders"],
    queryFn: () => getTopSpenders(10),
  });
  const accountsQ = useQuery({
    queryKey: ["adPlatform", "accounts", statusFilter],
    queryFn: () => listAdvertiserAccounts(statusFilter ? { status: statusFilter } : undefined),
  });
  const queueQ = useQuery({
    queryKey: ["adPlatform", "queue"],
    queryFn: () => getModerationQueue(),
  });
  const creativesQ = useQuery({
    queryKey: ["adPlatform", "creatives"],
    queryFn: () => listAdCreatives(),
  });

  const refetchAll = () => {
    qc.invalidateQueries({ queryKey: ["adPlatform"] });
  };

  const acctMut = useMutation({
    mutationFn: ({ id, data }: { id: string; data: AdminAdModerationAction }) =>
      moderateAccount(id, data),
    onSuccess: (r) => {
      toast.success(`Account ${r.status}`);
      refetchAll();
    },
    onError: () => toast.error("Moderation failed"),
  });
  const creativeMut = useMutation({
    mutationFn: ({ id, data }: { id: string; data: AdminAdModerationAction }) =>
      moderateCreative(id, data),
    onSuccess: (r) => {
      toast.success(`Creative ${r.status}`);
      refetchAll();
    },
    onError: () => toast.error("Moderation failed"),
  });

  const m = metricsQ.data;

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Megaphone className="h-6 w-6 text-primary" />
          <h1 className="text-2xl font-semibold">Ad Platform Management</h1>
        </div>
        <Button variant="outline" size="sm" onClick={refetchAll}>
          <RefreshCw className="mr-2 h-4 w-4" /> Refresh
        </Button>
      </div>

      <Tabs defaultValue="revenue">
        <TabsList>
          <TabsTrigger value="revenue">Revenue</TabsTrigger>
          <TabsTrigger value="moderation">Moderation</TabsTrigger>
          <TabsTrigger value="accounts">Accounts</TabsTrigger>
          <TabsTrigger value="creatives">Creatives</TabsTrigger>
          {isRoot && <TabsTrigger value="controls">Emergency Controls</TabsTrigger>}
        </TabsList>

        {/* ── Revenue ──────────────────────────────────────────────── */}
        <TabsContent value="revenue" className="space-y-4">
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm text-muted-foreground">Total Spend</CardTitle>
              </CardHeader>
              <CardContent className="text-2xl font-bold">
                {money(m?.total_spend_cents ?? 0)}
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm text-muted-foreground">Platform Revenue</CardTitle>
              </CardHeader>
              <CardContent className="text-2xl font-bold">
                {money(m?.platform_revenue_cents ?? 0)}
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm text-muted-foreground">Creator Share</CardTitle>
              </CardHeader>
              <CardContent className="text-2xl font-bold">
                {money(m?.creator_share_cents ?? 0)}
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm text-muted-foreground">Impressions</CardTitle>
              </CardHeader>
              <CardContent className="text-2xl font-bold">
                {(m?.impressions ?? 0).toLocaleString()}
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Top Spending Advertisers</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Account</TableHead>
                    <TableHead>Company</TableHead>
                    <TableHead className="text-right">Spend</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(spendersQ.data ?? []).map((s) => (
                    <TableRow key={s.account_id}>
                      <TableCell className="font-mono text-xs">{s.account_id}</TableCell>
                      <TableCell>{s.company_name || "—"}</TableCell>
                      <TableCell className="text-right">{money(s.spend_cents)}</TableCell>
                    </TableRow>
                  ))}
                  {(spendersQ.data ?? []).length === 0 && (
                    <TableRow>
                      <TableCell colSpan={3} className="text-center text-muted-foreground">
                        No spend recorded yet
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Monthly Revenue</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Month</TableHead>
                    <TableHead className="text-right">Spend</TableHead>
                    <TableHead className="text-right">Platform Revenue</TableHead>
                    <TableHead className="text-right">Impressions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(seriesQ.data ?? []).map((p) => (
                    <TableRow key={p.month}>
                      <TableCell>{p.month}</TableCell>
                      <TableCell className="text-right">{money(p.spend_cents)}</TableCell>
                      <TableCell className="text-right">
                        {money(p.platform_revenue_cents)}
                      </TableCell>
                      <TableCell className="text-right">{p.impressions}</TableCell>
                    </TableRow>
                  ))}
                  {(seriesQ.data ?? []).length === 0 && (
                    <TableRow>
                      <TableCell colSpan={4} className="text-center text-muted-foreground">
                        No revenue data
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Moderation ───────────────────────────────────────────── */}
        <TabsContent value="moderation" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Pending Accounts</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Account</TableHead>
                    <TableHead>Company</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(queueQ.data?.accounts ?? []).map((a) => (
                    <TableRow key={a.account_id}>
                      <TableCell className="font-mono text-xs">{a.account_id}</TableCell>
                      <TableCell>{a.company_name}</TableCell>
                      <TableCell>
                        <Badge variant={statusVariant(a.status)}>{a.status}</Badge>
                      </TableCell>
                      <TableCell className="space-x-1 text-right">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() =>
                            acctMut.mutate({ id: a.account_id, data: { action: "approve" } })
                          }
                        >
                          <Check className="h-4 w-4" />
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() =>
                            acctMut.mutate({
                              id: a.account_id,
                              data: { action: "reject", reason: "Policy violation" },
                            })
                          }
                        >
                          <X className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                  {(queueQ.data?.accounts ?? []).length === 0 && (
                    <TableRow>
                      <TableCell colSpan={4} className="text-center text-muted-foreground">
                        No pending accounts
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Pending Creatives</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Creative</TableHead>
                    <TableHead>Title</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(queueQ.data?.creatives ?? []).map((c) => (
                    <TableRow key={c.creative_id}>
                      <TableCell className="font-mono text-xs">{c.creative_id}</TableCell>
                      <TableCell>{c.title}</TableCell>
                      <TableCell>
                        <Badge variant={statusVariant(c.status)}>{c.status}</Badge>
                      </TableCell>
                      <TableCell className="space-x-1 text-right">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() =>
                            creativeMut.mutate({
                              id: c.creative_id,
                              data: { action: "approve" },
                            })
                          }
                        >
                          <Check className="h-4 w-4" />
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() =>
                            creativeMut.mutate({
                              id: c.creative_id,
                              data: { action: "reject", reason: "Violates content policy" },
                            })
                          }
                        >
                          <X className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                  {(queueQ.data?.creatives ?? []).length === 0 && (
                    <TableRow>
                      <TableCell colSpan={4} className="text-center text-muted-foreground">
                        No pending creatives
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Accounts ─────────────────────────────────────────────── */}
        <TabsContent value="accounts" className="space-y-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle>Advertiser Accounts</CardTitle>
              <Input
                placeholder="Filter by status"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="w-48"
              />
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Account</TableHead>
                    <TableHead>Owner</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Lifetime Spend</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(accountsQ.data ?? []).map((a) => (
                    <TableRow key={a.account_id}>
                      <TableCell className="font-mono text-xs">{a.account_id}</TableCell>
                      <TableCell>{a.owner_sub}</TableCell>
                      <TableCell>
                        <Badge variant={statusVariant(a.status)}>{a.status}</Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        {money(a.lifetime_spend_cents)}
                      </TableCell>
                      <TableCell className="text-right">
                        {a.status === "suspended" ? (
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() =>
                              acctMut.mutate({ id: a.account_id, data: { action: "approve" } })
                            }
                          >
                            <Check className="mr-1 h-4 w-4" /> Unsuspend
                          </Button>
                        ) : (
                          <Button
                            size="sm"
                            variant="destructive"
                            onClick={() =>
                              acctMut.mutate({
                                id: a.account_id,
                                data: { action: "suspend", reason: "Admin suspension" },
                              })
                            }
                          >
                            <Ban className="mr-1 h-4 w-4" /> Suspend
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                  {(accountsQ.data ?? []).length === 0 && (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center text-muted-foreground">
                        No advertiser accounts
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Creatives ────────────────────────────────────────────── */}
        <TabsContent value="creatives" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>All Creatives</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Creative</TableHead>
                    <TableHead>Title</TableHead>
                    <TableHead>Format</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(creativesQ.data ?? []).map((c) => (
                    <TableRow key={c.creative_id}>
                      <TableCell className="font-mono text-xs">{c.creative_id}</TableCell>
                      <TableCell>{c.title}</TableCell>
                      <TableCell>{c.format}</TableCell>
                      <TableCell>
                        <Badge variant={statusVariant(c.status)}>{c.status}</Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                  {(creativesQ.data ?? []).length === 0 && (
                    <TableRow>
                      <TableCell colSpan={4} className="text-center text-muted-foreground">
                        No creatives
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Emergency Controls (ROOT only) ───────────────────────── */}
        {isRoot && (
          <TabsContent value="controls" className="space-y-4">
            <KillSwitchPanel />
          </TabsContent>
        )}
      </Tabs>
    </div>
  );
}

/**
 * Platform-wide ad serving kill switch. ROOT operators can halt or resume all
 * ad serving in an emergency. Backed by GAP-0068's
 * GET/POST /ui/admin/ad-platform/kill-switch endpoints.
 */
function KillSwitchPanel() {
  const qc = useQueryClient();
  const [reason, setReason] = useState("");
  const [confirming, setConfirming] = useState(false);

  const ksQ = useQuery({
    queryKey: ["adPlatform", "kill-switch"],
    queryFn: () => getKillSwitchState(),
    refetchInterval: 10_000, // poll so the dashboard reflects another operator's toggle
  });

  const toggleMut = useMutation({
    mutationFn: (data: { enabled: boolean; reason: string }) => toggleKillSwitch(data),
    onSuccess: (r) => {
      if (r.active) {
        toast.error("Ad serving HALTED");
      } else {
        toast.success("Ad serving RESUMED");
      }
      qc.invalidateQueries({ queryKey: ["adPlatform", "kill-switch"] });
      setReason("");
      setConfirming(false);
    },
    onError: () => toast.error("Kill switch action failed"),
  });

  const ks = ksQ.data;
  const isActive = ks?.active ?? false;

  return (
    <Card className={isActive ? "border-destructive" : ""} data-testid="ks-panel">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <AlertTriangle
            className={`h-5 w-5 ${isActive ? "text-destructive" : "text-muted-foreground"}`}
          />
          Platform-Wide Ad Kill Switch
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="rounded border p-3 text-sm">
          <div className="flex items-center justify-between">
            <span>Status</span>
            <Badge variant={isActive ? "destructive" : "default"} data-testid="ks-status">
              {isActive ? "ACTIVE — All serving halted" : "Inactive — Serving normally"}
            </Badge>
          </div>
          {ks?.toggled_by && (
            <div className="mt-2 flex justify-between text-muted-foreground">
              <span>Last toggled by</span>
              <span>{ks.toggled_by}</span>
            </div>
          )}
          {ks?.reason && (
            <div className="mt-1 flex justify-between gap-4 text-muted-foreground">
              <span>Reason</span>
              <span className="max-w-xs text-right">{ks.reason}</span>
            </div>
          )}
        </div>

        {!confirming ? (
          <Button
            variant={isActive ? "default" : "destructive"}
            onClick={() => setConfirming(true)}
            data-testid="ks-toggle-btn"
          >
            <Power className="mr-2 h-4 w-4" />
            {isActive ? "Resume Ad Serving" : "Halt All Ad Serving"}
          </Button>
        ) : (
          <div className="space-y-2 rounded border border-destructive p-3">
            <p className="text-sm font-medium text-destructive">
              {isActive
                ? "Confirm: resume all ad serving?"
                : "Confirm: HALT ALL AD SERVING platform-wide?"}
            </p>
            {!isActive && (
              <div>
                <label htmlFor="ks-reason" className="text-sm">
                  Reason (required)
                </label>
                <Input
                  id="ks-reason"
                  className="mt-1"
                  placeholder="Describe the reason for halting ad serving…"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  data-testid="ks-reason-input"
                />
              </div>
            )}
            <div className="flex gap-2">
              <Button
                variant={isActive ? "default" : "destructive"}
                disabled={(!isActive && !reason.trim()) || toggleMut.isPending}
                onClick={() => toggleMut.mutate({ enabled: !isActive, reason })}
                data-testid="ks-confirm-btn"
              >
                Confirm
              </Button>
              <Button variant="outline" onClick={() => setConfirming(false)}>
                Cancel
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
