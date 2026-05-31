import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getRateLimitEvents,
  getTopOffenders,
  getBlocklist,
  getAllowlist,
  addToBlocklist,
  removeFromBlocklist,
  addToAllowlist,
  removeFromAllowlist,
  getRateLimitLiveSummary,
  exportRateLimitEvents,
} from "@/api/endpoints/adminRateLimits";
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
  DialogTrigger,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Ban,
  Plus,
  Trash2,
  RefreshCw,
  Download,
  Activity,
} from "lucide-react";
import { toast } from "sonner";
import RateLimitConfigPanel from "./RateLimitConfigPanel";

const LIVE_REFRESH_INTERVAL = 15_000;

export default function RateLimitDashboard() {
  const queryClient = useQueryClient();
  const [lookbackHours, setLookbackHours] = useState(1);

  // Block/Allow dialog state
  const [blockIp, setBlockIp] = useState("");
  const [blockReason, setBlockReason] = useState("");
  const [blockExpiry, setBlockExpiry] = useState("");
  const [allowCidr, setAllowCidr] = useState("");
  const [allowReason, setAllowReason] = useState("");

  // Event log search state
  const [eventStatusFilter, setEventStatusFilter] = useState("");
  const [eventSearch, setEventSearch] = useState("");

  // Queries
  const eventsQ = useQuery({
    queryKey: ["admin", "rate-limits", "events", lookbackHours],
    queryFn: () => getRateLimitEvents(lookbackHours, 100),
    refetchInterval: 30_000,
  });

  const offendersQ = useQuery({
    queryKey: ["admin", "rate-limits", "top-offenders", lookbackHours],
    queryFn: () => getTopOffenders(lookbackHours, 20),
    refetchInterval: 30_000,
  });

  const blocklistQ = useQuery({
    queryKey: ["admin", "rate-limits", "blocklist"],
    queryFn: getBlocklist,
  });

  const allowlistQ = useQuery({
    queryKey: ["admin", "rate-limits", "allowlist"],
    queryFn: getAllowlist,
  });

  const liveQ = useQuery({
    queryKey: ["admin", "rate-limits", "live-summary", lookbackHours],
    queryFn: () => getRateLimitLiveSummary(lookbackHours),
    refetchInterval: LIVE_REFRESH_INTERVAL,
    staleTime: 0,
  });

  // Mutations
  const addBlockMut = useMutation({
    mutationFn: addToBlocklist,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin", "rate-limits", "blocklist"] });
      setBlockIp("");
      setBlockReason("");
      setBlockExpiry("");
    },
  });

  const removeBlockMut = useMutation({
    mutationFn: removeFromBlocklist,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["admin", "rate-limits", "blocklist"] }),
  });

  const addAllowMut = useMutation({
    mutationFn: addToAllowlist,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin", "rate-limits", "allowlist"] });
      setAllowCidr("");
      setAllowReason("");
    },
  });

  const removeAllowMut = useMutation({
    mutationFn: removeFromAllowlist,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["admin", "rate-limits", "allowlist"] }),
  });

  const exportMut = useMutation({
    mutationFn: () => exportRateLimitEvents(lookbackHours, eventStatusFilter || undefined),
    onError: () => toast.error("Failed to export events"),
  });

  const events = eventsQ.data;
  const offenders = offendersQ.data;
  const live = liveQ.data;

  // Filtered events for the event log table
  const filteredEvents = (events?.events ?? []).filter((evt) => {
    if (eventStatusFilter && evt.status !== eventStatusFilter) return false;
    if (eventSearch) {
      const q = eventSearch.toLowerCase();
      const hay = `${evt.endpoint_group} ${evt.identity_value} ${evt.endpoint}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  // Live summary derived values
  const liveByGroup = live?.by_group ?? {};
  const topGroupEntry = Object.entries(liveByGroup).sort((a, b) => b[1] - a[1])[0];
  const topSource = live?.by_source?.[0];
  const maxBucket = Math.max(1, ...(live?.time_series ?? []).map((p) => p.count));
  const maxGroup = Math.max(1, ...Object.values(liveByGroup));

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="h-8 w-8 text-primary" />
          <div>
            <h1 className="text-2xl font-bold">Rate Limit Dashboard</h1>
            <p className="text-sm text-muted-foreground">Monitor and manage API rate limiting</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <select
            className="rounded border px-2 py-1 text-sm"
            value={lookbackHours}
            onChange={(e) => setLookbackHours(Number(e.target.value))}
          >
            <option value={1}>Last 1 hour</option>
            <option value={6}>Last 6 hours</option>
            <option value={24}>Last 24 hours</option>
          </select>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              queryClient.invalidateQueries({ queryKey: ["admin", "rate-limits"] });
            }}
          >
            <RefreshCw className="mr-1 h-4 w-4" />
            Refresh
          </Button>
        </div>
      </div>

      <Tabs defaultValue="rules">
        <TabsList>
          <TabsTrigger value="rules">Rules</TabsTrigger>
          <TabsTrigger value="blocklist">Blocklist</TabsTrigger>
          <TabsTrigger value="allowlist">Allowlist</TabsTrigger>
          <TabsTrigger value="live">Live Dashboard</TabsTrigger>
          <TabsTrigger value="events">Event Log</TabsTrigger>
        </TabsList>

        {/* ── Rules ───────────────────────────────────────────────── */}
        <TabsContent value="rules" className="mt-4">
          <RateLimitConfigPanel />
        </TabsContent>

        {/* ── Blocklist ───────────────────────────────────────────── */}
        <TabsContent value="blocklist" className="mt-4 space-y-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                <Ban className="h-5 w-5" />
                IP Blocklist
              </CardTitle>
              <Dialog>
                <DialogTrigger asChild>
                  <Button size="sm">
                    <Plus className="mr-1 h-4 w-4" />
                    Block IP
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Block IP Address</DialogTitle>
                  </DialogHeader>
                  <div className="space-y-3">
                    <Input
                      placeholder="IP address"
                      value={blockIp}
                      onChange={(e) => setBlockIp(e.target.value)}
                    />
                    <Input
                      placeholder="Reason"
                      value={blockReason}
                      onChange={(e) => setBlockReason(e.target.value)}
                    />
                    <Input
                      placeholder="Expires in hours (optional)"
                      type="number"
                      value={blockExpiry}
                      onChange={(e) => setBlockExpiry(e.target.value)}
                    />
                    <Button
                      onClick={() =>
                        addBlockMut.mutate({
                          ip: blockIp,
                          reason: blockReason,
                          expires_in_hours: blockExpiry ? Number(blockExpiry) : undefined,
                        })
                      }
                      disabled={!blockIp}
                    >
                      Block IP
                    </Button>
                  </div>
                </DialogContent>
              </Dialog>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>IP</TableHead>
                    <TableHead>Reason</TableHead>
                    <TableHead>Added By</TableHead>
                    <TableHead>Expires</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(blocklistQ.data?.entries ?? []).map((entry) => (
                    <TableRow key={entry.sk}>
                      <TableCell className="font-mono">{entry.sk}</TableCell>
                      <TableCell>{entry.reason}</TableCell>
                      <TableCell>{entry.added_by}</TableCell>
                      <TableCell>
                        {entry.ttl_epoch
                          ? new Date(entry.ttl_epoch * 1000).toLocaleString()
                          : "Never"}
                      </TableCell>
                      <TableCell>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => removeBlockMut.mutate(entry.sk)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                  {(!blocklistQ.data?.entries || blocklistQ.data.entries.length === 0) && (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center text-muted-foreground">
                        No blocked IPs
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          {/* Top offenders (quick-block source) */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <ShieldAlert className="h-5 w-5" />
                Top Offending IPs
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>IP</TableHead>
                    <TableHead>Rejections</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(offenders?.top_ips ?? []).slice(0, 10).map((ip) => (
                    <TableRow key={ip.ip}>
                      <TableCell className="font-mono text-sm">{ip.ip}</TableCell>
                      <TableCell>{ip.rejected_count}</TableCell>
                      <TableCell>
                        <Button
                          variant="destructive"
                          size="sm"
                          onClick={() =>
                            addBlockMut.mutate({ ip: ip.ip, reason: "Blocked from dashboard" })
                          }
                        >
                          <Ban className="mr-1 h-3 w-3" />
                          Block
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                  {(!offenders?.top_ips || offenders.top_ips.length === 0) && (
                    <TableRow>
                      <TableCell colSpan={3} className="text-center text-muted-foreground">
                        No offending IPs in this period
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Allowlist ───────────────────────────────────────────── */}
        <TabsContent value="allowlist" className="mt-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                <ShieldCheck className="h-5 w-5" />
                IP Allowlist
              </CardTitle>
              <Dialog>
                <DialogTrigger asChild>
                  <Button size="sm">
                    <Plus className="mr-1 h-4 w-4" />
                    Add Exemption
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Allow IP/CIDR</DialogTitle>
                  </DialogHeader>
                  <div className="space-y-3">
                    <Input
                      placeholder="IP or CIDR (e.g. 10.0.0.0/8)"
                      value={allowCidr}
                      onChange={(e) => setAllowCidr(e.target.value)}
                    />
                    <Input
                      placeholder="Reason"
                      value={allowReason}
                      onChange={(e) => setAllowReason(e.target.value)}
                    />
                    <Button
                      onClick={() => addAllowMut.mutate({ cidr: allowCidr, reason: allowReason })}
                      disabled={!allowCidr}
                    >
                      Add to Allowlist
                    </Button>
                  </div>
                </DialogContent>
              </Dialog>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>CIDR</TableHead>
                    <TableHead>Reason</TableHead>
                    <TableHead>Added By</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(allowlistQ.data?.entries ?? []).map((entry) => (
                    <TableRow key={entry.sk}>
                      <TableCell className="font-mono">{entry.sk}</TableCell>
                      <TableCell>{entry.reason}</TableCell>
                      <TableCell>{entry.added_by}</TableCell>
                      <TableCell>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => removeAllowMut.mutate(entry.sk)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                  {(!allowlistQ.data?.entries || allowlistQ.data.entries.length === 0) && (
                    <TableRow>
                      <TableCell colSpan={4} className="text-center text-muted-foreground">
                        No allowlisted IPs
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Live Dashboard ──────────────────────────────────────── */}
        <TabsContent value="live" className="mt-4 space-y-4">
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">
                  Total Hits ({lookbackHours}h)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{live?.total_hits ?? 0}</div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">Top Group</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-lg font-semibold truncate">{topGroupEntry?.[0] ?? "None"}</div>
                {topGroupEntry && (
                  <p className="text-xs text-muted-foreground">{topGroupEntry[1]} hits</p>
                )}
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">Top Source</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-lg font-semibold truncate font-mono">
                  {topSource?.source_ip ?? "None"}
                </div>
                {topSource && <p className="text-xs text-muted-foreground">{topSource.count} hits</p>}
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">Auto-refresh</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center gap-2 text-lg font-semibold">
                  <Activity className="h-5 w-5 text-green-500" />
                  {LIVE_REFRESH_INTERVAL / 1000}s
                </div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Hits Over Time (5-min buckets)</CardTitle>
            </CardHeader>
            <CardContent>
              {(live?.time_series ?? []).length === 0 ? (
                <p className="text-sm text-muted-foreground">No hits in this period</p>
              ) : (
                <div className="flex h-40 items-end gap-1">
                  {(live?.time_series ?? []).map((point) => (
                    <div
                      key={point.bucket}
                      className="flex flex-1 flex-col items-center justify-end"
                      title={`${point.bucket}: ${point.count}`}
                    >
                      <div
                        className="w-full rounded-t bg-primary"
                        style={{ height: `${(point.count / maxBucket) * 100}%` }}
                      />
                      <span className="mt-1 truncate text-[9px] text-muted-foreground">
                        {point.bucket.slice(-5)}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Hits by Group</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {Object.entries(liveByGroup)
                    .sort((a, b) => b[1] - a[1])
                    .map(([group, count]) => (
                      <div key={group} className="flex items-center gap-2">
                        <span className="w-28 truncate text-sm">{group}</span>
                        <div className="h-3 flex-1 rounded bg-muted">
                          <div
                            className="h-3 rounded bg-primary"
                            style={{ width: `${(count / maxGroup) * 100}%` }}
                          />
                        </div>
                        <span className="w-10 text-right text-sm tabular-nums">{count}</span>
                      </div>
                    ))}
                  {Object.keys(liveByGroup).length === 0 && (
                    <p className="text-sm text-muted-foreground">No hits in this period</p>
                  )}
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Top Sources</CardTitle>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Source</TableHead>
                      <TableHead>Hits</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(live?.by_source ?? []).slice(0, 10).map((s) => (
                      <TableRow key={s.source_ip}>
                        <TableCell className="font-mono text-sm">{s.source_ip}</TableCell>
                        <TableCell>{s.count}</TableCell>
                      </TableRow>
                    ))}
                    {(!live?.by_source || live.by_source.length === 0) && (
                      <TableRow>
                        <TableCell colSpan={2} className="text-center text-muted-foreground">
                          No sources in this period
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* ── Event Log ───────────────────────────────────────────── */}
        <TabsContent value="events" className="mt-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle>Rate Limit Event Log</CardTitle>
              <Button
                size="sm"
                variant="outline"
                onClick={() => exportMut.mutate()}
                disabled={exportMut.isPending}
              >
                <Download className="mr-1 h-4 w-4" />
                Export CSV
              </Button>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex flex-wrap items-center gap-2">
                <Input
                  className="max-w-xs"
                  placeholder="Search group / source / endpoint"
                  value={eventSearch}
                  onChange={(e) => setEventSearch(e.target.value)}
                />
                <select
                  className="rounded border px-2 py-1 text-sm"
                  value={eventStatusFilter}
                  onChange={(e) => setEventStatusFilter(e.target.value)}
                >
                  <option value="">All statuses</option>
                  <option value="rejected">Rejected</option>
                  <option value="allowed">Allowed</option>
                </select>
              </div>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Group</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Identity</TableHead>
                    <TableHead>Endpoint</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Count/Limit</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredEvents.slice(0, 100).map((evt, idx) => (
                    <TableRow key={idx}>
                      <TableCell>
                        <Badge variant="outline">{evt.endpoint_group}</Badge>
                      </TableCell>
                      <TableCell>{evt.identity_type}</TableCell>
                      <TableCell className="max-w-[200px] truncate font-mono text-xs">
                        {evt.identity_value}
                      </TableCell>
                      <TableCell className="max-w-[200px] truncate text-xs">
                        {evt.method} {evt.endpoint}
                      </TableCell>
                      <TableCell>
                        <Badge variant={evt.status === "rejected" ? "destructive" : "secondary"}>
                          {evt.status}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {evt.count}/{evt.limit}
                      </TableCell>
                    </TableRow>
                  ))}
                  {filteredEvents.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center text-muted-foreground">
                        No rate limit events in this period
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
