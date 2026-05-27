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
import { Shield, ShieldAlert, ShieldCheck, Ban, Plus, Trash2, RefreshCw, Settings2 } from "lucide-react";
import RateLimitConfigPanel from "./RateLimitConfigPanel";

export default function RateLimitDashboard() {
  const queryClient = useQueryClient();
  const [lookbackHours, setLookbackHours] = useState(1);
  const [showConfigPanel, setShowConfigPanel] = useState(false);

  // Block/Allow dialog state
  const [blockIp, setBlockIp] = useState("");
  const [blockReason, setBlockReason] = useState("");
  const [blockExpiry, setBlockExpiry] = useState("");
  const [allowCidr, setAllowCidr] = useState("");
  const [allowReason, setAllowReason] = useState("");

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

  const events = eventsQ.data;
  const offenders = offendersQ.data;

  // Summary stats
  const rejectedCount = events?.events?.filter((e) => e.status === "rejected").length ?? 0;
  const topIp = offenders?.top_ips?.[0];
  const topUser = offenders?.top_users?.[0];
  const groupCounts: Record<string, number> = {};
  for (const evt of events?.events ?? []) {
    if (evt.status === "rejected") {
      groupCounts[evt.endpoint_group] = (groupCounts[evt.endpoint_group] ?? 0) + 1;
    }
  }
  const mostLimitedGroup = Object.entries(groupCounts).sort((a, b) => b[1] - a[1])[0];

  if (showConfigPanel) {
    return (
      <div className="space-y-6 p-6">
        <div className="flex items-center gap-3">
          <Button variant="outline" size="sm" onClick={() => setShowConfigPanel(false)}>
            Back to Dashboard
          </Button>
          <h1 className="text-2xl font-bold">Rate Limit Configuration</h1>
        </div>
        <RateLimitConfigPanel />
      </div>
    );
  }

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
          <Button variant="outline" size="sm" onClick={() => setShowConfigPanel(true)}>
            <Settings2 className="mr-1 h-4 w-4" />
            Configure
          </Button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              429s (Last {lookbackHours}h)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{rejectedCount}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Top Offending IP</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-lg font-semibold truncate">{topIp?.ip ?? "None"}</div>
            {topIp && <p className="text-xs text-muted-foreground">{topIp.rejected_count} rejections</p>}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Top Offending User</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-lg font-semibold truncate">{topUser?.user_sub ?? "None"}</div>
            {topUser && <p className="text-xs text-muted-foreground">{topUser.rejected_count} rejections</p>}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Most Limited Group</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-lg font-semibold">{mostLimitedGroup?.[0] ?? "None"}</div>
            {mostLimitedGroup && (
              <p className="text-xs text-muted-foreground">{mostLimitedGroup[1]} rejections</p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Endpoint Group Breakdown */}
      {Object.keys(groupCounts).length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>429s by Endpoint Group</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-3">
              {Object.entries(groupCounts)
                .sort((a, b) => b[1] - a[1])
                .map(([group, count]) => (
                  <div key={group} className="flex items-center gap-2 rounded-md border px-3 py-2">
                    <span className="font-medium">{group}</span>
                    <Badge variant="destructive">{count}</Badge>
                  </div>
                ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Top Offenders Table */}
      <div className="grid gap-4 md:grid-cols-2">
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

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5" />
              Top Offending Users
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead>Rejections</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(offenders?.top_users ?? []).slice(0, 10).map((u) => (
                  <TableRow key={u.user_sub}>
                    <TableCell className="truncate text-sm">{u.user_sub}</TableCell>
                    <TableCell>{u.rejected_count}</TableCell>
                  </TableRow>
                ))}
                {(!offenders?.top_users || offenders.top_users.length === 0) && (
                  <TableRow>
                    <TableCell colSpan={2} className="text-center text-muted-foreground">
                      No offending users in this period
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>

      {/* Blocklist */}
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
                Add Block
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

      {/* Allowlist */}
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
                Add Allow
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
                  onClick={() =>
                    addAllowMut.mutate({ cidr: allowCidr, reason: allowReason })
                  }
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

      {/* Recent Events */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Rate Limit Events</CardTitle>
        </CardHeader>
        <CardContent>
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
              {(events?.events ?? []).slice(0, 50).map((evt, idx) => (
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
              {(!events?.events || events.events.length === 0) && (
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
    </div>
  );
}
