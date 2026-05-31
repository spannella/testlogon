import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Server } from "lucide-react";
import { toast } from "sonner";
import {
  listAdminInstances,
  listAdminPods,
  getPlatformSpending,
  getPerUserSpending,
  getInstanceTypeStats,
  forceTerminateInstance,
  forceTerminatePod,
} from "@/api/endpoints/adminCompute";
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
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import QuotaEditorDialog from "./QuotaEditorDialog";

const fmtUsd = (cents: number) => `$${(cents / 100).toFixed(2)}`;

export default function AdminComputeDashboard() {
  const qc = useQueryClient();
  const [statusFilter, setStatusFilter] = useState("");
  const [userFilter, setUserFilter] = useState("");
  const [quotaUser, setQuotaUser] = useState<string | null>(null);
  const [quotaOpen, setQuotaOpen] = useState(false);

  const spending = useQuery({
    queryKey: ["admin-compute", "spending"],
    queryFn: () => getPlatformSpending(),
  });

  const perUser = useQuery({
    queryKey: ["admin-compute", "per-user-spending"],
    queryFn: () => getPerUserSpending(),
  });

  const typeStats = useQuery({
    queryKey: ["admin-compute", "type-stats"],
    queryFn: () => getInstanceTypeStats(),
  });

  const instances = useQuery({
    queryKey: ["admin-compute", "instances", statusFilter, userFilter],
    queryFn: () =>
      listAdminInstances({
        status: statusFilter || undefined,
        user_sub: userFilter || undefined,
      }),
  });

  const pods = useQuery({
    queryKey: ["admin-compute", "pods", statusFilter, userFilter],
    queryFn: () =>
      listAdminPods({
        status: statusFilter || undefined,
        user_sub: userFilter || undefined,
      }),
  });

  const termInstance = useMutation({
    mutationFn: ({ userSub, id }: { userSub: string; id: string }) =>
      forceTerminateInstance(userSub, id, { reason: "Admin termination" }),
    onSuccess: () => {
      toast.success("Instance terminated");
      qc.invalidateQueries({ queryKey: ["admin-compute"] });
    },
    onError: (e: unknown) => toast.error((e as Error).message || "Failed to terminate"),
  });

  const termPod = useMutation({
    mutationFn: ({ userSub, id }: { userSub: string; id: string }) =>
      forceTerminatePod(userSub, id, { reason: "Admin termination" }),
    onSuccess: () => {
      toast.success("Pod terminated");
      qc.invalidateQueries({ queryKey: ["admin-compute"] });
    },
    onError: (e: unknown) => toast.error((e as Error).message || "Failed to terminate"),
  });

  const s = spending.data;
  const maxRunning = Math.max(1, ...(typeStats.data?.stats.map((t) => t.running_count) ?? [1]));

  return (
    <div className="space-y-6 p-4">
      <div className="flex items-center gap-2">
        <Server className="h-6 w-6" />
        <h1 className="text-2xl font-semibold">Compute Dashboard</h1>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Total Spending
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{fmtUsd(s?.total_cents ?? 0)}</div>
            <div className="text-xs text-muted-foreground">{s?.month ?? "—"}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Active Instances
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{s?.active_instance_count ?? 0}</div>
            <div className="text-xs text-muted-foreground">
              EC2 {fmtUsd(s?.ec2_total_cents ?? 0)} · K8s {fmtUsd(s?.k8s_total_cents ?? 0)}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Active Pods
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{s?.active_pod_count ?? 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Active Users
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{s?.active_user_count ?? 0}</div>
          </CardContent>
        </Card>
      </div>

      {/* Per-user spending */}
      <Card>
        <CardHeader>
          <CardTitle>Per-User Spending</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>User</TableHead>
                <TableHead>EC2</TableHead>
                <TableHead>K8s</TableHead>
                <TableHead>Total</TableHead>
                <TableHead>Instances</TableHead>
                <TableHead>Pods</TableHead>
                <TableHead></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(perUser.data?.users ?? []).map((u) => (
                <TableRow key={u.user_sub}>
                  <TableCell className="max-w-[180px] truncate font-mono text-xs">
                    {u.user_sub}
                  </TableCell>
                  <TableCell>{fmtUsd(u.ec2_cents)}</TableCell>
                  <TableCell>{fmtUsd(u.k8s_cents)}</TableCell>
                  <TableCell className="font-semibold">{fmtUsd(u.total_cents)}</TableCell>
                  <TableCell>{u.instance_count}</TableCell>
                  <TableCell>{u.pod_count}</TableCell>
                  <TableCell>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => {
                        setQuotaUser(u.user_sub);
                        setQuotaOpen(true);
                      }}
                    >
                      Quota
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
              {(perUser.data?.users.length ?? 0) === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground">
                    No spending recorded this month
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Instance type popularity */}
      <Card>
        <CardHeader>
          <CardTitle>Instance Type Popularity</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {(typeStats.data?.stats ?? []).map((t) => (
            <div key={t.instance_type} className="flex items-center gap-2">
              <div className="w-28 font-mono text-xs">{t.instance_type}</div>
              <div className="h-4 flex-1 rounded bg-muted">
                <div
                  className="h-4 rounded bg-primary"
                  style={{ width: `${(t.running_count / maxRunning) * 100}%` }}
                />
              </div>
              <div className="w-24 text-right text-xs text-muted-foreground">
                {t.running_count} running / {t.total_launched} total
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* All resources */}
      <Card>
        <CardHeader>
          <CardTitle>All Resources</CardTitle>
          <div className="flex gap-2 pt-2">
            <Input
              placeholder="Filter by status"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="max-w-[180px]"
            />
            <Input
              placeholder="Filter by user_sub"
              value={userFilter}
              onChange={(e) => setUserFilter(e.target.value)}
              className="max-w-[260px]"
            />
          </div>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="ec2">
            <TabsList>
              <TabsTrigger value="ec2">EC2 Instances</TabsTrigger>
              <TabsTrigger value="k8s">K8s Pods</TabsTrigger>
            </TabsList>

            <TabsContent value="ec2">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>User</TableHead>
                    <TableHead>Label</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>IP</TableHead>
                    <TableHead></TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(instances.data?.instances ?? []).map((i) => (
                    <TableRow key={i.instance_id}>
                      <TableCell className="max-w-[160px] truncate font-mono text-xs">
                        {i.user_sub}
                      </TableCell>
                      <TableCell>{i.label}</TableCell>
                      <TableCell>{i.instance_type}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{i.status}</Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs">{i.public_ip}</TableCell>
                      <TableCell>
                        <Button
                          size="sm"
                          variant="destructive"
                          disabled={i.status === "terminated"}
                          onClick={() =>
                            termInstance.mutate({ userSub: i.user_sub, id: i.instance_id })
                          }
                        >
                          Terminate
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                  {(instances.data?.instances.length ?? 0) === 0 && (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center text-muted-foreground">
                        No instances
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </TabsContent>

            <TabsContent value="k8s">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>User</TableHead>
                    <TableHead>Label</TableHead>
                    <TableHead>Image</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>IP</TableHead>
                    <TableHead></TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(pods.data?.pods ?? []).map((p) => (
                    <TableRow key={p.pod_id}>
                      <TableCell className="max-w-[160px] truncate font-mono text-xs">
                        {p.user_sub}
                      </TableCell>
                      <TableCell>{p.label}</TableCell>
                      <TableCell>{p.image}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{p.status}</Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs">{p.pod_ip}</TableCell>
                      <TableCell>
                        <Button
                          size="sm"
                          variant="destructive"
                          disabled={p.status === "terminated"}
                          onClick={() => termPod.mutate({ userSub: p.user_sub, id: p.pod_id })}
                        >
                          Terminate
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                  {(pods.data?.pods.length ?? 0) === 0 && (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center text-muted-foreground">
                        No pods
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      <QuotaEditorDialog
        userSub={quotaUser}
        open={quotaOpen}
        onOpenChange={setQuotaOpen}
      />
    </div>
  );
}
