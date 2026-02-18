import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldCheck, RefreshCw } from "lucide-react";
import { toast } from "sonner";

import {
  grantAdminRole,
  listRoleAudit,
  revokeAdminRole,
  type RoleAuditItem,
} from "@/api/endpoints/adminRoles";
import { ApiError } from "@/api/client";
import { useAuthStore } from "@/stores/authStore";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { ErrorPage } from "@/components/shared/ErrorPage";

function accessTokenRole(token: string | null): string | null {
  if (!token || token.split(".").length < 2) return null;
  try {
    const payload = JSON.parse(atob(token.split(".")[1]!));
    const role = payload?.role;
    return typeof role === "string" ? role : null;
  } catch {
    return null;
  }
}

function formatTs(ts?: number): string {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleString();
}

function RoleActionForm({
  type,
  onSubmit,
  loading,
}: {
  type: "grant" | "revoke";
  onSubmit: (payload: { target_user_sub: string; reason: string }) => void;
  loading: boolean;
}) {
  const [targetUserSub, setTargetUserSub] = React.useState("");
  const [reason, setReason] = React.useState("");

  const actionLabel = type === "grant" ? "Grant admin" : "Revoke admin";

  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        const target = targetUserSub.trim();
        const why = reason.trim();
        if (!target) {
          toast.error("Target user_sub is required");
          return;
        }
        if (!why) {
          toast.error("Reason is required");
          return;
        }
        onSubmit({ target_user_sub: target, reason: why });
      }}
    >
      <div className="space-y-1.5">
        <Label htmlFor={`${type}-target`}>Target user_sub</Label>
        <Input
          id={`${type}-target`}
          value={targetUserSub}
          onChange={(e) => setTargetUserSub(e.target.value)}
          placeholder="user_123"
        />
      </div>

      <div className="space-y-1.5">
        <Label htmlFor={`${type}-reason`}>Reason</Label>
        <Input
          id={`${type}-reason`}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="Required for audit trail"
        />
      </div>

      <Button type="submit" disabled={loading} variant={type === "grant" ? "default" : "destructive"}>
        {loading ? "Submitting..." : actionLabel}
      </Button>
    </form>
  );
}

export default function RootRoleManagementPage() {
  const qc = useQueryClient();
  const accessToken = useAuthStore((s) => s.accessToken);
  const role = accessTokenRole(accessToken);

  const [actorFilter, setActorFilter] = React.useState("");
  const [startTs, setStartTs] = React.useState("");
  const [endTs, setEndTs] = React.useState("");

  const auditQuery = useQuery({
    queryKey: ["root-role-audit", actorFilter, startTs, endTs],
    queryFn: () =>
      listRoleAudit({
        actor_sub: actorFilter || undefined,
        start_ts: startTs || undefined,
        end_ts: endTs || undefined,
        limit: "100",
      }),
  });

  const grantMut = useMutation({
    mutationFn: ({ target_user_sub, reason }: { target_user_sub: string; reason: string }) =>
      grantAdminRole({ target_user_sub, role: "admin", reason }),
    onSuccess: () => {
      toast.success("Admin role granted");
      qc.invalidateQueries({ queryKey: ["root-role-audit"] });
    },
    onError: (err: unknown) => {
      const msg = err instanceof ApiError ? err.detail : "Grant failed";
      toast.error(msg);
    },
  });

  const revokeMut = useMutation({
    mutationFn: ({ target_user_sub, reason }: { target_user_sub: string; reason: string }) =>
      revokeAdminRole({ target_user_sub, role: "admin", reason }),
    onSuccess: () => {
      toast.success("Admin role revoked");
      qc.invalidateQueries({ queryKey: ["root-role-audit"] });
    },
    onError: (err: unknown) => {
      const msg = err instanceof ApiError ? err.detail : "Revoke failed";
      toast.error(msg);
    },
  });

  if (role && role !== "root") {
    return <ErrorPage status={403} title="Root access required" description="This console is available only to the root account." />;
  }

  return (
    <div className="mx-auto w-full max-w-7xl space-y-6 p-4 md:p-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Root Role Management</h1>
          <p className="text-sm text-muted-foreground">Grant/revoke admin access and review immutable role audit history.</p>
        </div>
        <Badge variant="secondary" className="inline-flex gap-1">
          <ShieldCheck className="h-3.5 w-3.5" /> Root only
        </Badge>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Grant admin role</CardTitle>
            <CardDescription>Assign admin role to an existing user. Reason is required.</CardDescription>
          </CardHeader>
          <CardContent>
            <RoleActionForm type="grant" onSubmit={(payload) => grantMut.mutate(payload)} loading={grantMut.isPending} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Revoke admin role</CardTitle>
            <CardDescription>Remove admin role and return user to standard role. Reason is required.</CardDescription>
          </CardHeader>
          <CardContent>
            <RoleActionForm type="revoke" onSubmit={(payload) => revokeMut.mutate(payload)} loading={revokeMut.isPending} />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="space-y-3">
          <div className="flex items-center justify-between gap-2">
            <div>
              <CardTitle>Role assignment audit timeline</CardTitle>
              <CardDescription>Review grant/revoke events with actor metadata and reasons.</CardDescription>
            </div>
            <Button variant="outline" size="sm" onClick={() => auditQuery.refetch()}>
              <RefreshCw className="mr-1 h-4 w-4" /> Refresh
            </Button>
          </div>

          <div className="grid gap-2 md:grid-cols-3">
            <Input value={actorFilter} onChange={(e) => setActorFilter(e.target.value)} placeholder="Filter by actor_sub" />
            <Input value={startTs} onChange={(e) => setStartTs(e.target.value)} placeholder="start_ts (epoch seconds)" />
            <Input value={endTs} onChange={(e) => setEndTs(e.target.value)} placeholder="end_ts (epoch seconds)" />
          </div>
        </CardHeader>
        <CardContent>
          {auditQuery.isLoading ? (
            <p className="text-sm text-muted-foreground">Loading audit events...</p>
          ) : (auditQuery.data?.items?.length ?? 0) === 0 ? (
            <p className="text-sm text-muted-foreground">No role audit events found for current filters.</p>
          ) : (
            <div className="overflow-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Time</TableHead>
                    <TableHead>Action</TableHead>
                    <TableHead>Actor</TableHead>
                    <TableHead>Target</TableHead>
                    <TableHead>Transition</TableHead>
                    <TableHead>Reason</TableHead>
                    <TableHead>Metadata</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(auditQuery.data?.items ?? []).map((row: RoleAuditItem) => (
                    <TableRow key={row.event_id}>
                      <TableCell className="whitespace-nowrap text-xs">{formatTs(row.ts)}</TableCell>
                      <TableCell>
                        <Badge variant={row.action === "grant" ? "default" : "destructive"}>{row.action}</Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs">{row.actor_sub}</TableCell>
                      <TableCell className="font-mono text-xs">{row.target_user_sub}</TableCell>
                      <TableCell className="text-xs">{row.previous_role} → {row.new_role}</TableCell>
                      <TableCell className="max-w-[280px] whitespace-normal break-words text-xs">{row.reason || "-"}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        <div>ip: {row.ip || "-"}</div>
                        <div className="font-mono">req: {row.request_id || "-"}</div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
