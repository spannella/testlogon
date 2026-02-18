import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldCheck, RefreshCw } from "lucide-react";
import { toast } from "sonner";

import {
  grantAdminRole,
  listRoleAudit,
  revokeAdminRole,
  updateAdminProfile,
  type AdminProfileType,
  type AdminScope,
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
import { getRoleFromAccessToken } from "@/lib/adminCapabilities";

const ADMIN_SCOPE_OPTIONS: Array<{ value: AdminScope; label: string; guidance: string }> = [
  { value: "auth_support", label: "Auth support", guidance: "Login, session, and account recovery support" },
  { value: "billing_support", label: "Billing support", guidance: "Payments, charges, and billing account support" },
  { value: "content_moderation", label: "Content moderation", guidance: "Content review and moderation controls" },
];

export function validateAdminProfileInput(profileType: AdminProfileType, scopes: AdminScope[]): string | null {
  if (profileType === "general") {
    if (scopes.length > 0) {
      return "General admins cannot have scoped permissions selected.";
    }
    return null;
  }
  if (scopes.length === 0) {
    return "Scoped admins must include at least one scope.";
  }
  return null;
}

function formatTs(ts?: number): string {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleString();
}

function formatProfile(profile?: { type: string; scopes?: string[] } | null): string {
  if (!profile) return "-";
  if (profile.type === "general") return "general";
  const scopes = (profile.scopes ?? []).join(", ");
  return scopes ? `scoped (${scopes})` : "scoped";
}

function GrantAdminForm({
  onSubmit,
  loading,
}: {
  onSubmit: (payload: {
    target_user_sub: string;
    reason: string;
    admin_profile_type: AdminProfileType;
    admin_scopes?: AdminScope[];
  }) => void;
  loading: boolean;
}) {
  const [targetUserSub, setTargetUserSub] = React.useState("");
  const [reason, setReason] = React.useState("");
  const [profileType, setProfileType] = React.useState<AdminProfileType>("general");
  const [selectedScopes, setSelectedScopes] = React.useState<AdminScope[]>([]);

  const validationError = validateAdminProfileInput(profileType, selectedScopes);

  const toggleScope = (scope: AdminScope) => {
    setSelectedScopes((prev) => (prev.includes(scope) ? prev.filter((s) => s !== scope) : [...prev, scope]));
  };

  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        const target = targetUserSub.trim();
        const why = reason.trim();
        if (!target) return toast.error("Target user_sub is required");
        if (!why) return toast.error("Reason is required");
        if (validationError) return toast.error(validationError);

        onSubmit({
          target_user_sub: target,
          reason: why,
          admin_profile_type: profileType,
          admin_scopes: profileType === "scoped" ? selectedScopes : undefined,
        });
      }}
    >
      <div className="space-y-1.5">
        <Label htmlFor="grant-target">Target user_sub</Label>
        <Input id="grant-target" value={targetUserSub} onChange={(e) => setTargetUserSub(e.target.value)} placeholder="user_123" />
      </div>

      <div className="space-y-1.5">
        <Label htmlFor="grant-reason">Reason</Label>
        <Input id="grant-reason" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Required for audit trail" />
      </div>

      <div className="space-y-1.5">
        <Label htmlFor="grant-profile-type">Admin profile mode</Label>
        <select
          id="grant-profile-type"
          className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
          value={profileType}
          onChange={(e) => {
            const nextType = e.target.value as AdminProfileType;
            setProfileType(nextType);
            if (nextType === "general") setSelectedScopes([]);
          }}
        >
          <option value="general">General admin (all admin domains)</option>
          <option value="scoped">Scoped admin (selected domains only)</option>
        </select>
      </div>

      <div className="space-y-2 rounded-md border p-3">
        <Label>Scoped permissions</Label>
        <p className="text-xs text-muted-foreground">
          Select at least one scope for scoped admins. Leave all unchecked for general admins.
        </p>
        <div className="space-y-2">
          {ADMIN_SCOPE_OPTIONS.map((scope) => (
            <label key={scope.value} className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                checked={selectedScopes.includes(scope.value)}
                onChange={() => toggleScope(scope.value)}
                disabled={profileType === "general"}
              />
              <span>
                <span className="font-medium">{scope.label}</span>
                <span className="block text-xs text-muted-foreground">{scope.guidance}</span>
              </span>
            </label>
          ))}
        </div>
        {validationError ? <p className="text-xs text-destructive">{validationError}</p> : null}
      </div>

      <Button type="submit" disabled={loading}>
        {loading ? "Submitting..." : "Grant admin"}
      </Button>
    </form>
  );
}

function RevokeAdminForm({
  onSubmit,
  loading,
}: {
  onSubmit: (payload: { target_user_sub: string; reason: string }) => void;
  loading: boolean;
}) {
  const [targetUserSub, setTargetUserSub] = React.useState("");
  const [reason, setReason] = React.useState("");

  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        const target = targetUserSub.trim();
        const why = reason.trim();
        if (!target) return toast.error("Target user_sub is required");
        if (!why) return toast.error("Reason is required");
        onSubmit({ target_user_sub: target, reason: why });
      }}
    >
      <div className="space-y-1.5">
        <Label htmlFor="revoke-target">Target user_sub</Label>
        <Input id="revoke-target" value={targetUserSub} onChange={(e) => setTargetUserSub(e.target.value)} placeholder="user_123" />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="revoke-reason">Reason</Label>
        <Input id="revoke-reason" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Required for audit trail" />
      </div>
      <Button type="submit" disabled={loading} variant="destructive">
        {loading ? "Submitting..." : "Revoke admin"}
      </Button>
    </form>
  );
}

function UpdateProfileForm({
  onSubmit,
  loading,
}: {
  onSubmit: (payload: {
    target_user_sub: string;
    reason: string;
    admin_profile_type: AdminProfileType;
    admin_scopes?: AdminScope[];
  }) => void;
  loading: boolean;
}) {
  const [targetUserSub, setTargetUserSub] = React.useState("");
  const [reason, setReason] = React.useState("");
  const [profileType, setProfileType] = React.useState<AdminProfileType>("general");
  const [selectedScopes, setSelectedScopes] = React.useState<AdminScope[]>([]);
  const validationError = validateAdminProfileInput(profileType, selectedScopes);

  const toggleScope = (scope: AdminScope) => {
    setSelectedScopes((prev) => (prev.includes(scope) ? prev.filter((s) => s !== scope) : [...prev, scope]));
  };

  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        const target = targetUserSub.trim();
        const why = reason.trim();
        if (!target) return toast.error("Target user_sub is required");
        if (!why) return toast.error("Reason is required");
        if (validationError) return toast.error(validationError);
        onSubmit({
          target_user_sub: target,
          reason: why,
          admin_profile_type: profileType,
          admin_scopes: profileType === "scoped" ? selectedScopes : undefined,
        });
      }}
    >
      <div className="space-y-1.5">
        <Label htmlFor="profile-target">Target admin user_sub</Label>
        <Input id="profile-target" value={targetUserSub} onChange={(e) => setTargetUserSub(e.target.value)} placeholder="admin_123" />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="profile-reason">Reason</Label>
        <Input id="profile-reason" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why this profile change is needed" />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="update-profile-type">Admin profile mode</Label>
        <select
          id="update-profile-type"
          className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
          value={profileType}
          onChange={(e) => {
            const nextType = e.target.value as AdminProfileType;
            setProfileType(nextType);
            if (nextType === "general") setSelectedScopes([]);
          }}
        >
          <option value="general">General admin (all admin domains)</option>
          <option value="scoped">Scoped admin (selected domains only)</option>
        </select>
      </div>

      <div className="space-y-2 rounded-md border p-3">
        <Label>Scoped permissions</Label>
        <div className="space-y-2">
          {ADMIN_SCOPE_OPTIONS.map((scope) => (
            <label key={scope.value} className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                checked={selectedScopes.includes(scope.value)}
                onChange={() => toggleScope(scope.value)}
                disabled={profileType === "general"}
              />
              <span>{scope.label}</span>
            </label>
          ))}
        </div>
        {validationError ? <p className="text-xs text-destructive">{validationError}</p> : null}
      </div>

      <Button type="submit" disabled={loading} variant="secondary">
        {loading ? "Submitting..." : "Update admin profile"}
      </Button>
    </form>
  );
}

export default function RootRoleManagementPage() {
  const qc = useQueryClient();
  const accessToken = useAuthStore((s) => s.accessToken);
  const role = getRoleFromAccessToken(accessToken);

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
    mutationFn: (payload: {
      target_user_sub: string;
      reason: string;
      admin_profile_type: AdminProfileType;
      admin_scopes?: AdminScope[];
    }) => grantAdminRole({ ...payload, role: "admin" }),
    onSuccess: () => {
      toast.success("Admin role granted");
      qc.invalidateQueries({ queryKey: ["root-role-audit"] });
    },
    onError: (err: unknown) => {
      const msg = err instanceof ApiError ? err.detail : "Grant failed";
      toast.error(msg);
    },
  });

  const updateProfileMut = useMutation({
    mutationFn: (payload: {
      target_user_sub: string;
      reason: string;
      admin_profile_type: AdminProfileType;
      admin_scopes?: AdminScope[];
    }) => updateAdminProfile(payload),
    onSuccess: () => {
      toast.success("Admin profile updated");
      qc.invalidateQueries({ queryKey: ["root-role-audit"] });
    },
    onError: (err: unknown) => {
      const msg = err instanceof ApiError ? err.detail : "Profile update failed";
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
          <p className="text-sm text-muted-foreground">
            Assign general or scoped admins, update admin capability profiles, and review immutable role/profile audit history.
          </p>
        </div>
        <Badge variant="secondary" className="inline-flex gap-1">
          <ShieldCheck className="h-3.5 w-3.5" /> Root only
        </Badge>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>Grant admin role</CardTitle>
            <CardDescription>
              Choose one category: General, Auth support, Billing support, or Content moderation. Reason is required.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <GrantAdminForm onSubmit={(payload) => grantMut.mutate(payload)} loading={grantMut.isPending} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Update admin profile</CardTitle>
            <CardDescription>
              Convert existing admins between general/scoped profiles or update scoped permissions.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <UpdateProfileForm onSubmit={(payload) => updateProfileMut.mutate(payload)} loading={updateProfileMut.isPending} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Revoke admin role</CardTitle>
            <CardDescription>Remove admin role and return user to standard role. Reason is required.</CardDescription>
          </CardHeader>
          <CardContent>
            <RevokeAdminForm onSubmit={(payload) => revokeMut.mutate(payload)} loading={revokeMut.isPending} />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="space-y-3">
          <div className="flex items-center justify-between gap-2">
            <div>
              <CardTitle>Role assignment audit timeline</CardTitle>
              <CardDescription>Review grant/revoke/profile-update events with profile transitions and actor metadata.</CardDescription>
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
                    <TableHead>Role transition</TableHead>
                    <TableHead>Profile transition</TableHead>
                    <TableHead>Reason</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(auditQuery.data?.items ?? []).map((row: RoleAuditItem) => (
                    <TableRow key={row.event_id}>
                      <TableCell className="whitespace-nowrap text-xs">{formatTs(row.ts)}</TableCell>
                      <TableCell>
                        <Badge variant={row.action === "revoke" ? "destructive" : "default"}>{row.action}</Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs">{row.actor_sub}</TableCell>
                      <TableCell className="font-mono text-xs">{row.target_user_sub}</TableCell>
                      <TableCell className="text-xs">{row.previous_role} → {row.new_role}</TableCell>
                      <TableCell className="max-w-[260px] whitespace-normal break-words text-xs">
                        {formatProfile(row.previous_admin_profile)} → {formatProfile(row.new_admin_profile)}
                      </TableCell>
                      <TableCell className="max-w-[240px] whitespace-normal break-words text-xs">{row.reason || "-"}</TableCell>
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
