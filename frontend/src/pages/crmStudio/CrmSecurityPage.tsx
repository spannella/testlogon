import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Shield, Plus, Trash2, Users, FileLock2, KeyRound } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ApiError } from "@/api/client";
import { NotEnabledState, isNotEnabled } from "./NotEnabledState";
import {
  ACL_ACTIONS,
  ACL_MODULES,
  STUDIO_ENTITY_TYPES,
  addSecurityGroupMember,
  assignRoleToGroup,
  assignRoleToUser,
  assignSecurityGroupRecord,
  createAclRole,
  createSecurityGroup,
  deleteAclRole,
  deleteSecurityGroup,
  getAclRole,
  getSecurityGroup,
  listAclRoles,
  listRoleAssignments,
  listSecurityGroups,
  removeSecurityGroupMember,
  revokeRoleFromGroup,
  revokeRoleFromUser,
  unassignSecurityGroupRecord,
  updateAclRole,
  type CrmAclPermissionMatrix,
} from "@/api/endpoints/crmStudio";

function fmt(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

const emptyMatrix = (): CrmAclPermissionMatrix => ({});

// ════════════════════════════════════════════════════════════════════════════
// Permission matrix editor
// ════════════════════════════════════════════════════════════════════════════

function MatrixEditor({
  value,
  onChange,
}: {
  value: Record<string, CrmAclPermissionMatrix>;
  onChange: (next: Record<string, CrmAclPermissionMatrix>) => void;
}) {
  const toggle = (module: string, action: keyof CrmAclPermissionMatrix) => {
    const current = value[module] ?? emptyMatrix();
    const next = { ...value, [module]: { ...current, [action]: !current[action] } };
    onChange(next);
  };
  return (
    <div className="overflow-x-auto rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="min-w-[120px]">Module</TableHead>
            {ACL_ACTIONS.map((a) => (
              <TableHead key={a.key} className="text-center">
                {a.label}
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {ACL_MODULES.map((mod) => {
            const m = value[mod] ?? emptyMatrix();
            return (
              <TableRow key={mod}>
                <TableCell className="font-medium capitalize">{mod}</TableCell>
                {ACL_ACTIONS.map((a) => (
                  <TableCell key={a.key} className="text-center">
                    <Checkbox
                      checked={!!m[a.key]}
                      onCheckedChange={() => toggle(mod, a.key)}
                      aria-label={`${mod} ${a.label}`}
                    />
                  </TableCell>
                ))}
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// ACL Roles tab
// ════════════════════════════════════════════════════════════════════════════

function AclRolesTab() {
  const qc = useQueryClient();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [matrix, setMatrix] = useState<Record<string, CrmAclPermissionMatrix>>({});

  const [assignUserSub, setAssignUserSub] = useState("");
  const [assignGroupKey, setAssignGroupKey] = useState("");

  const rolesQuery = useQuery({
    queryKey: ["crm-acl", "roles"],
    queryFn: () => listAclRoles({ limit: 200 }),
    retry: false,
  });

  const detailQuery = useQuery({
    queryKey: ["crm-acl", "role", selectedId],
    queryFn: () => getAclRole(selectedId!),
    enabled: !!selectedId,
    retry: false,
  });

  const assignmentsQuery = useQuery({
    queryKey: ["crm-acl", "assignments", selectedId],
    queryFn: () => listRoleAssignments(selectedId!),
    enabled: !!selectedId,
    retry: false,
  });

  const createMut = useMutation({
    mutationFn: () =>
      createAclRole({
        name: name.trim(),
        description: description.trim(),
        permissions: matrix,
      }),
    onSuccess: (role) => {
      toast.success("Role created");
      setCreateOpen(false);
      setName("");
      setDescription("");
      setMatrix({});
      qc.invalidateQueries({ queryKey: ["crm-acl", "roles"] });
      setSelectedId(role.role_id);
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to create role"),
  });

  const saveMatrixMut = useMutation({
    mutationFn: (perms: Record<string, CrmAclPermissionMatrix>) =>
      updateAclRole(selectedId!, { permissions: perms }),
    onSuccess: () => {
      toast.success("Permissions saved");
      qc.invalidateQueries({ queryKey: ["crm-acl", "role", selectedId] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to save"),
  });

  const deleteMut = useMutation({
    mutationFn: (roleId: string) => deleteAclRole(roleId),
    onSuccess: () => {
      toast.success("Role deleted");
      setSelectedId(null);
      qc.invalidateQueries({ queryKey: ["crm-acl", "roles"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to delete"),
  });

  const assignUserMut = useMutation({
    mutationFn: () => assignRoleToUser(selectedId!, assignUserSub.trim()),
    onSuccess: () => {
      toast.success("User assigned");
      setAssignUserSub("");
      qc.invalidateQueries({ queryKey: ["crm-acl", "assignments", selectedId] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to assign"),
  });

  const revokeUserMut = useMutation({
    mutationFn: (userSub: string) => revokeRoleFromUser(selectedId!, userSub),
    onSuccess: () => {
      toast.success("User revoked");
      qc.invalidateQueries({ queryKey: ["crm-acl", "assignments", selectedId] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to revoke"),
  });

  const assignGroupMut = useMutation({
    mutationFn: () => assignRoleToGroup(selectedId!, assignGroupKey.trim()),
    onSuccess: () => {
      toast.success("Group assigned");
      setAssignGroupKey("");
      qc.invalidateQueries({ queryKey: ["crm-acl", "assignments", selectedId] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to assign group"),
  });

  const revokeGroupMut = useMutation({
    mutationFn: (groupKey: string) => revokeRoleFromGroup(selectedId!, groupKey),
    onSuccess: () => {
      toast.success("Group revoked");
      qc.invalidateQueries({ queryKey: ["crm-acl", "assignments", selectedId] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to revoke group"),
  });

  if (rolesQuery.isError) {
    const err = rolesQuery.error;
    if (isNotEnabled(err)) return <NotEnabledState feature="CRM ACL roles" />;
    return <NotEnabledState feature="CRM ACL roles" status={(err as ApiError)?.status} />;
  }

  const roles = rolesQuery.data?.roles ?? [];
  const detail = detailQuery.data;
  const editMatrix = detail?.permissions ?? {};

  return (
    <div className="grid gap-4 lg:grid-cols-[320px_1fr]">
      {/* Role list */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0">
          <div>
            <CardTitle className="text-base">Roles</CardTitle>
            <CardDescription>{roles.length} defined</CardDescription>
          </div>
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <Plus className="mr-1 h-4 w-4" /> New
          </Button>
        </CardHeader>
        <CardContent className="space-y-1">
          {rolesQuery.isLoading && (
            <p className="text-sm text-muted-foreground">Loading…</p>
          )}
          {!rolesQuery.isLoading && roles.length === 0 && (
            <p className="text-sm text-muted-foreground">No roles yet.</p>
          )}
          {roles.map((r) => (
            <button
              key={r.role_id}
              onClick={() => setSelectedId(r.role_id)}
              className={`w-full rounded-md px-3 py-2 text-left text-sm transition-colors hover:bg-accent ${
                selectedId === r.role_id ? "bg-accent" : ""
              }`}
            >
              <div className="font-medium">{r.name}</div>
              {r.description && (
                <div className="truncate text-xs text-muted-foreground">{r.description}</div>
              )}
            </button>
          ))}
        </CardContent>
      </Card>

      {/* Role detail */}
      <div className="space-y-4">
        {!selectedId && (
          <Card>
            <CardContent className="py-10 text-center text-sm text-muted-foreground">
              Select a role to view its permission matrix and assignments.
            </CardContent>
          </Card>
        )}
        {selectedId && detail && (
          <>
            <Card>
              <CardHeader className="flex flex-row items-start justify-between gap-2 space-y-0">
                <div>
                  <CardTitle className="text-base">{detail.name}</CardTitle>
                  <CardDescription>
                    Created {fmt(detail.created_at)} · {detail.description || "no description"}
                  </CardDescription>
                </div>
                <Button
                  size="sm"
                  variant="destructive"
                  onClick={() => {
                    if (confirm(`Delete role "${detail.name}"?`)) deleteMut.mutate(detail.role_id);
                  }}
                  disabled={deleteMut.isPending}
                >
                  <Trash2 className="mr-1 h-4 w-4" /> Delete
                </Button>
              </CardHeader>
              <CardContent className="space-y-3">
                <MatrixEditor
                  value={editMatrix}
                  onChange={(next) =>
                    qc.setQueryData(["crm-acl", "role", selectedId], {
                      ...detail,
                      permissions: next,
                    })
                  }
                />
                <Button
                  size="sm"
                  onClick={() => saveMatrixMut.mutate(editMatrix)}
                  disabled={saveMatrixMut.isPending}
                >
                  Save permissions
                </Button>
              </CardContent>
            </Card>

            {/* Assignments */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Assignments</CardTitle>
                <CardDescription>Grant this role to users or platform groups.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                {/* Users */}
                <div className="space-y-2">
                  <Label className="flex items-center gap-1 text-xs uppercase text-muted-foreground">
                    <Users className="h-3.5 w-3.5" /> Users
                  </Label>
                  <div className="flex gap-2">
                    <Input
                      placeholder="user sub / email"
                      value={assignUserSub}
                      onChange={(e) => setAssignUserSub(e.target.value)}
                    />
                    <Button
                      size="sm"
                      onClick={() => assignUserMut.mutate()}
                      disabled={!assignUserSub.trim() || assignUserMut.isPending}
                    >
                      Assign
                    </Button>
                  </div>
                  <div className="space-y-1">
                    {(assignmentsQuery.data?.user_assignments ?? []).map((ua, i) => {
                      const sub = String(
                        (ua as Record<string, unknown>).user_sub ?? (ua as Record<string, unknown>).sub ?? "",
                      );
                      return (
                        <div
                          key={`${sub}-${i}`}
                          className="flex items-center justify-between rounded border px-2 py-1 text-sm"
                        >
                          <span className="font-mono text-xs">{sub || "(unknown)"}</span>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => revokeUserMut.mutate(sub)}
                            disabled={!sub}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </div>
                      );
                    })}
                    {(assignmentsQuery.data?.user_assignments ?? []).length === 0 && (
                      <p className="text-xs text-muted-foreground">No user assignments.</p>
                    )}
                  </div>
                </div>

                {/* Groups */}
                <div className="space-y-2">
                  <Label className="flex items-center gap-1 text-xs uppercase text-muted-foreground">
                    <KeyRound className="h-3.5 w-3.5" /> Groups
                  </Label>
                  <div className="flex gap-2">
                    <Input
                      placeholder="group key"
                      value={assignGroupKey}
                      onChange={(e) => setAssignGroupKey(e.target.value)}
                    />
                    <Button
                      size="sm"
                      onClick={() => assignGroupMut.mutate()}
                      disabled={!assignGroupKey.trim() || assignGroupMut.isPending}
                    >
                      Assign
                    </Button>
                  </div>
                  <div className="space-y-1">
                    {(assignmentsQuery.data?.group_assignments ?? []).map((ga) => (
                      <div
                        key={ga.group_key}
                        className="flex items-center justify-between rounded border px-2 py-1 text-sm"
                      >
                        <span className="font-mono text-xs">{ga.group_key}</span>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => revokeGroupMut.mutate(ga.group_key)}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    ))}
                    {(assignmentsQuery.data?.group_assignments ?? []).length === 0 && (
                      <p className="text-xs text-muted-foreground">No group assignments.</p>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          </>
        )}
      </div>

      {/* Create dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle>New ACL role</DialogTitle>
            <DialogDescription>
              Define a named role with a per-module permission matrix.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="role-name">Name</Label>
              <Input
                id="role-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Sales Manager"
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="role-desc">Description</Label>
              <Textarea
                id="role-desc"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={2}
              />
            </div>
            <MatrixEditor value={matrix} onChange={setMatrix} />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => createMut.mutate()}
              disabled={!name.trim() || createMut.isPending}
            >
              Create role
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// Security Groups tab
// ════════════════════════════════════════════════════════════════════════════

function SecurityGroupsTab() {
  const qc = useQueryClient();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [isGlobal, setIsGlobal] = useState(false);

  const [memberSub, setMemberSub] = useState("");
  const [memberCanEdit, setMemberCanEdit] = useState(false);
  const [recEntity, setRecEntity] = useState(STUDIO_ENTITY_TYPES[0]!);
  const [recId, setRecId] = useState("");

  const groupsQuery = useQuery({
    queryKey: ["crm-sg", "groups"],
    queryFn: () => listSecurityGroups({ limit: 200 }),
    retry: false,
  });

  const detailQuery = useQuery({
    queryKey: ["crm-sg", "group", selectedId],
    queryFn: () => getSecurityGroup(selectedId!),
    enabled: !!selectedId,
    retry: false,
  });

  const createMut = useMutation({
    mutationFn: () =>
      createSecurityGroup({
        name: name.trim(),
        description: description.trim(),
        is_global: isGlobal,
      }),
    onSuccess: (g) => {
      toast.success("Group created");
      setCreateOpen(false);
      setName("");
      setDescription("");
      setIsGlobal(false);
      qc.invalidateQueries({ queryKey: ["crm-sg", "groups"] });
      setSelectedId(g.group_id);
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to create group"),
  });

  const deleteMut = useMutation({
    mutationFn: (gid: string) => deleteSecurityGroup(gid),
    onSuccess: () => {
      toast.success("Group deleted");
      setSelectedId(null);
      qc.invalidateQueries({ queryKey: ["crm-sg", "groups"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to delete (root only?)"),
  });

  const addMemberMut = useMutation({
    mutationFn: () => addSecurityGroupMember(selectedId!, memberSub.trim(), memberCanEdit),
    onSuccess: () => {
      toast.success("Member added");
      setMemberSub("");
      setMemberCanEdit(false);
      qc.invalidateQueries({ queryKey: ["crm-sg", "group", selectedId] });
      qc.invalidateQueries({ queryKey: ["crm-sg", "groups"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to add member"),
  });

  const removeMemberMut = useMutation({
    mutationFn: (sub: string) => removeSecurityGroupMember(selectedId!, sub),
    onSuccess: () => {
      toast.success("Member removed");
      qc.invalidateQueries({ queryKey: ["crm-sg", "group", selectedId] });
      qc.invalidateQueries({ queryKey: ["crm-sg", "groups"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to remove"),
  });

  const assignRecMut = useMutation({
    mutationFn: () => assignSecurityGroupRecord(selectedId!, recEntity, recId.trim()),
    onSuccess: () => {
      toast.success("Record assigned");
      setRecId("");
      qc.invalidateQueries({ queryKey: ["crm-sg", "group", selectedId] });
      qc.invalidateQueries({ queryKey: ["crm-sg", "groups"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to assign record"),
  });

  const unassignRecMut = useMutation({
    mutationFn: (r: { entity: string; id: string }) =>
      unassignSecurityGroupRecord(selectedId!, r.entity, r.id),
    onSuccess: () => {
      toast.success("Record unassigned");
      qc.invalidateQueries({ queryKey: ["crm-sg", "group", selectedId] });
      qc.invalidateQueries({ queryKey: ["crm-sg", "groups"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to unassign"),
  });

  if (groupsQuery.isError) {
    const err = groupsQuery.error;
    if (isNotEnabled(err)) return <NotEnabledState feature="CRM security groups" />;
    return <NotEnabledState feature="CRM security groups" status={(err as ApiError)?.status} />;
  }

  const groups = groupsQuery.data?.groups ?? [];
  const detail = detailQuery.data;

  return (
    <div className="grid gap-4 lg:grid-cols-[320px_1fr]">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0">
          <div>
            <CardTitle className="text-base">Groups</CardTitle>
            <CardDescription>{groups.length} defined</CardDescription>
          </div>
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <Plus className="mr-1 h-4 w-4" /> New
          </Button>
        </CardHeader>
        <CardContent className="space-y-1">
          {groupsQuery.isLoading && <p className="text-sm text-muted-foreground">Loading…</p>}
          {!groupsQuery.isLoading && groups.length === 0 && (
            <p className="text-sm text-muted-foreground">No groups yet.</p>
          )}
          {groups.map((g) => (
            <button
              key={g.group_id}
              onClick={() => setSelectedId(g.group_id)}
              className={`w-full rounded-md px-3 py-2 text-left text-sm transition-colors hover:bg-accent ${
                selectedId === g.group_id ? "bg-accent" : ""
              }`}
            >
              <div className="flex items-center gap-2 font-medium">
                {g.name}
                {g.is_global && (
                  <Badge variant="secondary" className="text-[10px]">
                    global
                  </Badge>
                )}
              </div>
              <div className="text-xs text-muted-foreground">
                {g.member_count} members · {g.record_count} records
              </div>
            </button>
          ))}
        </CardContent>
      </Card>

      <div className="space-y-4">
        {!selectedId && (
          <Card>
            <CardContent className="py-10 text-center text-sm text-muted-foreground">
              Select a group to manage members and record assignments.
            </CardContent>
          </Card>
        )}
        {selectedId && detail && (
          <>
            <Card>
              <CardHeader className="flex flex-row items-start justify-between gap-2 space-y-0">
                <div>
                  <CardTitle className="text-base">{detail.group.name}</CardTitle>
                  <CardDescription>
                    {detail.group.description || "no description"} · owner{" "}
                    <span className="font-mono">{detail.group.owner_sub}</span>
                  </CardDescription>
                </div>
                <Button
                  size="sm"
                  variant="destructive"
                  onClick={() => {
                    if (confirm(`Delete group "${detail.group.name}"?`))
                      deleteMut.mutate(detail.group.group_id);
                  }}
                  disabled={deleteMut.isPending}
                >
                  <Trash2 className="mr-1 h-4 w-4" /> Delete
                </Button>
              </CardHeader>
            </Card>

            {/* Members */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <Users className="h-4 w-4" /> Members
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex flex-wrap items-end gap-2">
                  <div className="flex-1 space-y-1">
                    <Label className="text-xs">User sub</Label>
                    <Input
                      placeholder="user sub / email"
                      value={memberSub}
                      onChange={(e) => setMemberSub(e.target.value)}
                    />
                  </div>
                  <label className="flex items-center gap-2 pb-2 text-sm">
                    <Switch checked={memberCanEdit} onCheckedChange={setMemberCanEdit} />
                    Can edit
                  </label>
                  <Button
                    size="sm"
                    onClick={() => addMemberMut.mutate()}
                    disabled={!memberSub.trim() || addMemberMut.isPending}
                  >
                    Add
                  </Button>
                </div>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>User</TableHead>
                      <TableHead>Can edit</TableHead>
                      <TableHead>Added</TableHead>
                      <TableHead />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {detail.members.map((m) => (
                      <TableRow key={m.user_sub}>
                        <TableCell className="font-mono text-xs">{m.user_sub}</TableCell>
                        <TableCell>
                          {m.can_edit ? (
                            <Badge variant="secondary">edit</Badge>
                          ) : (
                            <Badge variant="outline">read</Badge>
                          )}
                        </TableCell>
                        <TableCell className="text-xs">{fmt(m.added_at)}</TableCell>
                        <TableCell className="text-right">
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => removeMemberMut.mutate(m.user_sub)}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                    {detail.members.length === 0 && (
                      <TableRow>
                        <TableCell colSpan={4} className="text-center text-sm text-muted-foreground">
                          No members.
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>

            {/* Records */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <FileLock2 className="h-4 w-4" /> Record assignments
                </CardTitle>
                <CardDescription>
                  Scope individual records into this group for record-level access control.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex flex-wrap items-end gap-2">
                  <div className="space-y-1">
                    <Label className="text-xs">Entity</Label>
                    <Select value={recEntity} onValueChange={setRecEntity}>
                      <SelectTrigger className="w-40">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {STUDIO_ENTITY_TYPES.map((et) => (
                          <SelectItem key={et} value={et} className="capitalize">
                            {et}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="flex-1 space-y-1">
                    <Label className="text-xs">Record ID</Label>
                    <Input
                      placeholder="record id"
                      value={recId}
                      onChange={(e) => setRecId(e.target.value)}
                    />
                  </div>
                  <Button
                    size="sm"
                    onClick={() => assignRecMut.mutate()}
                    disabled={!recId.trim() || assignRecMut.isPending}
                  >
                    Assign
                  </Button>
                </div>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Entity</TableHead>
                      <TableHead>Record</TableHead>
                      <TableHead>Assigned</TableHead>
                      <TableHead />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {detail.records.map((r) => (
                      <TableRow key={`${r.entity_type}-${r.record_id}`}>
                        <TableCell className="capitalize">{r.entity_type}</TableCell>
                        <TableCell className="font-mono text-xs">{r.record_id}</TableCell>
                        <TableCell className="text-xs">{fmt(r.created_at)}</TableCell>
                        <TableCell className="text-right">
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() =>
                              unassignRecMut.mutate({ entity: r.entity_type, id: r.record_id })
                            }
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                    {detail.records.length === 0 && (
                      <TableRow>
                        <TableCell colSpan={4} className="text-center text-sm text-muted-foreground">
                          No records assigned.
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </>
        )}
      </div>

      {/* Create dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New security group</DialogTitle>
            <DialogDescription>
              Groups scope record-level access across CRM modules.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="sg-name">Name</Label>
              <Input id="sg-name" value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="sg-desc">Description</Label>
              <Textarea
                id="sg-desc"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={2}
              />
            </div>
            <label className="flex items-center gap-2 text-sm">
              <Switch checked={isGlobal} onCheckedChange={setIsGlobal} />
              Global group (applies to all users)
            </label>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => createMut.mutate()}
              disabled={!name.trim() || createMut.isPending}
            >
              Create group
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// Page shell
// ════════════════════════════════════════════════════════════════════════════

export default function CrmSecurityPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="CRM Security"
        description="Manage ACL roles, permission matrices, and record-level security groups."
      />
      <Tabs defaultValue="roles">
        <TabsList>
          <TabsTrigger value="roles">
            <Shield className="mr-1 h-4 w-4" /> ACL Roles
          </TabsTrigger>
          <TabsTrigger value="groups">
            <FileLock2 className="mr-1 h-4 w-4" /> Security Groups
          </TabsTrigger>
        </TabsList>
        <TabsContent value="roles" className="mt-4">
          <AclRolesTab />
        </TabsContent>
        <TabsContent value="groups" className="mt-4">
          <SecurityGroupsTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
