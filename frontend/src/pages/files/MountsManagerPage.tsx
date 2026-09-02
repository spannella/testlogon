import React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { HardDrive, Plus, RefreshCw, Trash2, KeyRound, PlugZap } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from "@/components/ui/dialog";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
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
import {
  listMounts,
  createSftpMount,
  createFileMount,
  deleteSftpMount,
  deleteFileMount,
  testMount,
  validateFileMount,
  rotateMountCredential,
  type FileMount,
} from "@/api/endpoints/files";
import {
  SUPPORTED_PROVIDERS,
  providerMeta,
  mountStatusBadge,
  validateMountConfig,
  buildCreateBody,
  validateRotateCredential,
  canTestMount,
  type MountProvider,
  type MountConfigDraft,
  type RotateCredentialDraft,
  type BadgeSeverity,
} from "@/lib/mountConfig";

function is404(err: unknown): boolean {
  return err instanceof ApiError && err.status === 404;
}

const badgeVariant: Record<BadgeSeverity, "success" | "warning" | "destructive" | "secondary"> = {
  success: "success",
  warning: "warning",
  danger: "destructive",
  neutral: "secondary",
};

function emptyDraft(): MountConfigDraft {
  return {
    provider: "sftp",
    protocol: "sftp",
    host: "",
    port: 22,
    remote_root: "/",
    read_only: false,
    auth_credential_ref: "",
    mount_path: "/",
    bucket: "",
    prefix: "",
    mode: "read_only",
    auth_ref: "",
  };
}

function emptyRotate(): RotateCredentialDraft {
  return { auth_mode: "password", username: "", password: "", private_key: "" };
}

export default function MountsManagerPage() {
  const qc = useQueryClient();
  const [addOpen, setAddOpen] = React.useState(false);
  const [draft, setDraft] = React.useState<MountConfigDraft>(emptyDraft);
  const [rotateFor, setRotateFor] = React.useState<string | null>(null);
  const [rotate, setRotate] = React.useState<RotateCredentialDraft>(emptyRotate);

  const mountsQuery = useQuery({
    queryKey: ["fs-mounts-manager"],
    queryFn: () => listMounts(),
    retry: (count, err) => !is404(err) && count < 2,
  });

  const featureDisabled = is404(mountsQuery.error);
  const mounts: FileMount[] = Array.isArray(mountsQuery.data) ? mountsQuery.data : [];

  const invalidate = () => qc.invalidateQueries({ queryKey: ["fs-mounts-manager"] });

  const createMut = useMutation({
    mutationFn: async (d: MountConfigDraft) => {
      const body = buildCreateBody(d);
      if (d.provider === "sftp") return createSftpMount(body as never);
      return createFileMount(body as never);
    },
    onSuccess: () => {
      toast.success("Mount added");
      setAddOpen(false);
      setDraft(emptyDraft());
      invalidate();
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.detail : "Failed to add mount"),
  });

  const deleteMut = useMutation({
    mutationFn: async (m: FileMount) => {
      if (m.provider === "sftp") return deleteSftpMount(m.mount_id);
      return deleteFileMount(m.mount_id);
    },
    onSuccess: () => {
      toast.success("Mount removed");
      invalidate();
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.detail : "Failed to remove mount"),
  });

  const testMut = useMutation({
    mutationFn: async (m: FileMount) => {
      if (canTestMount(m.provider)) return testMount(m.mount_id);
      return validateFileMount(m.mount_id);
    },
    onSuccess: (res) => {
      const ok = (res as { ok?: boolean }).ok;
      if (ok === false) toast.warning("Connection check reported a problem");
      else toast.success("Connection OK");
      invalidate();
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.detail : "Connection test failed"),
  });

  const rotateMut = useMutation({
    mutationFn: async (args: { mountId: string; body: RotateCredentialDraft }) =>
      rotateMountCredential(args.mountId, {
        auth_mode: args.body.auth_mode as "password" | "private_key",
        username: args.body.username ?? "",
        password: args.body.password || null,
        private_key: args.body.private_key || null,
        private_key_passphrase: args.body.private_key_passphrase || null,
        auth_credential_ref: args.body.auth_credential_ref || null,
      }),
    onSuccess: () => {
      toast.success("Credential rotated");
      setRotateFor(null);
      setRotate(emptyRotate());
      invalidate();
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.detail : "Failed to rotate credential"),
  });

  const draftErrors = validateMountConfig(draft);
  const rotateErrors = validateRotateCredential(rotate);
  const err = (field: string, res = draftErrors) =>
    res.errors.find((e) => e.field === field)?.message;

  const isHostBased = draft.provider === "sftp";

  if (featureDisabled) {
    return (
      <div className="space-y-6">
        <PageHeader title="Mounts" description="External storage providers" />
        <EmptyState
          icon={<HardDrive className="h-8 w-8" />}
          title="Mounts are not enabled"
          description="External mount management is not available in this environment."
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Mounts"
        description="Connect and manage external storage providers (SFTP, Google Drive, OneDrive, S3)."
        actions={
          <>
            <Button
              variant="outline"
              size="sm"
              onClick={() => mountsQuery.refetch()}
              disabled={mountsQuery.isFetching}
            >
              <RefreshCw className={`mr-2 h-4 w-4 ${mountsQuery.isFetching ? "animate-spin" : ""}`} />
              Refresh
            </Button>
            <Button size="sm" onClick={() => setAddOpen(true)}>
              <Plus className="mr-2 h-4 w-4" />
              Add provider
            </Button>
          </>
        }
      />

      {mounts.length === 0 && !mountsQuery.isLoading ? (
        <EmptyState
          icon={<HardDrive className="h-8 w-8" />}
          title="No mounts yet"
          description="Add an external provider to browse remote files alongside your own."
          action={{ label: "Add provider", onClick: () => setAddOpen(true) }}
        />
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Provider</TableHead>
              <TableHead>Path</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {mounts.map((m) => {
              const meta = providerMeta(m.provider);
              const badge = mountStatusBadge(m.status);
              return (
                <TableRow key={m.mount_id}>
                  <TableCell className="font-medium">{meta.label}</TableCell>
                  <TableCell className="text-muted-foreground">{m.mount_path || "—"}</TableCell>
                  <TableCell>
                    <Badge variant={badgeVariant[badge.severity]}>{badge.label}</Badge>
                  </TableCell>
                  <TableCell className="text-right space-x-1">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => testMut.mutate(m)}
                      disabled={testMut.isPending}
                      title="Test connection"
                    >
                      <PlugZap className="h-4 w-4" />
                    </Button>
                    {canTestMount(m.provider) && (m.can_rotate ?? true) && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          setRotate(emptyRotate());
                          setRotateFor(m.mount_id);
                        }}
                        title="Rotate credential"
                      >
                        <KeyRound className="h-4 w-4" />
                      </Button>
                    )}
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        if (window.confirm("Remove this mount?")) deleteMut.mutate(m);
                      }}
                      disabled={deleteMut.isPending}
                      title="Remove"
                    >
                      <Trash2 className="h-4 w-4 text-destructive" />
                    </Button>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      )}

      {/* Add provider dialog */}
      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add a mount</DialogTitle>
            <DialogDescription>
              Configure an external storage provider. Credentials are stored by reference.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="space-y-1">
              <Label>Provider</Label>
              <Select
                value={String(draft.provider)}
                onValueChange={(v) => setDraft({ ...draft, provider: v as MountProvider })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SUPPORTED_PROVIDERS.map((p) => (
                    <SelectItem key={p} value={p}>
                      {providerMeta(p).label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {isHostBased ? (
              <>
                <div className="grid grid-cols-3 gap-2">
                  <div className="col-span-1 space-y-1">
                    <Label>Protocol</Label>
                    <Select
                      value={draft.protocol || "sftp"}
                      onValueChange={(v) => setDraft({ ...draft, protocol: v })}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="sftp">SFTP</SelectItem>
                        <SelectItem value="scp">SCP</SelectItem>
                        <SelectItem value="ftp">FTP</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="col-span-2 space-y-1">
                    <Label>Host</Label>
                    <Input
                      value={draft.host ?? ""}
                      onChange={(e) => setDraft({ ...draft, host: e.target.value })}
                      placeholder="sftp.example.com"
                    />
                    {err("host") && <p className="text-xs text-destructive">{err("host")}</p>}
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div className="space-y-1">
                    <Label>Port</Label>
                    <Input
                      type="number"
                      value={String(draft.port ?? "")}
                      onChange={(e) => setDraft({ ...draft, port: e.target.value })}
                    />
                    {err("port") && <p className="text-xs text-destructive">{err("port")}</p>}
                  </div>
                  <div className="space-y-1">
                    <Label>Remote root</Label>
                    <Input
                      value={draft.remote_root ?? ""}
                      onChange={(e) => setDraft({ ...draft, remote_root: e.target.value })}
                      placeholder="/"
                    />
                    {err("remote_root") && (
                      <p className="text-xs text-destructive">{err("remote_root")}</p>
                    )}
                  </div>
                </div>
                <div className="space-y-1">
                  <Label>Credential reference</Label>
                  <Input
                    value={draft.auth_credential_ref ?? ""}
                    onChange={(e) => setDraft({ ...draft, auth_credential_ref: e.target.value })}
                    placeholder="secret-manager ref"
                  />
                  {err("auth_credential_ref") && (
                    <p className="text-xs text-destructive">{err("auth_credential_ref")}</p>
                  )}
                </div>
              </>
            ) : (
              <>
                <div className="space-y-1">
                  <Label>Mount path</Label>
                  <Input
                    value={draft.mount_path ?? ""}
                    onChange={(e) => setDraft({ ...draft, mount_path: e.target.value })}
                    placeholder="/cloud/my-drive"
                  />
                  {err("mount_path") && (
                    <p className="text-xs text-destructive">{err("mount_path")}</p>
                  )}
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div className="space-y-1">
                    <Label>Bucket / container</Label>
                    <Input
                      value={draft.bucket ?? ""}
                      onChange={(e) => setDraft({ ...draft, bucket: e.target.value })}
                    />
                    {err("bucket") && <p className="text-xs text-destructive">{err("bucket")}</p>}
                  </div>
                  <div className="space-y-1">
                    <Label>Prefix (optional)</Label>
                    <Input
                      value={draft.prefix ?? ""}
                      onChange={(e) => setDraft({ ...draft, prefix: e.target.value })}
                    />
                  </div>
                </div>
                <div className="space-y-1">
                  <Label>Credential reference</Label>
                  <Input
                    value={draft.auth_ref ?? ""}
                    onChange={(e) => setDraft({ ...draft, auth_ref: e.target.value })}
                  />
                  {err("auth_ref") && (
                    <p className="text-xs text-destructive">{err("auth_ref")}</p>
                  )}
                </div>
              </>
            )}

            <div className="flex items-center justify-between">
              <Label htmlFor="ro">Read only</Label>
              <Switch
                id="ro"
                checked={!!draft.read_only}
                onCheckedChange={(v) =>
                  setDraft({ ...draft, read_only: v, mode: v ? "read_only" : "read_write" })
                }
              />
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setAddOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => createMut.mutate(draft)}
              disabled={!draftErrors.ok || createMut.isPending}
            >
              Add mount
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Rotate credential dialog */}
      <Dialog open={!!rotateFor} onOpenChange={(o) => !o && setRotateFor(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rotate credential</DialogTitle>
            <DialogDescription>
              Replace the stored credential for this mount.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-1">
              <Label>Auth mode</Label>
              <Select
                value={rotate.auth_mode}
                onValueChange={(v) => setRotate({ ...rotate, auth_mode: v })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="password">Password</SelectItem>
                  <SelectItem value="private_key">Private key</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label>Username</Label>
              <Input
                value={rotate.username ?? ""}
                onChange={(e) => setRotate({ ...rotate, username: e.target.value })}
              />
              {err("username", rotateErrors) && (
                <p className="text-xs text-destructive">{err("username", rotateErrors)}</p>
              )}
            </div>
            {rotate.auth_mode === "password" ? (
              <div className="space-y-1">
                <Label>Password</Label>
                <Input
                  type="password"
                  value={rotate.password ?? ""}
                  onChange={(e) => setRotate({ ...rotate, password: e.target.value })}
                />
                {err("password", rotateErrors) && (
                  <p className="text-xs text-destructive">{err("password", rotateErrors)}</p>
                )}
              </div>
            ) : (
              <div className="space-y-1">
                <Label>Private key</Label>
                <Input
                  value={rotate.private_key ?? ""}
                  onChange={(e) => setRotate({ ...rotate, private_key: e.target.value })}
                  placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                />
                {err("private_key", rotateErrors) && (
                  <p className="text-xs text-destructive">{err("private_key", rotateErrors)}</p>
                )}
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRotateFor(null)}>
              Cancel
            </Button>
            <Button
              onClick={() => rotateFor && rotateMut.mutate({ mountId: rotateFor, body: rotate })}
              disabled={!rotateErrors.ok || rotateMut.isPending}
            >
              Rotate
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
