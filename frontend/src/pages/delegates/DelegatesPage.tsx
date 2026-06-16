import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { UserCog, Plus, Trash2, Edit2, Clock, CheckCircle } from "lucide-react";
import { toast } from "sonner";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
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
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import {
  listDelegates,
  addDelegate,
  updateDelegatePermissions,
  revokeDelegate,
  listManagedCreators,
  listInvites,
  respondToInvite,
  getDelegateSettings,
  updateDelegateSettings,
  getDelegateAudit,
  listPresets,
} from "@/api/endpoints/delegates";

import type {
  DelegateOut,
  ManagedCreatorOut,
  DelegateAuditOut,
  PermissionPresetOut,
  DelegateSettingsOut,
} from "@/api/types";

const ALL_PERMISSIONS = [
  "chat_read",
  "chat_respond",
  "feed_read",
  "feed_post",
  "feed_moderate",
  "broadcast_moderate",
  "broadcast_control",
];

export default function DelegatesPage() {
  const queryClient = useQueryClient();
  const [addOpen, setAddOpen] = useState(false);
  const [editTarget, setEditTarget] = useState<DelegateOut | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<DelegateOut | null>(null);

  // -- Add form state --
  const [newDelegateId, setNewDelegateId] = useState("");
  const [newPerms, setNewPerms] = useState<string[]>([]);
  const [newPreset, setNewPreset] = useState<string>("");
  const [newLabel, setNewLabel] = useState("");

  // -- Edit form state --
  const [editPerms, setEditPerms] = useState<string[]>([]);
  const [editPreset, setEditPreset] = useState<string>("");

  // -- Queries --
  const delegatesQ = useQuery({ queryKey: ["delegates"], queryFn: listDelegates });
  const managedQ = useQuery({ queryKey: ["delegates", "managed"], queryFn: listManagedCreators });
  const invitesQ = useQuery({ queryKey: ["delegates", "invites"], queryFn: listInvites });
  const settingsQ = useQuery({ queryKey: ["delegates", "settings"], queryFn: getDelegateSettings });
  const auditQ = useQuery({ queryKey: ["delegates", "audit"], queryFn: getDelegateAudit });
  const presetsQ = useQuery({ queryKey: ["delegates", "presets"], queryFn: listPresets });

  // -- Mutations --
  const addMut = useMutation({
    mutationFn: () =>
      addDelegate({
        delegate_id: newDelegateId,
        permissions: newPerms,
        preset: newPreset || undefined,
        label: newLabel,
      }),
    onSuccess: () => {
      toast.success("Delegate added");
      queryClient.invalidateQueries({ queryKey: ["delegates"] });
      setAddOpen(false);
      setNewDelegateId("");
      setNewPerms([]);
      setNewPreset("");
      setNewLabel("");
    },
    onError: (err: any) => toast.error(err?.message ?? "Failed to add delegate"),
  });

  const updateMut = useMutation({
    mutationFn: () =>
      updateDelegatePermissions(editTarget!.delegate_id, {
        permissions: editPerms,
        preset: editPreset || undefined,
      }),
    onSuccess: () => {
      toast.success("Permissions updated");
      queryClient.invalidateQueries({ queryKey: ["delegates"] });
      setEditTarget(null);
    },
    onError: (err: any) => toast.error(err?.message ?? "Failed to update"),
  });

  const revokeMut = useMutation({
    mutationFn: () => revokeDelegate(revokeTarget!.delegate_id),
    onSuccess: () => {
      toast.success("Delegate revoked");
      queryClient.invalidateQueries({ queryKey: ["delegates"] });
      setRevokeTarget(null);
    },
    onError: (err: any) => toast.error(err?.message ?? "Failed to revoke"),
  });

  const respondMut = useMutation({
    mutationFn: ({ creatorId, accept }: { creatorId: string; accept: boolean }) =>
      respondToInvite(creatorId, { accept }),
    onSuccess: (_data, vars) => {
      toast.success(vars.accept ? "Invite accepted" : "Invite declined");
      queryClient.invalidateQueries({ queryKey: ["delegates"] });
    },
    onError: (err: any) => toast.error(err?.message ?? "Failed"),
  });

  const settingsMut = useMutation({
    mutationFn: updateDelegateSettings,
    onSuccess: () => {
      toast.success("Settings saved");
      queryClient.invalidateQueries({ queryKey: ["delegates", "settings"] });
    },
    onError: (err: any) => toast.error(err?.message ?? "Failed to save settings"),
  });

  const handlePresetChange = (presetKey: string, perms: string[], setPerms: (p: string[]) => void, setPresetState: (p: string) => void) => {
    const found = presetsQ.data?.find((p: PermissionPresetOut) => p.key === presetKey);
    if (found) {
      setPerms(found.permissions);
    }
    setPresetState(presetKey);
  };

  const togglePerm = (perm: string, perms: string[], setPerms: (p: string[]) => void) => {
    if (perms.includes(perm)) {
      setPerms(perms.filter((p) => p !== perm));
    } else {
      setPerms([...perms, perm]);
    }
  };

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-4 md:p-6">
      <div className="flex items-center gap-3">
        <UserCog className="h-7 w-7 text-primary" />
        <h1 className="text-2xl font-bold">Delegates</h1>
      </div>

      {/* Pending invites banner */}
      {(invitesQ.data?.length ?? 0) > 0 && (
        <Card className="border-amber-300 bg-amber-50 dark:bg-amber-950/20">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Pending Invites</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {invitesQ.data!.map((inv: DelegateOut) => (
              <div key={inv.creator_id} className="flex items-center justify-between rounded-md border bg-background p-3">
                <div>
                  <span className="font-medium">{inv.creator_id}</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {inv.permissions.map((p) => (
                      <Badge key={p} variant="outline" className="text-xs">{p}</Badge>
                    ))}
                  </div>
                </div>
                <div className="flex gap-2">
                  <Button size="sm" onClick={() => respondMut.mutate({ creatorId: inv.creator_id, accept: true })}>
                    Accept
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => respondMut.mutate({ creatorId: inv.creator_id, accept: false })}>
                    Decline
                  </Button>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      <Tabs defaultValue="delegates">
        <TabsList>
          <TabsTrigger value="delegates">My Delegates</TabsTrigger>
          <TabsTrigger value="managing">Managing</TabsTrigger>
          <TabsTrigger value="audit">Audit Log</TabsTrigger>
        </TabsList>

        {/* ── My Delegates Tab ─────────────────────────────────── */}
        <TabsContent value="delegates" className="space-y-4">
          <div className="flex justify-end">
            <Button onClick={() => setAddOpen(true)}>
              <Plus className="mr-2 h-4 w-4" /> Add Delegate
            </Button>
          </div>

          {delegatesQ.data?.length === 0 && (
            <p className="py-8 text-center text-muted-foreground">No delegates yet.</p>
          )}

          <div className="space-y-3">
            {delegatesQ.data?.map((d: DelegateOut) => (
              <Card key={d.delegate_id}>
                <CardContent className="flex items-start justify-between p-4">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold">{d.delegate_id}</span>
                      <Badge variant={d.status === "active" ? "default" : "secondary"}>
                        {d.status === "active" ? (
                          <><CheckCircle className="mr-1 h-3 w-3" /> Active</>
                        ) : (
                          <><Clock className="mr-1 h-3 w-3" /> Pending</>
                        )}
                      </Badge>
                      {d.preset && <Badge variant="outline">{d.preset}</Badge>}
                    </div>
                    {d.label && <p className="text-sm text-muted-foreground">{d.label}</p>}
                    <div className="flex flex-wrap gap-1">
                      {d.permissions.map((p) => (
                        <Badge key={p} variant="outline" className="text-xs">{p}</Badge>
                      ))}
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => {
                        setEditTarget(d);
                        setEditPerms(d.permissions);
                        setEditPreset(d.preset ?? "");
                      }}
                    >
                      <Edit2 className="h-4 w-4" />
                    </Button>
                    <Button size="sm" variant="destructive" onClick={() => setRevokeTarget(d)}>
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Settings card */}
          {settingsQ.data && (
            <SettingsCard settings={settingsQ.data} onSave={(s) => settingsMut.mutate(s)} />
          )}
        </TabsContent>

        {/* ── Managing Tab ─────────────────────────────────────── */}
        <TabsContent value="managing" className="space-y-4">
          {managedQ.data?.length === 0 && (
            <p className="py-8 text-center text-muted-foreground">You are not managing any creators.</p>
          )}
          {managedQ.data?.map((c: ManagedCreatorOut) => (
            <Card key={c.creator_id}>
              <CardContent className="p-4">
                <div className="flex items-center gap-2">
                  <span className="font-semibold">{c.creator_id}</span>
                  {c.preset && <Badge variant="outline">{c.preset}</Badge>}
                </div>
                <div className="mt-1 flex flex-wrap gap-1">
                  {c.permissions.map((p) => (
                    <Badge key={p} variant="outline" className="text-xs">{p}</Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          ))}
        </TabsContent>

        {/* ── Audit Log Tab ───────────────────────────────────── */}
        <TabsContent value="audit" className="space-y-4">
          {auditQ.data?.length === 0 && (
            <p className="py-8 text-center text-muted-foreground">No audit entries yet.</p>
          )}
          {auditQ.data?.map((e: DelegateAuditOut) => (
            <Card key={e.event_id}>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <p className="text-sm font-medium">{e.action}</p>
                    <p className="text-xs text-muted-foreground">
                      by {e.actor_id} ({e.actor_type}) &rarr; {e.target_id}
                    </p>
                  </div>
                  <span className="text-xs text-muted-foreground">
                    {new Date(e.ts * 1000).toLocaleString()}
                  </span>
                </div>
              </CardContent>
            </Card>
          ))}
        </TabsContent>
      </Tabs>

      {/* ── Add Delegate Dialog ──────────────────────────────── */}
      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Add Delegate</DialogTitle>
            <DialogDescription>Grant another user permission to act on your behalf.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>User ID / Email</Label>
              <Input value={newDelegateId} onChange={(e) => setNewDelegateId(e.target.value)} placeholder="user@example.com" />
            </div>
            <div>
              <Label>Label (optional)</Label>
              <Input value={newLabel} onChange={(e) => setNewLabel(e.target.value)} placeholder="Social Media Manager" />
            </div>
            <div>
              <Label>Preset</Label>
              <Select value={newPreset} onValueChange={(v) => handlePresetChange(v, newPerms, setNewPerms, setNewPreset)}>
                <SelectTrigger><SelectValue placeholder="Choose preset..." /></SelectTrigger>
                <SelectContent>
                  {presetsQ.data?.map((p: PermissionPresetOut) => (
                    <SelectItem key={p.key} value={p.key}>{p.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Permissions</Label>
              <div className="mt-1 flex flex-wrap gap-2">
                {ALL_PERMISSIONS.map((perm) => (
                  <Badge
                    key={perm}
                    variant={newPerms.includes(perm) ? "default" : "outline"}
                    className="cursor-pointer"
                    onClick={() => togglePerm(perm, newPerms, setNewPerms)}
                  >
                    {perm}
                  </Badge>
                ))}
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAddOpen(false)}>Cancel</Button>
            <Button disabled={!newDelegateId || newPerms.length === 0} onClick={() => addMut.mutate()}>
              Add Delegate
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Edit Permissions Dialog ──────────────────────────── */}
      <Dialog open={!!editTarget} onOpenChange={(v) => !v && setEditTarget(null)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Edit Permissions</DialogTitle>
            <DialogDescription>Update permissions for {editTarget?.delegate_id}</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>Preset</Label>
              <Select value={editPreset} onValueChange={(v) => handlePresetChange(v, editPerms, setEditPerms, setEditPreset)}>
                <SelectTrigger><SelectValue placeholder="Choose preset..." /></SelectTrigger>
                <SelectContent>
                  {presetsQ.data?.map((p: PermissionPresetOut) => (
                    <SelectItem key={p.key} value={p.key}>{p.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Permissions</Label>
              <div className="mt-1 flex flex-wrap gap-2">
                {ALL_PERMISSIONS.map((perm) => (
                  <Badge
                    key={perm}
                    variant={editPerms.includes(perm) ? "default" : "outline"}
                    className="cursor-pointer"
                    onClick={() => togglePerm(perm, editPerms, setEditPerms)}
                  >
                    {perm}
                  </Badge>
                ))}
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditTarget(null)}>Cancel</Button>
            <Button disabled={editPerms.length === 0} onClick={() => updateMut.mutate()}>
              Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Revoke Confirmation ──────────────────────────────── */}
      <AlertDialog open={!!revokeTarget} onOpenChange={(v) => !v && setRevokeTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Revoke Delegate</AlertDialogTitle>
            <AlertDialogDescription>
              This will immediately remove {revokeTarget?.delegate_id}'s access. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={() => revokeMut.mutate()}>Revoke</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

// ── Settings Card ───────────────────────────────────────────────

function SettingsCard({
  settings,
  onSave,
}: {
  settings: DelegateSettingsOut;
  onSave: (s: DelegateSettingsOut & { delegate_tag_format: string }) => void;
}) {
  const [requireAcceptance, setRequireAcceptance] = useState(settings.require_acceptance);
  const [maxDelegates, setMaxDelegates] = useState(settings.max_delegates);
  const [tagEnabled, setTagEnabled] = useState(settings.delegate_tag_enabled);
  const [tagFormat, setTagFormat] = useState(settings.delegate_tag_format);
  const [hideFromRecipients, setHideFromRecipients] = useState(
    settings.hide_delegate_from_recipients ?? false,
  );

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Delegation Settings</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center justify-between">
          <Label>Require acceptance</Label>
          <Switch checked={requireAcceptance} onCheckedChange={setRequireAcceptance} />
        </div>
        <div className="flex items-center justify-between gap-4">
          <Label>Max delegates</Label>
          <Input
            type="number"
            className="w-20"
            min={1}
            max={20}
            value={maxDelegates}
            onChange={(e) => setMaxDelegates(Number(e.target.value))}
          />
        </div>
        <div className="flex items-center justify-between">
          <Label>Delegate tag</Label>
          <Switch checked={tagEnabled} onCheckedChange={setTagEnabled} />
        </div>
        {tagEnabled && (
          <div>
            <Label>Tag format</Label>
            <Input value={tagFormat} onChange={(e) => setTagFormat(e.target.value)} />
          </div>
        )}
        <div className="flex items-center justify-between gap-4">
          <div>
            <Label>Hide delegate from recipients</Label>
            <p className="text-muted-foreground text-xs">
              Recipients see messages as if you sent them. You and the delegate still
              see the "via" attribution, and the audit log always records it.
            </p>
          </div>
          <Switch checked={hideFromRecipients} onCheckedChange={setHideFromRecipients} />
        </div>
        <Button
          onClick={() =>
            onSave({
              require_acceptance: requireAcceptance,
              max_delegates: maxDelegates,
              delegate_tag_enabled: tagEnabled,
              delegate_tag_format: tagFormat,
              hide_delegate_from_recipients: hideFromRecipients,
            })
          }
        >
          Save Settings
        </Button>
      </CardContent>
    </Card>
  );
}
