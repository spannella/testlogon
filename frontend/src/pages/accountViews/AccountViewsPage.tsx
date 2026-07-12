/**
 * VEW-001..003 — Account Views Manager
 *
 * Allows users to create/edit named field-level views over their financial
 * resources (wallet / ledger_account / payout_destination), manage who those
 * views are granted to, and generate public share links.
 *
 * Feature flag: OPEN_BANK_PROJECT_ENABLED + ACCOUNT_VIEWS_ENABLED
 * Both flags must be ON; 404 when either is off.
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Plus, Trash2, UserPlus, Link2, RefreshCw, AlertCircle, ChevronRight } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
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
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { ApiError } from "@/api/client";
import { useAuthStore } from "@/stores/authStore";
import {
  getGrantCatalog,
  listViews,
  createView,
  updateView,
  deleteView,
  grantView,
  listGrantsForView,
  revokeGrant,
  createPublicLink,
  listSharedWithMe,
  type ResourceType,
  type ViewOut,
  type ViewGrantOut,
  type GrantField,
  type GrantsMatrix,
  type PresetOut,
} from "@/api/endpoints/accountViews";

// ─── Constants ────────────────────────────────────────────────────────────────

const RESOURCE_TYPES: { value: ResourceType; label: string }[] = [
  { value: "wallet", label: "Wallet" },
  { value: "ledger_account", label: "Ledger Account" },
  { value: "payout_destination", label: "Payout Destination" },
];

const GRANT_LABELS: Record<GrantField, string> = {
  can_see_balance: "Balance",
  can_see_available_balance: "Available Balance",
  can_see_transaction_list: "Transaction List",
  can_see_transaction_amount: "Transaction Amount",
  can_see_transaction_description: "Transaction Description",
  can_see_counterparty: "Counterparty ID",
  can_see_counterparty_name: "Counterparty Name",
  can_see_owners: "Account Owners",
  can_see_account_label: "Account Label",
  can_see_payout_destination_masked: "Payout Destination (masked)",
  can_add_comment: "Add Comment",
  can_add_tag: "Add Tag",
  can_add_narrative: "Add Narrative",
  can_delete_comment: "Delete Comment",
};

function fmtTs(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

function presetBadgeVariant(preset: string | null): "default" | "secondary" | "outline" {
  if (!preset) return "outline";
  if (preset === "owner") return "default";
  if (preset === "public") return "secondary";
  return "outline";
}

// ─── Feature-off guard ────────────────────────────────────────────────────────

function FeatureOffBanner() {
  return (
    <div className="flex flex-col items-center justify-center py-24 gap-4 text-center">
      <AlertCircle className="h-12 w-12 text-muted-foreground" />
      <p className="text-lg font-semibold text-muted-foreground">Account Views not enabled</p>
      <p className="text-sm text-muted-foreground max-w-md">
        The Account Views feature (VEW-001..005) requires both the Open Bank Project and Account
        Views feature flags to be enabled on the server.
      </p>
    </div>
  );
}

// ─── Grants matrix editor ─────────────────────────────────────────────────────

interface GrantsEditorProps {
  fields: GrantField[];
  value: GrantsMatrix;
  onChange: (g: GrantsMatrix) => void;
  presets: PresetOut[];
}

function GrantsEditor({ fields, value, onChange, presets }: GrantsEditorProps) {
  function applyPreset(key: string) {
    const preset = presets.find((p) => p.key === key);
    if (preset) onChange(preset.grants);
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <Label className="text-xs text-muted-foreground">Apply preset:</Label>
        <Select onValueChange={applyPreset}>
          <SelectTrigger className="w-40 h-7 text-xs">
            <SelectValue placeholder="choose…" />
          </SelectTrigger>
          <SelectContent>
            {presets.map((p) => (
              <SelectItem key={p.key} value={p.key}>
                {p.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="grid grid-cols-2 gap-2">
        {fields.map((field) => (
          <label key={field} className="flex items-center gap-2 cursor-pointer text-sm">
            <Checkbox
              checked={!!value[field]}
              onCheckedChange={(checked) =>
                onChange({ ...value, [field]: !!checked })
              }
            />
            {GRANT_LABELS[field] ?? field}
          </label>
        ))}
      </div>
    </div>
  );
}

// ─── View card ────────────────────────────────────────────────────────────────

interface ViewCardProps {
  view: ViewOut;
  resourceType: ResourceType;
  resourceId: string;
  fields: GrantField[];
  presets: PresetOut[];
  onDeleted: () => void;
}

function ViewCard({ view, resourceType, resourceId, fields, presets, onDeleted }: ViewCardProps) {
  const qc = useQueryClient();
  const [showGrants, setShowGrants] = useState(false);
  const [showEdit, setShowEdit] = useState(false);
  const [showGrantForm, setShowGrantForm] = useState(false);
  const [showPublicLink, setShowPublicLink] = useState(false);

  const [editName, setEditName] = useState(view.name);
  const [editDesc, setEditDesc] = useState(view.description);
  const [editGrants, setEditGrants] = useState<GrantsMatrix>(view.grants);
  const [granteeInput, setGranteeInput] = useState("");
  const [publicLinkResult, setPublicLinkResult] = useState<{ url: string; expires_at: number } | null>(null);

  const grantsKey = ["account-views", "grants", resourceType, resourceId, view.view_id];

  const grantsQ = useQuery({
    queryKey: grantsKey,
    queryFn: () => listGrantsForView(resourceType, resourceId, view.view_id),
    enabled: showGrants,
  });

  const updateMut = useMutation({
    mutationFn: () =>
      updateView(resourceType, resourceId, view.view_id, {
        name: editName.trim(),
        description: editDesc.trim(),
        grants: editGrants,
      }),
    onSuccess: () => {
      toast.success("View updated");
      setShowEdit(false);
      void qc.invalidateQueries({ queryKey: ["account-views", "list", resourceType, resourceId] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to update view"),
  });

  const deleteMut = useMutation({
    mutationFn: () => deleteView(resourceType, resourceId, view.view_id),
    onSuccess: () => {
      toast.success("View deleted");
      onDeleted();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to delete view"),
  });

  const grantMut = useMutation({
    mutationFn: () => grantView(resourceType, resourceId, view.view_id, granteeInput.trim()),
    onSuccess: () => {
      toast.success("Access granted — pending acceptance");
      setGranteeInput("");
      setShowGrantForm(false);
      void qc.invalidateQueries({ queryKey: grantsKey });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to grant access"),
  });

  const revokeMut = useMutation({
    mutationFn: (granteeSub: string) =>
      revokeGrant(resourceType, resourceId, view.view_id, granteeSub),
    onSuccess: () => {
      toast.success("Grant revoked");
      void qc.invalidateQueries({ queryKey: grantsKey });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to revoke grant"),
  });

  const publicLinkMut = useMutation({
    mutationFn: () => createPublicLink(resourceType, resourceId, view.view_id),
    onSuccess: (res) => {
      setPublicLinkResult({ url: res.url, expires_at: res.expires_at });
      setShowPublicLink(true);
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to create public link"),
  });

  const activeGrantCount = grantsQ.data?.grants.filter((g) => g.status === "active").length ?? 0;
  const pendingGrantCount = grantsQ.data?.grants.filter((g) => g.status === "pending").length ?? 0;

  return (
    <Card className="flex flex-col">
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-2">
          <div className="space-y-1 min-w-0">
            <CardTitle className="text-base truncate">{view.name}</CardTitle>
            {view.description && (
              <CardDescription className="text-xs line-clamp-2">{view.description}</CardDescription>
            )}
          </div>
          <div className="flex gap-1 shrink-0">
            {view.preset && (
              <Badge variant={presetBadgeVariant(view.preset)} className="text-xs capitalize">
                {view.preset}
              </Badge>
            )}
            {view.is_system_alias && (
              <Badge variant="outline" className="text-xs">system</Badge>
            )}
          </div>
        </div>
      </CardHeader>

      <CardContent className="flex-1 space-y-3">
        {/* Granted fields summary */}
        <div className="flex flex-wrap gap-1">
          {Object.entries(view.grants)
            .filter(([, v]) => v)
            .slice(0, 4)
            .map(([k]) => (
              <Badge key={k} variant="outline" className="text-xs py-0">
                {GRANT_LABELS[k as GrantField] ?? k}
              </Badge>
            ))}
          {Object.values(view.grants).filter(Boolean).length > 4 && (
            <Badge variant="outline" className="text-xs py-0">
              +{Object.values(view.grants).filter(Boolean).length - 4} more
            </Badge>
          )}
        </div>

        <p className="text-xs text-muted-foreground">Created {fmtTs(view.created_at)}</p>

        {/* Action buttons */}
        <div className="flex flex-wrap gap-2 pt-1">
          {!view.is_system_alias && (
            <Button
              size="sm"
              variant="outline"
              className="h-7 text-xs"
              onClick={() => {
                setEditName(view.name);
                setEditDesc(view.description);
                setEditGrants(view.grants);
                setShowEdit(true);
              }}
            >
              Edit
            </Button>
          )}
          <Button
            size="sm"
            variant="outline"
            className="h-7 text-xs"
            onClick={() => setShowGrants((v) => !v)}
          >
            <UserPlus className="h-3 w-3 mr-1" />
            Delegates
          </Button>
          {view.preset === "public" && (
            <Button
              size="sm"
              variant="outline"
              className="h-7 text-xs"
              onClick={() => publicLinkMut.mutate()}
              disabled={publicLinkMut.isPending}
            >
              <Link2 className="h-3 w-3 mr-1" />
              Share link
            </Button>
          )}
          {!view.is_system_alias && (
            <Button
              size="sm"
              variant="destructive"
              className="h-7 text-xs"
              onClick={() => deleteMut.mutate()}
              disabled={deleteMut.isPending}
            >
              <Trash2 className="h-3 w-3" />
            </Button>
          )}
        </div>

        {/* Delegates panel */}
        {showGrants && (
          <div className="border rounded-md p-3 space-y-2 bg-muted/30">
            <div className="flex items-center justify-between">
              <p className="text-xs font-semibold">
                Delegates
                {grantsQ.data && (
                  <span className="ml-1 text-muted-foreground">
                    ({activeGrantCount} active{pendingGrantCount > 0 ? `, ${pendingGrantCount} pending` : ""})
                  </span>
                )}
              </p>
              <Button
                size="sm"
                variant="ghost"
                className="h-6 text-xs"
                onClick={() => setShowGrantForm((v) => !v)}
              >
                <Plus className="h-3 w-3 mr-1" /> Add
              </Button>
            </div>

            {showGrantForm && (
              <div className="flex gap-2">
                <Input
                  className="h-7 text-xs"
                  placeholder="User ID (sub)"
                  value={granteeInput}
                  onChange={(e) => setGranteeInput(e.target.value)}
                />
                <Button
                  size="sm"
                  className="h-7 text-xs"
                  onClick={() => grantMut.mutate()}
                  disabled={!granteeInput.trim() || grantMut.isPending}
                >
                  Grant
                </Button>
              </div>
            )}

            {grantsQ.isLoading && <Skeleton className="h-6 w-full" />}
            {grantsQ.data?.grants.map((g) => (
              <div key={g.grant_id} className="flex items-center justify-between gap-2 text-xs">
                <span className="truncate font-mono">{g.grantee_sub}</span>
                <div className="flex items-center gap-1 shrink-0">
                  <Badge
                    variant={g.status === "active" ? "default" : "secondary"}
                    className="text-xs py-0"
                  >
                    {g.status}
                  </Badge>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-5 w-5 p-0 text-destructive"
                    onClick={() => revokeMut.mutate(g.grantee_sub)}
                    disabled={revokeMut.isPending}
                  >
                    <Trash2 className="h-3 w-3" />
                  </Button>
                </div>
              </div>
            ))}
            {grantsQ.data?.grants.length === 0 && (
              <p className="text-xs text-muted-foreground">No delegates yet.</p>
            )}
          </div>
        )}
      </CardContent>

      {/* Edit view dialog */}
      <Dialog open={showEdit} onOpenChange={setShowEdit}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle>Edit View — {view.name}</DialogTitle>
            <DialogDescription>
              Update the name, description, and field permissions for this view.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-1">
              <Label>Name</Label>
              <Input value={editName} onChange={(e) => setEditName(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label>Description</Label>
              <Textarea
                value={editDesc}
                onChange={(e) => setEditDesc(e.target.value)}
                rows={2}
              />
            </div>
            <div className="space-y-1">
              <Label>Field permissions</Label>
              <GrantsEditor
                fields={fields}
                value={editGrants}
                onChange={setEditGrants}
                presets={presets}
              />
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setShowEdit(false)}>
                Cancel
              </Button>
              <Button
                onClick={() => updateMut.mutate()}
                disabled={!editName.trim() || updateMut.isPending}
              >
                Save changes
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Public link dialog */}
      <Dialog open={showPublicLink} onOpenChange={setShowPublicLink}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Public share link</DialogTitle>
            <DialogDescription>
              Anyone with this link can read the fields permitted by this view.
              Expires {publicLinkResult ? fmtTs(publicLinkResult.expires_at) : "—"}.
            </DialogDescription>
          </DialogHeader>
          {publicLinkResult && (
            <div className="space-y-3">
              <div className="break-all rounded-md bg-muted p-3 text-xs font-mono">
                {publicLinkResult.url}
              </div>
              <Button
                className="w-full"
                onClick={() => {
                  void navigator.clipboard.writeText(publicLinkResult.url);
                  toast.success("Link copied to clipboard");
                }}
              >
                Copy link
              </Button>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </Card>
  );
}

// ─── Create view dialog ───────────────────────────────────────────────────────

interface CreateViewDialogProps {
  open: boolean;
  onClose: () => void;
  resourceType: ResourceType;
  resourceId: string;
  fields: GrantField[];
  presets: PresetOut[];
}

function CreateViewDialog({
  open,
  onClose,
  resourceType,
  resourceId,
  fields,
  presets,
}: CreateViewDialogProps) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [grants, setGrants] = useState<GrantsMatrix>({});

  const createMut = useMutation({
    mutationFn: () =>
      createView(resourceType, resourceId, {
        name: name.trim(),
        description: description.trim(),
        grants,
      }),
    onSuccess: () => {
      toast.success("View created");
      setName("");
      setDescription("");
      setGrants({});
      onClose();
      void qc.invalidateQueries({
        queryKey: ["account-views", "list", resourceType, resourceId],
      });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to create view"),
  });

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>Create New View</DialogTitle>
          <DialogDescription>
            Define a named set of field permissions for{" "}
            <span className="font-mono text-xs">{resourceType}/{resourceId}</span>.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-1">
            <Label>Name *</Label>
            <Input
              placeholder="e.g. Accountant view"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label>Description</Label>
            <Textarea
              placeholder="Optional description…"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={2}
            />
          </div>
          <div className="space-y-1">
            <Label>Field permissions</Label>
            <GrantsEditor
              fields={fields}
              value={grants}
              onChange={setGrants}
              presets={presets}
            />
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button
              onClick={() => createMut.mutate()}
              disabled={!name.trim() || createMut.isPending}
            >
              Create view
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ─── Resource selector + view list ───────────────────────────────────────────

function ResourceViewsPanel({
  fields,
  presets,
}: {
  fields: GrantField[];
  presets: PresetOut[];
}) {
  const userId = useAuthStore((s) => s.userId ?? "");
  const [resourceType, setResourceType] = useState<ResourceType>("wallet");
  const [resourceId, setResourceId] = useState(userId);
  const [showCreate, setShowCreate] = useState(false);

  const viewsKey = ["account-views", "list", resourceType, resourceId];

  const viewsQ = useQuery({
    queryKey: viewsKey,
    queryFn: () => listViews(resourceType, resourceId),
    enabled: !!resourceId,
  });

  const qc = useQueryClient();

  return (
    <div className="space-y-4">
      {/* Resource selector */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm">Select Resource</CardTitle>
          <CardDescription className="text-xs">
            Choose the resource type and its ID to manage views.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="space-y-1 shrink-0">
              <Label className="text-xs">Resource type</Label>
              <Select
                value={resourceType}
                onValueChange={(v) => setResourceType(v as ResourceType)}
              >
                <SelectTrigger className="w-48">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {RESOURCE_TYPES.map((rt) => (
                    <SelectItem key={rt.value} value={rt.value}>
                      {rt.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex-1 space-y-1">
              <Label className="text-xs">Resource ID</Label>
              <Input
                placeholder="User sub or payout ID"
                value={resourceId}
                onChange={(e) => setResourceId(e.target.value)}
              />
            </div>
            <div className="flex items-end gap-2">
              <Button
                size="sm"
                variant="outline"
                onClick={() => void qc.invalidateQueries({ queryKey: viewsKey })}
              >
                <RefreshCw className="h-4 w-4" />
              </Button>
              <Button size="sm" onClick={() => setShowCreate(true)} disabled={!resourceId}>
                <Plus className="h-4 w-4 mr-1" /> New view
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Views grid */}
      {viewsQ.isLoading && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-48 rounded-lg" />
          ))}
        </div>
      )}

      {viewsQ.isError && !(viewsQ.error instanceof ApiError && viewsQ.error.status === 403) && (
        <div className="text-sm text-destructive">
          {viewsQ.error instanceof Error ? viewsQ.error.message : "Failed to load views"}
        </div>
      )}

      {viewsQ.isError && viewsQ.error instanceof ApiError && viewsQ.error.status === 403 && (
        <div className="rounded-md border border-muted p-4 text-sm text-muted-foreground">
          You are not the owner of this resource.
        </div>
      )}

      {viewsQ.data && viewsQ.data.length === 0 && (
        <div className="text-center py-12 text-muted-foreground text-sm">
          No views yet. Create one to start delegating access.
        </div>
      )}

      {viewsQ.data && viewsQ.data.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {viewsQ.data.map((view) => (
            <ViewCard
              key={view.view_id}
              view={view}
              resourceType={resourceType}
              resourceId={resourceId}
              fields={fields}
              presets={presets}
              onDeleted={() => void qc.invalidateQueries({ queryKey: viewsKey })}
            />
          ))}
        </div>
      )}

      <CreateViewDialog
        open={showCreate}
        onClose={() => setShowCreate(false)}
        resourceType={resourceType}
        resourceId={resourceId}
        fields={fields}
        presets={presets}
      />
    </div>
  );
}

// ─── Shared-with-me panel ─────────────────────────────────────────────────────

function SharedWithMePanel() {
  const sharedQ = useQuery({
    queryKey: ["account-views", "shared-with-me"],
    queryFn: () => listSharedWithMe({ limit: 50 }),
  });

  return (
    <div className="space-y-3">
      {sharedQ.isLoading && (
        <div className="space-y-2">
          {[1, 2].map((i) => (
            <Skeleton key={i} className="h-16 rounded-md" />
          ))}
        </div>
      )}
      {sharedQ.data?.grants.length === 0 && (
        <p className="text-sm text-muted-foreground py-8 text-center">
          No resources have been shared with you yet.
        </p>
      )}
      {sharedQ.data?.grants.map((g) => (
        <SharedGrantRow key={g.grant_id} grant={g} />
      ))}
    </div>
  );
}

interface SharedGrantRowProps {
  grant: ViewGrantOut;
}

function SharedGrantRow({ grant }: SharedGrantRowProps) {
  const qc = useQueryClient();

  const respondMut = useMutation({
    mutationFn: (accept: boolean) =>
      import("@/api/endpoints/accountViews").then(({ respondToGrant }) =>
        respondToGrant(
          grant.resource_type,
          grant.resource_id,
          grant.view_id,
          grant.grantee_sub,
          accept,
        ),
      ),
    onSuccess: (_data, accept) => {
      toast.success(accept ? "Access accepted" : "Access declined");
      void qc.invalidateQueries({ queryKey: ["account-views", "shared-with-me"] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to respond"),
  });

  return (
    <div className="flex items-center justify-between gap-3 rounded-md border px-4 py-3">
      <div className="space-y-0.5 min-w-0">
        <p className="text-sm font-medium capitalize">
          {grant.resource_type.replace(/_/g, " ")}
        </p>
        <p className="text-xs text-muted-foreground font-mono truncate">
          from {grant.owner_sub}
        </p>
        <p className="text-xs text-muted-foreground">Invited {fmtTs(grant.invited_at)}</p>
      </div>
      <div className="flex items-center gap-2 shrink-0">
        <Badge
          variant={grant.status === "active" ? "default" : "secondary"}
          className="text-xs"
        >
          {grant.status}
        </Badge>
        {grant.status === "pending" && (
          <>
            <Button
              size="sm"
              className="h-7 text-xs"
              onClick={() => respondMut.mutate(true)}
              disabled={respondMut.isPending}
            >
              Accept
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="h-7 text-xs"
              onClick={() => respondMut.mutate(false)}
              disabled={respondMut.isPending}
            >
              Decline
            </Button>
          </>
        )}
        {grant.status === "active" && (
          <Button
            size="sm"
            variant="ghost"
            className="h-7 text-xs"
            asChild
          >
            <a
              href={`/bank/views/read/${grant.resource_type}/${grant.resource_id}/${grant.view_id}`}
            >
              View data <ChevronRight className="h-3 w-3 ml-1" />
            </a>
          </Button>
        )}
      </div>
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

type Tab = "my-views" | "shared-with-me";

export default function AccountViewsPage() {
  const [tab, setTab] = useState<Tab>("my-views");

  const catalogQ = useQuery({
    queryKey: ["account-views", "catalog"],
    queryFn: getGrantCatalog,
    retry: false,
  });

  const featureOff =
    catalogQ.isError &&
    catalogQ.error instanceof ApiError &&
    (catalogQ.error.status === 404 || catalogQ.error.status === 503);

  if (catalogQ.isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-48 w-full rounded-lg" />
      </div>
    );
  }

  if (featureOff) {
    return (
      <div className="p-6">
        <PageHeader
          title="Account Views"
          description="Field-level access delegation for financial resources"
        />
        <FeatureOffBanner />
      </div>
    );
  }

  if (catalogQ.isError) {
    return (
      <div className="p-6">
        <PageHeader
          title="Account Views"
          description="Field-level access delegation for financial resources"
        />
        <p className="text-sm text-destructive">
          {catalogQ.error instanceof Error
            ? catalogQ.error.message
            : "Failed to load catalog"}
        </p>
      </div>
    );
  }

  const fields = (catalogQ.data?.fields ?? []) as GrantField[];
  const presets = catalogQ.data?.presets ?? [];

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        title="Account Views"
        description="Create named permission sets and delegate field-level access to other parties"
      />

      {/* Tab switcher */}
      <div className="flex gap-1 border-b">
        {(["my-views", "shared-with-me"] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              tab === t
                ? "border-primary text-primary"
                : "border-transparent text-muted-foreground hover:text-foreground"
            }`}
          >
            {t === "my-views" ? "My Views" : "Shared with Me"}
          </button>
        ))}
      </div>

      {tab === "my-views" && (
        <ResourceViewsPanel fields={fields} presets={presets} />
      )}
      {tab === "shared-with-me" && <SharedWithMePanel />}
    </div>
  );
}
