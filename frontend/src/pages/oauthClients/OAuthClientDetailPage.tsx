/**
 * OAU-001 / OAU-005: OAuth Consumer App Detail + Edit Page
 *
 * Shows full detail for a single consumer app, allows editing name/description/
 * redirect URIs/scopes, rotating the client secret, and enabling/disabling.
 */

import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  ArrowLeft,
  KeyRound,
  RefreshCw,
  Trash2,
  ToggleLeft,
  ToggleRight,
  RotateCcw,
  Save,
} from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Separator } from "@/components/ui/separator";
import { ApiError } from "@/api/client";
import {
  getOAuthConsumer,
  updateOAuthConsumer,
  deleteOAuthConsumer,
  enableOAuthConsumer,
  disableOAuthConsumer,
  rotateOAuthConsumerSecret,
  type OAuthConsumer,
  type OAuthSecretRotated,
} from "@/api/endpoints/oauthClients";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmt(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

const KNOWN_SCOPES = [
  "openid",
  "profile",
  "email",
  "offline_access",
  "read:accounts",
  "write:accounts",
  "read:transactions",
  "read:balances",
];

// ─── Edit form ────────────────────────────────────────────────────────────────

interface EditFormProps {
  consumer: OAuthConsumer;
  onSaved: () => void;
}

function EditForm({ consumer, onSaved }: EditFormProps) {
  const [name, setName] = useState(consumer.name);
  const [description, setDescription] = useState(consumer.description);
  const [redirectUrisRaw, setRedirectUrisRaw] = useState(
    consumer.redirect_uris.join("\n"),
  );
  const [selectedScopes, setSelectedScopes] = useState<string[]>(
    consumer.allowed_scopes,
  );

  const dirty =
    name !== consumer.name ||
    description !== consumer.description ||
    redirectUrisRaw !== consumer.redirect_uris.join("\n") ||
    JSON.stringify(selectedScopes.sort()) !==
      JSON.stringify([...consumer.allowed_scopes].sort());

  const saveMut = useMutation({
    mutationFn: () =>
      updateOAuthConsumer(consumer.client_id, {
        name: name.trim(),
        description: description.trim(),
        redirect_uris: redirectUrisRaw
          .split("\n")
          .map((u) => u.trim())
          .filter(Boolean),
        allowed_scopes: selectedScopes,
      }),
    onSuccess: () => {
      toast.success("Changes saved");
      onSaved();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Save failed"),
  });

  function toggleScope(scope: string) {
    setSelectedScopes((prev) =>
      prev.includes(scope) ? prev.filter((s) => s !== scope) : [...prev, scope],
    );
  }

  // Collect any scopes that are on the consumer but not in our known list
  const extraScopes = consumer.allowed_scopes.filter(
    (s) => !KNOWN_SCOPES.includes(s),
  );
  const allScopes = [...KNOWN_SCOPES, ...extraScopes];

  return (
    <div className="grid gap-4">
      <div className="grid gap-1.5">
        <Label htmlFor="detail-name">App name *</Label>
        <Input
          id="detail-name"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
      </div>

      <div className="grid gap-1.5">
        <Label htmlFor="detail-desc">Description</Label>
        <Input
          id="detail-desc"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
      </div>

      <div className="grid gap-1.5">
        <Label htmlFor="detail-uris">
          Redirect URIs <span className="text-muted-foreground">(one per line)</span>
        </Label>
        <Textarea
          id="detail-uris"
          rows={4}
          value={redirectUrisRaw}
          onChange={(e) => setRedirectUrisRaw(e.target.value)}
        />
      </div>

      <div className="grid gap-1.5">
        <Label>Allowed scopes</Label>
        <div className="grid grid-cols-2 gap-1.5">
          {allScopes.map((scope) => (
            <div key={scope} className="flex items-center gap-2">
              <Checkbox
                id={`edit-scope-${scope}`}
                checked={selectedScopes.includes(scope)}
                onCheckedChange={() => toggleScope(scope)}
              />
              <Label
                htmlFor={`edit-scope-${scope}`}
                className="font-normal text-sm cursor-pointer"
              >
                {scope}
              </Label>
            </div>
          ))}
        </div>
      </div>

      <div className="flex justify-end">
        <Button
          disabled={!dirty || saveMut.isPending || !name.trim()}
          onClick={() => saveMut.mutate()}
        >
          <Save className="h-4 w-4 mr-1" />
          {saveMut.isPending ? "Saving…" : "Save changes"}
        </Button>
      </div>
    </div>
  );
}

// ─── Rotated-secret reveal dialog ─────────────────────────────────────────────

interface RotatedSecretDialogProps {
  result: OAuthSecretRotated | null;
  onClose: () => void;
}

function RotatedSecretDialog({ result, onClose }: RotatedSecretDialogProps) {
  const [copied, setCopied] = useState(false);

  function copy() {
    if (!result?.client_secret) return;
    navigator.clipboard.writeText(result.client_secret).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <Dialog open={!!result} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>New client secret — save it now</DialogTitle>
          <DialogDescription>
            The previous secret is immediately invalid. This new secret is shown only once.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4 py-2">
          <div className="grid gap-1.5">
            <Label>New client secret</Label>
            <div className="flex gap-2">
              <code className="flex-1 rounded bg-muted px-2 py-1 text-sm break-all">
                {result?.client_secret}
              </code>
              <Button size="sm" variant="outline" onClick={copy}>
                {copied ? "Copied!" : "Copy"}
              </Button>
            </div>
          </div>
          <div className="grid gap-1.5">
            <Label>Prefix (shown in future)</Label>
            <code className="rounded bg-muted px-2 py-1 text-sm">
              {result?.client_secret_prefix}
            </code>
          </div>
        </div>

        <DialogFooter>
          <Button onClick={onClose}>Done</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function OAuthClientDetailPage() {
  const { clientId } = useParams<{ clientId: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();

  const [confirmDelete, setConfirmDelete] = useState(false);
  const [confirmRotate, setConfirmRotate] = useState(false);
  const [rotatedSecret, setRotatedSecret] = useState<OAuthSecretRotated | null>(null);

  const { data: consumer, isLoading, error, refetch } = useQuery({
    queryKey: ["oauth-client", clientId],
    queryFn: () => getOAuthConsumer(clientId!),
    enabled: !!clientId,
    retry: (failCount, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) return false;
      return failCount < 2;
    },
  });

  const deleteMut = useMutation({
    mutationFn: () => deleteOAuthConsumer(clientId!),
    onSuccess: () => {
      toast.success("App deleted");
      void qc.invalidateQueries({ queryKey: ["oauth-clients"] });
      navigate("/bank/oauth-clients");
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Delete failed"),
  });

  const toggleMut = useMutation({
    mutationFn: () =>
      consumer?.enabled
        ? disableOAuthConsumer(clientId!)
        : enableOAuthConsumer(clientId!),
    onSuccess: () => {
      toast.success(consumer?.enabled ? "App disabled" : "App enabled");
      void refetch();
      void qc.invalidateQueries({ queryKey: ["oauth-clients"] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Toggle failed"),
  });

  const rotateMut = useMutation({
    mutationFn: () => rotateOAuthConsumerSecret(clientId!),
    onSuccess: (result) => {
      toast.success("Secret rotated");
      setRotatedSecret(result);
      void refetch();
      void qc.invalidateQueries({ queryKey: ["oauth-clients"] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Rotation failed"),
  });

  // ── Loading / error states ─────────────────────────────────────────
  if (isLoading) {
    return (
      <div className="p-6 flex justify-center py-20">
        <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (error instanceof ApiError && (error.status === 404 || error.status === 503)) {
    return (
      <div className="p-6 space-y-4">
        <Button variant="ghost" size="sm" onClick={() => navigate("/bank/oauth-clients")}>
          <ArrowLeft className="h-4 w-4 mr-1" /> Back
        </Button>
        <Card>
          <CardContent className="pt-6 text-center py-12">
            <KeyRound className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
            <p className="font-medium">
              {error.status === 404
                ? "App not found or not owned by you."
                : "OAuth2 provider is not enabled on this instance."}
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!consumer) {
    return null;
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-2">
        <Button variant="ghost" size="sm" onClick={() => navigate("/bank/oauth-clients")}>
          <ArrowLeft className="h-4 w-4 mr-1" /> Back
        </Button>
      </div>

      <PageHeader
        title={consumer.name || "(unnamed app)"}
        description={`Client ID: ${consumer.client_id}`}
        actions={
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={toggleMut.isPending}
              onClick={() => toggleMut.mutate()}
            >
              {consumer.enabled ? (
                <>
                  <ToggleRight className="h-4 w-4 mr-1" /> Disable
                </>
              ) : (
                <>
                  <ToggleLeft className="h-4 w-4 mr-1" /> Enable
                </>
              )}
            </Button>
            <Button
              variant="destructive"
              size="sm"
              onClick={() => setConfirmDelete(true)}
            >
              <Trash2 className="h-4 w-4 mr-1" /> Delete
            </Button>
          </div>
        }
      />

      {/* Status strip */}
      <div className="flex flex-wrap gap-2 text-sm">
        <Badge variant={consumer.enabled ? "default" : "secondary"}>
          {consumer.enabled ? "Enabled" : "Disabled"}
        </Badge>
        <Badge variant="outline">
          {consumer.is_confidential ? "Confidential" : "Public (PKCE only)"}
        </Badge>
        <span className="text-muted-foreground">Created {fmt(consumer.created_at)}</span>
        {consumer.updated_at !== consumer.created_at && (
          <span className="text-muted-foreground">Updated {fmt(consumer.updated_at)}</span>
        )}
      </div>

      {/* Edit form */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">App configuration</CardTitle>
          <CardDescription>Edit the app name, description, redirect URIs, and allowed scopes.</CardDescription>
        </CardHeader>
        <CardContent>
          <EditForm
            consumer={consumer}
            onSaved={() => {
              void refetch();
              void qc.invalidateQueries({ queryKey: ["oauth-clients"] });
            }}
          />
        </CardContent>
      </Card>

      {/* Secret management */}
      {consumer.is_confidential && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Client secret</CardTitle>
            <CardDescription>
              Rotate the secret if it has been compromised. The old secret is immediately invalidated.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-center gap-4 text-sm">
              <span className="text-muted-foreground w-32">Current prefix</span>
              <code className="rounded bg-muted px-2 py-0.5">{consumer.client_secret_prefix}</code>
            </div>
            {consumer.secret_rotated_at > 0 && (
              <div className="flex items-center gap-4 text-sm">
                <span className="text-muted-foreground w-32">Last rotated</span>
                <span>{fmt(consumer.secret_rotated_at)}</span>
              </div>
            )}
            <Separator />
            <Button
              variant="outline"
              size="sm"
              disabled={rotateMut.isPending}
              onClick={() => setConfirmRotate(true)}
            >
              <RotateCcw className="h-4 w-4 mr-1" />
              {rotateMut.isPending ? "Rotating…" : "Rotate secret"}
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Redirect URIs (read-only list) */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Registered redirect URIs</CardTitle>
        </CardHeader>
        <CardContent>
          <ul className="space-y-1">
            {consumer.redirect_uris.map((uri) => (
              <li key={uri} className="text-sm font-mono break-all">{uri}</li>
            ))}
          </ul>
        </CardContent>
      </Card>

      {/* Delete confirm */}
      <Dialog open={confirmDelete} onOpenChange={setConfirmDelete}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete "{consumer.name}"?</DialogTitle>
            <DialogDescription>
              This is irreversible. All tokens issued to this app will stop working immediately.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmDelete(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={deleteMut.isPending}
              onClick={() => deleteMut.mutate()}
            >
              {deleteMut.isPending ? "Deleting…" : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Rotate confirm */}
      <Dialog open={confirmRotate} onOpenChange={setConfirmRotate}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rotate client secret?</DialogTitle>
            <DialogDescription>
              The current secret will be permanently invalidated and any running apps using it will
              fail until reconfigured with the new secret.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmRotate(false)}>
              Cancel
            </Button>
            <Button
              disabled={rotateMut.isPending}
              onClick={() => {
                setConfirmRotate(false);
                rotateMut.mutate();
              }}
            >
              {rotateMut.isPending ? "Rotating…" : "Rotate secret"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Show new secret after rotation */}
      <RotatedSecretDialog
        result={rotatedSecret}
        onClose={() => setRotatedSecret(null)}
      />
    </div>
  );
}
