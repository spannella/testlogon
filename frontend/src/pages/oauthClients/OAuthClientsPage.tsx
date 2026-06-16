/**
 * OAU-001 / OAU-005: OAuth2/OIDC Consumer App Registry
 *
 * Displays all consumer apps registered by the current user, lets them
 * register new apps, and links to detail/edit. Gracefully handles the
 * feature-flag-off (404/503) case.
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Plus, KeyRound, RefreshCw, Trash2, ToggleLeft, ToggleRight, ChevronRight } from "lucide-react";
import { Link } from "react-router-dom";

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
import { ApiError } from "@/api/client";
import {
  listOAuthConsumers,
  createOAuthConsumer,
  deleteOAuthConsumer,
  enableOAuthConsumer,
  disableOAuthConsumer,
  type OAuthConsumer,
  type OAuthConsumerCreated,
} from "@/api/endpoints/oauthClients";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmt(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

// ─── Register dialog ──────────────────────────────────────────────────────────

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

interface RegisterDialogProps {
  open: boolean;
  onClose: () => void;
  onSuccess: (result: OAuthConsumerCreated) => void;
}

function RegisterDialog({ open, onClose, onSuccess }: RegisterDialogProps) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [redirectUrisRaw, setRedirectUrisRaw] = useState("");
  const [selectedScopes, setSelectedScopes] = useState<string[]>(["openid", "profile", "email"]);
  const [isConfidential, setIsConfidential] = useState(true);

  const mut = useMutation({
    mutationFn: () =>
      createOAuthConsumer({
        name: name.trim(),
        description: description.trim(),
        redirect_uris: redirectUrisRaw
          .split("\n")
          .map((u) => u.trim())
          .filter(Boolean),
        allowed_scopes: selectedScopes,
        is_confidential: isConfidential,
      }),
    onSuccess: (result) => {
      toast.success("OAuth app registered");
      onSuccess(result);
      handleClose();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to register app"),
  });

  function handleClose() {
    setName("");
    setDescription("");
    setRedirectUrisRaw("");
    setSelectedScopes(["openid", "profile", "email"]);
    setIsConfidential(true);
    onClose();
  }

  function toggleScope(scope: string) {
    setSelectedScopes((prev) =>
      prev.includes(scope) ? prev.filter((s) => s !== scope) : [...prev, scope],
    );
  }

  return (
    <Dialog open={open} onOpenChange={(v) => !v && handleClose()}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Register OAuth App</DialogTitle>
          <DialogDescription>
            Create a new OAuth2/OIDC consumer application. You will see the client secret once.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4 py-2">
          <div className="grid gap-1.5">
            <Label htmlFor="oa-name">App name *</Label>
            <Input
              id="oa-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="My Integration"
            />
          </div>

          <div className="grid gap-1.5">
            <Label htmlFor="oa-desc">Description</Label>
            <Input
              id="oa-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Optional description"
            />
          </div>

          <div className="grid gap-1.5">
            <Label htmlFor="oa-uris">
              Redirect URIs <span className="text-muted-foreground">(one per line)</span>
            </Label>
            <Textarea
              id="oa-uris"
              rows={3}
              value={redirectUrisRaw}
              onChange={(e) => setRedirectUrisRaw(e.target.value)}
              placeholder={"https://myapp.example.com/callback\nhttps://localhost:3001/callback"}
            />
          </div>

          <div className="grid gap-1.5">
            <Label>Allowed scopes</Label>
            <div className="grid grid-cols-2 gap-1.5">
              {KNOWN_SCOPES.map((scope) => (
                <div key={scope} className="flex items-center gap-2">
                  <Checkbox
                    id={`scope-${scope}`}
                    checked={selectedScopes.includes(scope)}
                    onCheckedChange={() => toggleScope(scope)}
                  />
                  <Label htmlFor={`scope-${scope}`} className="font-normal text-sm cursor-pointer">
                    {scope}
                  </Label>
                </div>
              ))}
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Checkbox
              id="oa-confidential"
              checked={isConfidential}
              onCheckedChange={(v) => setIsConfidential(!!v)}
            />
            <Label htmlFor="oa-confidential" className="font-normal cursor-pointer">
              Confidential client (has client_secret)
            </Label>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={handleClose}>
            Cancel
          </Button>
          <Button
            disabled={mut.isPending || !name.trim() || !redirectUrisRaw.trim()}
            onClick={() => mut.mutate()}
          >
            {mut.isPending ? "Registering…" : "Register App"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Secret reveal dialog ─────────────────────────────────────────────────────

interface SecretRevealDialogProps {
  result: OAuthConsumerCreated | null;
  onClose: () => void;
}

function SecretRevealDialog({ result, onClose }: SecretRevealDialogProps) {
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
          <DialogTitle>App registered — save your secret</DialogTitle>
          <DialogDescription>
            This is the only time the client secret will be shown. Copy it now.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4 py-2">
          <div className="grid gap-1.5">
            <Label>Client ID</Label>
            <code className="rounded bg-muted px-2 py-1 text-sm break-all">{result?.client_id}</code>
          </div>
          {result?.client_secret && (
            <div className="grid gap-1.5">
              <Label>Client Secret (one-time)</Label>
              <div className="flex gap-2">
                <code className="flex-1 rounded bg-muted px-2 py-1 text-sm break-all">
                  {result.client_secret}
                </code>
                <Button size="sm" variant="outline" onClick={copy}>
                  {copied ? "Copied!" : "Copy"}
                </Button>
              </div>
            </div>
          )}
          {result?.client_secret === "" && (
            <p className="text-sm text-muted-foreground">
              This is a public (PKCE-only) client — no client secret is issued.
            </p>
          )}
        </div>

        <DialogFooter>
          <Button onClick={onClose}>Done</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Consumer row ─────────────────────────────────────────────────────────────

interface ConsumerRowProps {
  consumer: OAuthConsumer;
  onDeleted: () => void;
  onToggled: () => void;
}

function ConsumerRow({ consumer, onDeleted, onToggled }: ConsumerRowProps) {
  const [confirmDelete, setConfirmDelete] = useState(false);

  const deleteMut = useMutation({
    mutationFn: () => deleteOAuthConsumer(consumer.client_id),
    onSuccess: () => {
      toast.success("App deleted");
      onDeleted();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Delete failed"),
  });

  const toggleMut = useMutation({
    mutationFn: () =>
      consumer.enabled
        ? disableOAuthConsumer(consumer.client_id)
        : enableOAuthConsumer(consumer.client_id),
    onSuccess: () => {
      toast.success(consumer.enabled ? "App disabled" : "App enabled");
      onToggled();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Toggle failed"),
  });

  return (
    <>
      <div className="flex items-center justify-between gap-4 rounded-lg border px-4 py-3 hover:bg-muted/40 transition-colors">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <KeyRound className="h-4 w-4 text-muted-foreground shrink-0" />
            <span className="font-medium truncate">{consumer.name || "(unnamed)"}</span>
            <Badge variant={consumer.enabled ? "default" : "secondary"} className="shrink-0">
              {consumer.enabled ? "enabled" : "disabled"}
            </Badge>
            {consumer.is_confidential ? null : (
              <Badge variant="outline" className="shrink-0 text-xs">public</Badge>
            )}
          </div>
          <div className="mt-1 flex flex-wrap gap-x-4 gap-y-0.5 text-xs text-muted-foreground">
            <span>
              <span className="font-mono">{consumer.client_id}</span>
            </span>
            <span>prefix: <span className="font-mono">{consumer.client_secret_prefix}</span></span>
            <span>created {fmt(consumer.created_at)}</span>
          </div>
          {consumer.description && (
            <p className="mt-0.5 text-xs text-muted-foreground truncate">{consumer.description}</p>
          )}
          <div className="mt-1 flex flex-wrap gap-1">
            {consumer.allowed_scopes.map((s) => (
              <Badge key={s} variant="outline" className="text-xs px-1.5 py-0">
                {s}
              </Badge>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-1 shrink-0">
          <Button
            size="icon"
            variant="ghost"
            title={consumer.enabled ? "Disable app" : "Enable app"}
            disabled={toggleMut.isPending}
            onClick={() => toggleMut.mutate()}
          >
            {consumer.enabled ? (
              <ToggleRight className="h-4 w-4" />
            ) : (
              <ToggleLeft className="h-4 w-4 text-muted-foreground" />
            )}
          </Button>

          <Button
            size="icon"
            variant="ghost"
            title="Delete app"
            onClick={() => setConfirmDelete(true)}
          >
            <Trash2 className="h-4 w-4 text-destructive" />
          </Button>

          <Link to={`/bank/oauth-clients/${consumer.client_id}`}>
            <Button size="icon" variant="ghost" title="View / edit">
              <ChevronRight className="h-4 w-4" />
            </Button>
          </Link>
        </div>
      </div>

      {/* Delete confirm dialog */}
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
    </>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function OAuthClientsPage() {
  const qc = useQueryClient();
  const [showRegister, setShowRegister] = useState(false);
  const [newApp, setNewApp] = useState<OAuthConsumerCreated | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ["oauth-clients"],
    queryFn: listOAuthConsumers,
    retry: (failCount, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) return false;
      return failCount < 2;
    },
  });

  function invalidate() {
    void qc.invalidateQueries({ queryKey: ["oauth-clients"] });
  }

  // ── Feature flag off ──────────────────────────────────────────────
  if (error instanceof ApiError && (error.status === 404 || error.status === 503)) {
    return (
      <div className="p-6 space-y-4">
        <PageHeader
          title="OAuth2/OIDC Apps"
          description="Developer + consumer app registry"
        />
        <Card>
          <CardContent className="pt-6">
            <div className="flex flex-col items-center gap-2 py-10 text-center">
              <KeyRound className="h-10 w-10 text-muted-foreground" />
              <p className="text-muted-foreground">
                The Open Bank Project OAuth2 provider is not enabled on this instance.
              </p>
              <p className="text-xs text-muted-foreground">
                Set <code>OPEN_BANK_PROJECT_ENABLED=true</code> and{" "}
                <code>OAUTH_PROVIDER_ENABLED=1</code> to activate.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  const consumers: OAuthConsumer[] = data ?? [];

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        title="OAuth2/OIDC Apps"
        description="Manage consumer applications that access the Open Bank Project API on behalf of users."
        actions={
          <Button onClick={() => setShowRegister(true)}>
            <Plus className="h-4 w-4 mr-1" />
            Register App
          </Button>
        }
      />

      {/* OIDC discovery info */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base">Authorization Server</CardTitle>
          <CardDescription>
            Use these endpoints in your OAuth2/OIDC client configuration.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-1 text-sm">
            <div className="flex gap-2">
              <span className="text-muted-foreground w-40 shrink-0">Discovery URL</span>
              <code className="break-all">{window.location.origin}/.well-known/openid-configuration</code>
            </div>
            <div className="flex gap-2">
              <span className="text-muted-foreground w-40 shrink-0">Token endpoint</span>
              <code className="break-all">{window.location.origin}/oauth/token</code>
            </div>
            <div className="flex gap-2">
              <span className="text-muted-foreground w-40 shrink-0">Auth endpoint</span>
              <code className="break-all">{window.location.origin}/oauth/authorize</code>
            </div>
            <div className="flex gap-2">
              <span className="text-muted-foreground w-40 shrink-0">JWKS URI</span>
              <code className="break-all">{window.location.origin}/oauth/jwks</code>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* App list */}
      <div className="space-y-2">
        {isLoading && (
          <div className="flex justify-center py-10">
            <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        )}

        {!isLoading && error && !(error instanceof ApiError && (error.status === 404 || error.status === 503)) && (
          <Card>
            <CardContent className="pt-6 text-center text-sm text-destructive">
              Failed to load apps: {error instanceof Error ? error.message : "Unknown error"}
            </CardContent>
          </Card>
        )}

        {!isLoading && !error && consumers.length === 0 && (
          <Card>
            <CardContent className="pt-6">
              <div className="flex flex-col items-center gap-2 py-10 text-center">
                <KeyRound className="h-10 w-10 text-muted-foreground" />
                <p className="font-medium">No apps registered yet</p>
                <p className="text-sm text-muted-foreground">
                  Register your first OAuth2 consumer app to get started.
                </p>
                <Button className="mt-2" onClick={() => setShowRegister(true)}>
                  <Plus className="h-4 w-4 mr-1" />
                  Register App
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        {consumers.map((c) => (
          <ConsumerRow
            key={c.client_id}
            consumer={c}
            onDeleted={invalidate}
            onToggled={invalidate}
          />
        ))}
      </div>

      {/* Dialogs */}
      <RegisterDialog
        open={showRegister}
        onClose={() => setShowRegister(false)}
        onSuccess={(result) => {
          invalidate();
          setNewApp(result);
        }}
      />

      <SecretRevealDialog
        result={newApp}
        onClose={() => setNewApp(null)}
      />
    </div>
  );
}
