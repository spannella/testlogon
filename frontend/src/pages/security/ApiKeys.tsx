import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Key, Plus, Trash2, Copy, Check, AlertTriangle, Globe, Download } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import { EmptyState } from "@/components/shared/EmptyState";
import { getApiKeys, createApiKey, revokeApiKey, setApiKeyIpRules } from "@/api/endpoints/account";

export function ApiKeys() {
  const queryClient = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [label, setLabel] = useState("");
  const [expiresInDays, setExpiresInDays] = useState<string>("none");
  const [createdKey, setCreatedKey] = useState<{ key_id: string; key_secret: string; label: string; expiresInDays: string } | null>(null);
  const [copiedField, setCopiedField] = useState<"key_id" | "key_secret" | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<string | null>(null);
  const [ipRulesTarget, setIpRulesTarget] = useState<string | null>(null);
  const [allowCidrs, setAllowCidrs] = useState("");
  const [denyCidrs, setDenyCidrs] = useState("");

  const keysQuery = useQuery({
    queryKey: ["apiKeys"],
    queryFn: getApiKeys,
  });

  const createMutation = useMutation({
    mutationFn: () => createApiKey({
      label: label || undefined,
      expires_in_days: expiresInDays === "none" ? undefined : Number(expiresInDays),
    }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["apiKeys"] });
      setCreatedKey({ key_id: data.key_id, key_secret: data.key_secret, label, expiresInDays });
      setLabel("");
      setExpiresInDays("none");
    },
    onError: () => toast.error("Failed to create API key"),
  });

  const revokeMutation = useMutation({
    mutationFn: (keyId: string) => revokeApiKey({ key_id: keyId }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["apiKeys"] });
      toast.success("API key revoked");
      setRevokeTarget(null);
    },
    onError: () => toast.error("Failed to revoke API key"),
  });

  const ipRulesMutation = useMutation({
    mutationFn: () =>
      setApiKeyIpRules({
        key_id: ipRulesTarget ?? "",
        allow_cidrs: allowCidrs.split("\n").map((s) => s.trim()).filter(Boolean),
        deny_cidrs: denyCidrs.split("\n").map((s) => s.trim()).filter(Boolean),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["apiKeys"] });
      toast.success("IP rules updated");
      setIpRulesTarget(null);
      setAllowCidrs("");
      setDenyCidrs("");
    },
    onError: () => toast.error("Failed to update IP rules"),
  });

  const handleDownload = () => {
    if (!createdKey) return;
    const lines = [
      "API Key Details",
      "===============",
      "",
      `Label:      ${createdKey.label || "(none)"}`,
      `Key ID:     ${createdKey.key_id}`,
      `Secret Key: ${createdKey.key_secret}`,
      "",
      `Created:    ${new Date().toLocaleString()}`,
      createdKey.expiresInDays !== "none" ? `Expires in: ${createdKey.expiresInDays} days` : "Expires:    Never",
      "",
      "IMPORTANT: Store this file securely and delete it after saving your credentials.",
      "The Secret Key will not be shown again.",
    ];
    const blob = new Blob([lines.join("\n")], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const prefix = createdKey.key_id.slice(0, 8);
    a.download = `api-key-${prefix}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const keys = keysQuery.data?.keys ?? [];

  const handleCopy = async (field: "key_id" | "key_secret") => {
    const text = field === "key_id" ? createdKey?.key_id : createdKey?.key_secret;
    if (!text) return;

    if (!window.isSecureContext) {
      toast.error("Clipboard copy requires HTTPS. Use the Download button to save your key.");
      return;
    }

    try {
      await navigator.clipboard.writeText(text);
      setCopiedField(field);
      toast.success("Copied to clipboard");
      setTimeout(() => setCopiedField(null), 2000);
    } catch {
      toast.error("Copy failed — use the Download button instead");
    }
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Key className="h-5 w-5 text-muted-foreground" />
            <CardTitle className="text-base">API Keys</CardTitle>
          </div>
          <Button
            size="sm"
            variant="outline"
            onClick={() => { setCreateOpen(true); setCreatedKey(null); setCopiedField(null); setLabel(""); setExpiresInDays("none"); }}
          >
            <Plus className="mr-1 h-3.5 w-3.5" />
            Create Key
          </Button>
        </div>
        <CardDescription>Manage API keys for programmatic access</CardDescription>
      </CardHeader>
      <CardContent>
        {keysQuery.isLoading ? (
          <div className="space-y-2">
            <Skeleton className="h-14 w-full" />
            <Skeleton className="h-14 w-full" />
          </div>
        ) : keys.length === 0 ? (
          <EmptyState
            icon={<Key className="h-8 w-8" />}
            title="No API keys"
            description="Create an API key to access the platform programmatically."
          />
        ) : (
          <ul className="divide-y">
            {keys.map((k) => (
              <li key={k.key_id} className="flex items-center justify-between gap-4 py-3">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-medium">{k.label ?? "Unnamed key"}</p>
                    {k.prefix && (
                      <code className="text-xs text-muted-foreground">{k.prefix}…</code>
                    )}
                  </div>
                  <div className="mt-0.5 flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                    <span>Created {new Date(k.created_at * 1000).toLocaleDateString()}</span>
                    {k.expires_at > 0 && (
                      <Badge variant="secondary" className="text-[10px]">
                        Expires {new Date(k.expires_at * 1000).toLocaleDateString()}
                      </Badge>
                    )}
                    {k.last_used_at > 0 && (
                      <span>Last used {new Date(k.last_used_at * 1000).toLocaleDateString()}</span>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  <Button
                    size="icon"
                    variant="ghost"
                    onClick={() => {
                      setIpRulesTarget(k.key_id);
                      setAllowCidrs((k.allow_cidrs ?? []).join("\n"));
                      setDenyCidrs((k.deny_cidrs ?? []).join("\n"));
                    }}
                    aria-label="Manage IP rules"
                  >
                    <Globe className="h-4 w-4" />
                  </Button>
                  <Button
                    size="icon"
                    variant="ghost"
                    onClick={() => setRevokeTarget(k.key_id)}
                    aria-label="Revoke key"
                  >
                    <Trash2 className="h-4 w-4 text-destructive" />
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardContent>

      {/* Create key dialog */}
      <Dialog open={createOpen} onOpenChange={(o) => { if (!o) { setCreateOpen(false); setCreatedKey(null); } }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{createdKey ? "API Key Created" : "Create API Key"}</DialogTitle>
            <DialogDescription>
              {createdKey
                ? "Save both values now — the secret won't be shown again."
                : "Give your key an optional label for identification."}
            </DialogDescription>
          </DialogHeader>
          {createdKey ? (
            <div className="space-y-3">
              {([
                { label: "Key ID", field: "key_id" as const, value: createdKey.key_id },
                { label: "Secret Key", field: "key_secret" as const, value: createdKey.key_secret },
              ]).map(({ label: fieldLabel, field, value }) => (
                <div key={field}>
                  <p className="mb-1 text-xs font-medium text-muted-foreground">{fieldLabel}</p>
                  <div className="flex items-center gap-2 rounded-lg border bg-muted/50 p-3">
                    <code className="flex-1 break-all text-xs font-mono">{value}</code>
                    <Button
                      size="icon"
                      variant="ghost"
                      onClick={() => handleCopy(field)}
                      aria-label={`Copy ${fieldLabel}`}
                      className={copiedField === field ? "text-green-500" : ""}
                    >
                      {copiedField === field
                        ? <Check className="h-4 w-4" />
                        : <Copy className="h-4 w-4" />}
                    </Button>
                  </div>
                </div>
              ))}
              <div className="flex items-center gap-2 rounded-lg border border-amber-200 bg-amber-50 p-2 text-xs text-amber-800 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-200">
                <AlertTriangle className="h-4 w-4 shrink-0" />
                <span>The Secret Key is shown only once. Store it securely.</span>
              </div>
              <DialogFooter className="gap-2">
                <Button variant="outline" onClick={handleDownload}>
                  <Download className="mr-1 h-4 w-4" />
                  Download
                </Button>
                <Button onClick={() => setCreateOpen(false)}>Done</Button>
              </DialogFooter>
            </div>
          ) : (
            <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate(); }} className="space-y-3">
              <div>
                <Label htmlFor="key-label">Label (optional)</Label>
                <Input
                  id="key-label"
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                  placeholder="e.g. CI/CD Pipeline"
                  autoFocus
                />
              </div>
              <div>
                <Label htmlFor="key-expiry">Expiry</Label>
                <Select value={expiresInDays} onValueChange={setExpiresInDays}>
                  <SelectTrigger id="key-expiry" className="mt-1">
                    <SelectValue placeholder="No expiry" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">No expiry</SelectItem>
                    <SelectItem value="30">30 days</SelectItem>
                    <SelectItem value="90">90 days</SelectItem>
                    <SelectItem value="180">180 days</SelectItem>
                    <SelectItem value="365">1 year</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <DialogFooter>
                <Button type="submit" disabled={createMutation.isPending}>
                  {createMutation.isPending ? "Creating..." : "Create Key"}
                </Button>
              </DialogFooter>
            </form>
          )}
        </DialogContent>
      </Dialog>

      {/* Revoke dialog */}
      <ConfirmDialog
        open={!!revokeTarget}
        onOpenChange={(o) => { if (!o) setRevokeTarget(null); }}
        title="Revoke API Key"
        description="This key will immediately stop working. This action cannot be undone."
        variant="danger"
        confirmLabel="Revoke Key"
        onConfirm={() => { if (revokeTarget) revokeMutation.mutate(revokeTarget); }}
        loading={revokeMutation.isPending}
      />

      {/* IP rules dialog */}
      <Dialog open={!!ipRulesTarget} onOpenChange={(o) => { if (!o) setIpRulesTarget(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>IP Access Rules</DialogTitle>
            <DialogDescription>
              Restrict this API key to specific IP ranges using CIDR notation (one per line).
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={(e) => { e.preventDefault(); ipRulesMutation.mutate(); }} className="space-y-3">
            <div>
              <Label htmlFor="allow-cidrs">Allow CIDRs</Label>
              <textarea
                id="allow-cidrs"
                className="mt-1 flex min-h-[80px] w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                value={allowCidrs}
                onChange={(e) => setAllowCidrs(e.target.value)}
                placeholder="10.0.0.0/8&#10;192.168.1.0/24"
              />
            </div>
            <div>
              <Label htmlFor="deny-cidrs">Deny CIDRs</Label>
              <textarea
                id="deny-cidrs"
                className="mt-1 flex min-h-[80px] w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                value={denyCidrs}
                onChange={(e) => setDenyCidrs(e.target.value)}
                placeholder="0.0.0.0/0"
              />
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setIpRulesTarget(null)}>Cancel</Button>
              <Button type="submit" disabled={ipRulesMutation.isPending}>
                {ipRulesMutation.isPending ? "Saving..." : "Save Rules"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
