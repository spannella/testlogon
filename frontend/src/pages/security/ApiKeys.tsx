import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Key, Plus, Trash2, Copy, Check, AlertTriangle, Globe, Download, Info, X, BarChart2, Shield } from "lucide-react";
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
import { getApiKeys, createApiKey, revokeApiKey, setApiKeyIpRules, getApiKeyUsage } from "@/api/endpoints/account";
import type { ApiKey } from "@/api/types";

// ─── Capability scopes (mirrors app/services/api_key_capabilities.py) ──

const SCOPE_GROUPS: { label: string; scopes: string[] }[] = [
  { label: "Advertising", scopes: ["ads:manage", "ads:read", "ads:serve"] },
  { label: "File Manager", scopes: ["filemanager:admin", "filemanager:read", "filemanager:share", "filemanager:write"] },
  { label: "KYC", scopes: ["kyc:admin", "kyc:read", "kyc:submit", "kyc:upload", "kyc:webhook"] },
  { label: "Messaging", scopes: ["messager:manage", "messager:read", "messager:write"] },
  { label: "Newsfeed", scopes: ["newsfeed:moderate", "newsfeed:read", "newsfeed:write"] },
  { label: "Shopping", scopes: ["shopping:cart:write", "shopping:catalog:read", "shopping:checkout:write", "shopping:orders:read"] },
  { label: "Tickets", scopes: ["tickets:admin", "tickets:read", "tickets:write"] },
];

// ─── CIDR list editor ────────────────────────────────────────────

function CidrList({
  label,
  items,
  onAdd,
  onRemove,
  inputValue,
  onInputChange,
  placeholder,
}: {
  label: string;
  items: string[];
  onAdd: () => void;
  onRemove: (idx: number) => void;
  inputValue: string;
  onInputChange: (v: string) => void;
  placeholder?: string;
}) {
  const inputId = `cidr-input-${label.toLowerCase().replace(/\s+/g, "-")}`;
  return (
    <div className="space-y-2">
      <Label htmlFor={inputId}>{label}</Label>
      <div className="space-y-1.5">
        {items.map((cidr, i) => (
          <div key={i} className="flex items-center gap-2 rounded-md border border-input bg-muted/30 px-3 py-1.5">
            <code className="flex-1 text-xs font-mono">{cidr}</code>
            <button
              type="button"
              onClick={() => onRemove(i)}
              className="text-muted-foreground hover:text-destructive"
              aria-label={`Remove ${cidr}`}
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        ))}
        {items.length === 0 && (
          <p className="text-xs text-muted-foreground italic">No rules — all IPs {label.toLowerCase().includes("allow") ? "allowed" : "denied"} by default</p>
        )}
      </div>
      <div className="flex gap-2">
        <Input
          id={inputId}
          value={inputValue}
          onChange={(e) => onInputChange(e.target.value)}
          placeholder={placeholder ?? "e.g. 10.0.0.0/8"}
          className="h-8 flex-1 font-mono text-xs"
          onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); onAdd(); } }}
        />
        <Button type="button" size="sm" variant="outline" className="h-8 shrink-0" onClick={onAdd}>
          <Plus className="h-3.5 w-3.5" />
          Add
        </Button>
      </div>
    </div>
  );
}

// ─── Key details dialog ──────────────────────────────────────────

function KeyDetailsDialog({
  keyData,
  onClose,
  onOpenIpRules,
}: {
  keyData: ApiKey;
  onClose: () => void;
  onOpenIpRules: () => void;
}) {
  const usageQuery = useQuery({
    queryKey: ["apiKeyUsage", keyData.key_id],
    queryFn: () => getApiKeyUsage(keyData.key_id),
    staleTime: 60_000,
  });

  const usage = usageQuery.data;

  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Key className="h-4 w-4" />
            {keyData.label ?? "Unnamed key"}
          </DialogTitle>
          <DialogDescription>
            <code className="text-xs">{keyData.prefix}…</code>
            {" · "}
            Created {new Date(keyData.created_at * 1000).toLocaleDateString()}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {/* Usage stats */}
          <div>
            <div className="mb-2 flex items-center gap-1.5 text-sm font-medium">
              <BarChart2 className="h-4 w-4 text-muted-foreground" />
              Usage {usage?.period ? `(${usage.period})` : ""}
            </div>
            {usageQuery.isLoading ? (
              <div className="space-y-1.5">
                <Skeleton className="h-8 w-full" />
                <Skeleton className="h-8 w-full" />
              </div>
            ) : usage ? (
              <div className="grid grid-cols-2 gap-2">
                <div className="rounded-lg border border-border bg-muted/30 p-3">
                  <p className="text-xs text-muted-foreground">Total calls</p>
                  <p className="text-lg font-semibold">{usage.calls.toLocaleString()}</p>
                </div>
                <div className="rounded-lg border border-border bg-muted/30 p-3">
                  <p className="text-xs text-muted-foreground">Billable calls</p>
                  <p className="text-lg font-semibold">{usage.billable_calls.toLocaleString()}</p>
                </div>
                <div className="rounded-lg border border-border bg-muted/30 p-3">
                  <p className="text-xs text-muted-foreground">Spend</p>
                  <p className="text-lg font-semibold">${(usage.spend_cents / 100).toFixed(2)}</p>
                </div>
                {usage.limit_calls != null && (
                  <div className="rounded-lg border border-border bg-muted/30 p-3">
                    <p className="text-xs text-muted-foreground">Remaining</p>
                    <p className="text-lg font-semibold">
                      {(usage.remaining_calls ?? 0).toLocaleString()}
                      <span className="text-xs text-muted-foreground"> / {usage.limit_calls.toLocaleString()}</span>
                    </p>
                  </div>
                )}
              </div>
            ) : (
              <p className="text-xs text-muted-foreground">No usage data available</p>
            )}
          </div>

          {/* IP rules summary */}
          <div>
            <div className="mb-2 flex items-center justify-between">
              <div className="flex items-center gap-1.5 text-sm font-medium">
                <Shield className="h-4 w-4 text-muted-foreground" />
                IP Rules
              </div>
              <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => { onClose(); onOpenIpRules(); }}>
                <Globe className="mr-1 h-3 w-3" />
                Edit Rules
              </Button>
            </div>
            {((keyData.allow_cidrs ?? []).length === 0 && (keyData.deny_cidrs ?? []).length === 0) ? (
              <p className="text-xs text-muted-foreground italic">No IP restrictions — all IPs allowed</p>
            ) : (
              <div className="space-y-2">
                {(keyData.allow_cidrs ?? []).length > 0 && (
                  <div>
                    <p className="mb-1 text-xs font-medium text-green-700 dark:text-green-400">Allow</p>
                    <div className="flex flex-wrap gap-1">
                      {(keyData.allow_cidrs ?? []).map((cidr) => (
                        <Badge key={cidr} variant="outline" className="text-[10px] font-mono border-green-300 text-green-700 dark:border-green-700 dark:text-green-400">
                          {cidr}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
                {(keyData.deny_cidrs ?? []).length > 0 && (
                  <div>
                    <p className="mb-1 text-xs font-medium text-red-700 dark:text-red-400">Deny</p>
                    <div className="flex flex-wrap gap-1">
                      {(keyData.deny_cidrs ?? []).map((cidr) => (
                        <Badge key={cidr} variant="outline" className="text-[10px] font-mono border-red-300 text-red-700 dark:border-red-700 dark:text-red-400">
                          {cidr}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Scopes */}
          <div>
            <div className="mb-2 flex items-center gap-1.5 text-sm font-medium">
              <Shield className="h-4 w-4 text-muted-foreground" />
              Scopes
            </div>
            {(keyData.capabilities ?? []).length === 0 ? (
              <p className="text-xs text-muted-foreground italic">All scopes (full access)</p>
            ) : (
              <div className="flex flex-wrap gap-1">
                {(keyData.capabilities ?? []).map((scope) => (
                  <Badge key={scope} variant="outline" className="text-[10px] font-mono">
                    {scope}
                  </Badge>
                ))}
              </div>
            )}
          </div>

          {/* Expiry */}
          {(keyData.expires_at ?? 0) > 0 && (
            <div className="flex items-center gap-2 rounded-lg border border-amber-200 bg-amber-50 p-2 text-xs text-amber-800 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-200">
              <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
              Expires {new Date((keyData.expires_at ?? 0) * 1000).toLocaleDateString()}
            </div>
          )}
        </div>

        <DialogFooter>
          <Button onClick={onClose}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Main component ──────────────────────────────────────────────

export function ApiKeys() {
  const queryClient = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [label, setLabel] = useState("");
  const [expiresInDays, setExpiresInDays] = useState<string>("none");
  const [capabilities, setCapabilities] = useState<string[]>([]);
  const [createdKey, setCreatedKey] = useState<{ key_id: string; key_secret: string; label: string; expiresInDays: string } | null>(null);
  const [copiedField, setCopiedField] = useState<"key_id" | "key_secret" | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<string | null>(null);
  const [ipRulesTarget, setIpRulesTarget] = useState<string | null>(null);
  const [detailsTarget, setDetailsTarget] = useState<ApiKey | null>(null);
  // CIDR list state
  const [allowCidrList, setAllowCidrList] = useState<string[]>([]);
  const [denyCidrList, setDenyCidrList] = useState<string[]>([]);
  const [newAllowCidr, setNewAllowCidr] = useState("");
  const [newDenyCidr, setNewDenyCidr] = useState("");

  const keysQuery = useQuery({
    queryKey: ["apiKeys"],
    queryFn: getApiKeys,
  });

  const createMutation = useMutation({
    mutationFn: () => createApiKey({
      label: label || undefined,
      expires_in_days: expiresInDays === "none" ? undefined : Number(expiresInDays),
      capabilities: capabilities.length > 0 ? capabilities : undefined,
    }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["apiKeys"] });
      setCreatedKey({ key_id: data.key_id, key_secret: data.key_secret, label, expiresInDays });
      setLabel("");
      setExpiresInDays("none");
      setCapabilities([]);
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
    mutationFn: () => {
      // Auto-include any pending (not-yet-added) CIDR input values on save
      const pendingAllow = newAllowCidr.trim();
      const pendingDeny = newDenyCidr.trim();
      return setApiKeyIpRules({
        key_id: ipRulesTarget ?? "",
        allow_cidrs: pendingAllow && !allowCidrList.includes(pendingAllow)
          ? [...allowCidrList, pendingAllow]
          : allowCidrList,
        deny_cidrs: pendingDeny && !denyCidrList.includes(pendingDeny)
          ? [...denyCidrList, pendingDeny]
          : denyCidrList,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["apiKeys"] });
      toast.success("IP rules updated");
      setIpRulesTarget(null);
      setAllowCidrList([]);
      setDenyCidrList([]);
      setNewAllowCidr("");
      setNewDenyCidr("");
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

  const openIpRules = (k: ApiKey) => {
    setIpRulesTarget(k.key_id);
    setAllowCidrList(k.allow_cidrs ?? []);
    setDenyCidrList(k.deny_cidrs ?? []);
    setNewAllowCidr("");
    setNewDenyCidr("");
  };

  const addCidr = (list: string[], setList: (v: string[]) => void, value: string, setValue: (v: string) => void) => {
    const trimmed = value.trim();
    if (!trimmed || list.includes(trimmed)) return;
    setList([...list, trimmed]);
    setValue("");
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
            onClick={() => { setCreateOpen(true); setCreatedKey(null); setCopiedField(null); setLabel(""); setExpiresInDays("none"); setCapabilities([]); }}
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
                    {((k.allow_cidrs ?? []).length > 0 || (k.deny_cidrs ?? []).length > 0) && (
                      <Badge variant="outline" className="text-[10px]">
                        <Shield className="mr-1 h-2.5 w-2.5" />
                        IP restricted
                      </Badge>
                    )}
                  </div>
                  <div className="mt-0.5 flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                    <span>Created {new Date(k.created_at * 1000).toLocaleDateString()}</span>
                    {(k.expires_at ?? 0) > 0 && (
                      <Badge variant="secondary" className="text-[10px]">
                        Expires {new Date((k.expires_at ?? 0) * 1000).toLocaleDateString()}
                      </Badge>
                    )}
                    {(k.last_used_at ?? 0) > 0 && (
                      <span>Last used {new Date((k.last_used_at ?? 0) * 1000).toLocaleDateString()}</span>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  <Button
                    size="icon"
                    variant="ghost"
                    onClick={() => setDetailsTarget(k)}
                    aria-label="View key details"
                  >
                    <Info className="h-4 w-4" />
                  </Button>
                  <Button
                    size="icon"
                    variant="ghost"
                    onClick={() => openIpRules(k)}
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

      {/* Key details dialog */}
      {detailsTarget && (
        <KeyDetailsDialog
          keyData={detailsTarget}
          onClose={() => setDetailsTarget(null)}
          onOpenIpRules={() => openIpRules(detailsTarget)}
        />
      )}

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
              <div>
                <Label>
                  Scopes <span className="text-xs font-normal text-muted-foreground">(leave empty for full access)</span>
                </Label>
                <div className="mt-1 max-h-60 space-y-3 overflow-y-auto rounded-md border p-3">
                  {SCOPE_GROUPS.map((group) => (
                    <div key={group.label}>
                      <p className="mb-1 text-xs font-semibold text-muted-foreground">{group.label}</p>
                      <div className="flex flex-wrap gap-x-3 gap-y-1.5">
                        {group.scopes.map((scope) => (
                          <label key={scope} className="flex cursor-pointer items-center gap-1.5 text-xs">
                            <input
                              type="checkbox"
                              aria-label={scope}
                              checked={capabilities.includes(scope)}
                              onChange={(e) => {
                                setCapabilities((prev) =>
                                  e.target.checked ? [...prev, scope] : prev.filter((s) => s !== scope)
                                );
                              }}
                            />
                            <code className="text-xs">{scope}</code>
                          </label>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
                {capabilities.length > 0 && (
                  <p className="mt-1 text-xs text-muted-foreground">
                    {capabilities.length} scope{capabilities.length !== 1 ? "s" : ""} selected
                  </p>
                )}
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
      <Dialog open={!!ipRulesTarget} onOpenChange={(o) => { if (!o) { setIpRulesTarget(null); } }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Globe className="h-4 w-4" />
              IP Access Rules
            </DialogTitle>
            <DialogDescription>
              Restrict this API key to specific IP ranges using CIDR notation. Leave both lists empty to allow all IPs.
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={(e) => { e.preventDefault(); ipRulesMutation.mutate(); }} className="space-y-4">
            <CidrList
              label="Allow CIDRs"
              items={allowCidrList}
              onAdd={() => addCidr(allowCidrList, setAllowCidrList, newAllowCidr, setNewAllowCidr)}
              onRemove={(i) => setAllowCidrList(allowCidrList.filter((_, idx) => idx !== i))}
              inputValue={newAllowCidr}
              onInputChange={setNewAllowCidr}
              placeholder="e.g. 10.0.0.0/8"
            />
            <CidrList
              label="Deny CIDRs"
              items={denyCidrList}
              onAdd={() => addCidr(denyCidrList, setDenyCidrList, newDenyCidr, setNewDenyCidr)}
              onRemove={(i) => setDenyCidrList(denyCidrList.filter((_, idx) => idx !== i))}
              inputValue={newDenyCidr}
              onInputChange={setNewDenyCidr}
              placeholder="e.g. 0.0.0.0/0"
            />
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
