import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { PageMeta } from "@/components/shared/PageMeta";
import { Shield, Plus, Trash2, Settings2, BarChart3 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import {
  listSsoProviders,
  createSsoProvider,
  updateSsoProvider,
  deleteSsoProvider,
  getSsoProviderStats,
} from "@/api/endpoints/sso";
import type { SsoProviderOut } from "@/api/types";

export default function SsoProvidersPage() {
  const queryClient = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [displayName, setDisplayName] = useState("");
  const [metadataXml, setMetadataXml] = useState("");

  const { data, isLoading } = useQuery({
    queryKey: ["sso-providers"],
    queryFn: () => listSsoProviders("default"),
  });

  const createMut = useMutation({
    mutationFn: () =>
      createSsoProvider({
        display_name: displayName,
        protocol: "saml",
        tenant_id: "default",
        metadata_xml: metadataXml ? btoa(metadataXml) : undefined,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sso-providers"] });
      setCreateOpen(false);
      setDisplayName("");
      setMetadataXml("");
    },
  });

  const deleteMut = useMutation({
    mutationFn: (providerId: string) => deleteSsoProvider(providerId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sso-providers"] });
    },
  });

  const toggleSsoOnly = useMutation({
    mutationFn: ({ providerId, ssoOnly }: { providerId: string; ssoOnly: boolean }) =>
      updateSsoProvider(providerId, { sso_only: ssoOnly, tenant_id: "default" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sso-providers"] });
    },
  });

  const toggleStatus = useMutation({
    mutationFn: ({ providerId, status }: { providerId: string; status: string }) =>
      updateSsoProvider(providerId, { status, tenant_id: "default" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sso-providers"] });
    },
  });

  const providers = data?.providers ?? [];

  return (
    <div className="container max-w-4xl py-8">
      <PageMeta title="SSO Providers" />

      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="h-6 w-6" />
            SSO Providers
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Manage SAML SSO integrations for your organization
          </p>
        </div>

        <Dialog open={createOpen} onOpenChange={setCreateOpen}>
          <DialogTrigger asChild>
            <Button data-testid="add-provider-button">
              <Plus className="mr-2 h-4 w-4" />
              Add Provider
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Add SSO Provider</DialogTitle>
              <DialogDescription>
                Configure a new SAML SSO provider for your organization.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label htmlFor="display-name">Display Name</Label>
                <Input
                  id="display-name"
                  placeholder="e.g. Acme Corp Okta"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="metadata-xml">IdP Metadata XML (optional)</Label>
                <textarea
                  id="metadata-xml"
                  className="flex min-h-[120px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  placeholder="Paste your IdP metadata XML here..."
                  value={metadataXml}
                  onChange={(e) => setMetadataXml(e.target.value)}
                />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setCreateOpen(false)}>
                Cancel
              </Button>
              <Button
                onClick={() => createMut.mutate()}
                disabled={!displayName || createMut.isPending}
              >
                Create Provider
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {isLoading ? (
        <p className="text-muted-foreground">Loading providers...</p>
      ) : providers.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <Shield className="mx-auto h-12 w-12 text-muted-foreground/50" />
            <p className="mt-4 text-muted-foreground">
              No SSO providers configured. Add one to enable SAML SSO.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {providers.map((provider: SsoProviderOut) => (
            <ProviderCard
              key={provider.provider_id}
              provider={provider}
              onDelete={() => deleteMut.mutate(provider.provider_id)}
              onToggleSsoOnly={(ssoOnly) =>
                toggleSsoOnly.mutate({ providerId: provider.provider_id, ssoOnly })
              }
              onToggleStatus={(status) =>
                toggleStatus.mutate({ providerId: provider.provider_id, status })
              }
            />
          ))}
        </div>
      )}
    </div>
  );
}

function ProviderCard({
  provider,
  onDelete,
  onToggleSsoOnly,
  onToggleStatus,
}: {
  provider: SsoProviderOut;
  onDelete: () => void;
  onToggleSsoOnly: (ssoOnly: boolean) => void;
  onToggleStatus: (status: string) => void;
}) {
  const { data: stats } = useQuery({
    queryKey: ["sso-provider-stats", provider.provider_id],
    queryFn: () => getSsoProviderStats(provider.provider_id),
    staleTime: 30_000,
  });

  const statusColor =
    provider.status === "active"
      ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
      : provider.status === "testing"
        ? "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
        : "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200";

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between space-y-0 pb-2">
        <div>
          <CardTitle className="text-lg" data-testid="provider-name">
            {provider.display_name}
          </CardTitle>
          <CardDescription className="mt-1">
            {provider.protocol.toUpperCase()} | {provider.idp_entity_id || "No IdP configured"}
          </CardDescription>
        </div>
        <div className="flex items-center gap-2">
          <Badge className={statusColor} data-testid="provider-status">
            {provider.status}
          </Badge>
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8 text-destructive"
            onClick={onDelete}
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <span className="text-muted-foreground">Provider ID:</span>
            <p className="font-mono text-xs">{provider.provider_id}</p>
          </div>
          <div>
            <span className="text-muted-foreground">Default Role:</span>
            <p>{provider.default_role}</p>
          </div>
          <div>
            <span className="text-muted-foreground">JIT Provisioning:</span>
            <p>{provider.jit_provisioning_enabled ? "Enabled" : "Disabled"}</p>
          </div>
          <div className="flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-muted-foreground" />
            <span className="text-muted-foreground">Logins:</span>
            <span>{stats?.login_count ?? provider.login_count ?? 0}</span>
          </div>
        </div>

        <div className="flex items-center justify-between border-t pt-4">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <Switch
                checked={provider.sso_only}
                onCheckedChange={onToggleSsoOnly}
                id={`sso-only-${provider.provider_id}`}
              />
              <Label htmlFor={`sso-only-${provider.provider_id}`} className="text-sm">
                SSO Only
              </Label>
            </div>
            <div className="flex items-center gap-2">
              <Switch
                checked={provider.status === "active"}
                onCheckedChange={(checked) =>
                  onToggleStatus(checked ? "active" : "inactive")
                }
                id={`status-${provider.provider_id}`}
              />
              <Label htmlFor={`status-${provider.provider_id}`} className="text-sm">
                Active
              </Label>
            </div>
          </div>
          <Button variant="outline" size="sm" disabled>
            <Settings2 className="mr-1 h-3.5 w-3.5" />
            Configure
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
