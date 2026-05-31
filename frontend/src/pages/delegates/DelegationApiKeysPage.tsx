import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Plus, Trash2, Copy, ShieldCheck } from "lucide-react";
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import { listManagedCreators } from "@/api/endpoints/delegates";
import {
  createDelegationApiKey,
  listMyDelegationApiKeys,
  revokeMyDelegationApiKey,
  listCreatorDelegationApiKeys,
  revokeCreatorDelegationApiKey,
} from "@/api/endpoints/delegationApi";
import type { DelegationApiKeyOut } from "@/api/types";

const ALL_PERMISSIONS = [
  "chat_read",
  "chat_respond",
  "feed_read",
  "feed_post",
  "feed_moderate",
  "broadcast_moderate",
  "broadcast_control",
];

function statusVariant(status: string): "default" | "secondary" | "destructive" {
  if (status === "active") return "default";
  if (status === "revoked") return "destructive";
  return "secondary";
}

function DelegationApiCreateDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onCreated: (key: DelegationApiKeyOut) => void;
}) {
  const [label, setLabel] = useState("");
  const [creatorId, setCreatorId] = useState("");
  const [permissions, setPermissions] = useState<string[]>([]);

  const { data: creators = [] } = useQuery({
    queryKey: ["delegation-api", "managed-creators"],
    queryFn: listManagedCreators,
    enabled: open,
  });

  const createMut = useMutation({
    mutationFn: () =>
      createDelegationApiKey({ label, creator_id: creatorId, permissions }),
    onSuccess: (key) => {
      onCreated(key);
      onOpenChange(false);
      setLabel("");
      setCreatorId("");
      setPermissions([]);
    },
    onError: () => toast.error("Could not create API key"),
  });

  const selectedCreator = creators.find((c) => c.creator_id === creatorId);
  const allowed = new Set(selectedCreator?.permissions ?? []);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create delegation API key</DialogTitle>
          <DialogDescription>
            Issue a scoped key for a creator you manage. The key inherits a
            subset of your delegated permissions.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label htmlFor="dak-label">Label</Label>
            <Input
              id="dak-label"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="My CRM integration"
            />
          </div>
          <div>
            <Label>Creator</Label>
            <Select value={creatorId} onValueChange={setCreatorId}>
              <SelectTrigger>
                <SelectValue placeholder="Select a managed creator" />
              </SelectTrigger>
              <SelectContent>
                {creators.map((c) => (
                  <SelectItem key={c.creator_id} value={c.creator_id}>
                    {c.label || c.creator_id}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label>Permissions</Label>
            {ALL_PERMISSIONS.map((perm) => {
              const enabled = !creatorId || allowed.has(perm);
              return (
                <label
                  key={perm}
                  className="flex items-center gap-2 text-sm data-[disabled=true]:opacity-40"
                  data-disabled={!enabled}
                >
                  <Checkbox
                    checked={permissions.includes(perm)}
                    disabled={!enabled}
                    onCheckedChange={(checked) =>
                      setPermissions((prev) =>
                        checked
                          ? [...prev, perm]
                          : prev.filter((p) => p !== perm),
                      )
                    }
                  />
                  {perm}
                </label>
              );
            })}
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={() => createMut.mutate()}
            disabled={
              !label || !creatorId || permissions.length === 0 || createMut.isPending
            }
          >
            Create key
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function DelegationApiKeyCard({
  apiKey,
  onRevoke,
}: {
  apiKey: DelegationApiKeyOut;
  onRevoke: (keyId: string) => void;
}) {
  return (
    <Card>
      <CardContent className="flex items-start justify-between py-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="font-medium">{apiKey.label || apiKey.key_id}</span>
            <Badge variant={statusVariant(apiKey.status)}>{apiKey.status}</Badge>
          </div>
          <p className="text-sm text-muted-foreground">
            Creator: {apiKey.creator_id}
          </p>
          <p className="text-xs text-muted-foreground">
            Prefix {apiKey.prefix} · {apiKey.total_calls} calls · limit{" "}
            {apiKey.rate_limit_rpm}/min
          </p>
          <div className="flex flex-wrap gap-1 pt-1">
            {apiKey.permissions.map((p) => (
              <Badge key={p} variant="secondary" className="text-xs">
                {p}
              </Badge>
            ))}
          </div>
        </div>
        <Button
          variant="ghost"
          size="icon"
          onClick={() => onRevoke(apiKey.key_id)}
          aria-label="Revoke key"
        >
          <Trash2 className="h-4 w-4" />
        </Button>
      </CardContent>
    </Card>
  );
}

export default function DelegationApiKeysPage() {
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [newKeySecret, setNewKeySecret] = useState<string | null>(null);

  const { data: myKeys = [] } = useQuery({
    queryKey: ["delegation-api", "my-keys"],
    queryFn: listMyDelegationApiKeys,
  });
  const { data: creatorKeys = [] } = useQuery({
    queryKey: ["delegation-api", "creator-keys"],
    queryFn: listCreatorDelegationApiKeys,
  });

  const revokeMineMut = useMutation({
    mutationFn: revokeMyDelegationApiKey,
    onSuccess: () => {
      toast.success("Key revoked");
      qc.invalidateQueries({ queryKey: ["delegation-api", "my-keys"] });
    },
  });
  const revokeCreatorMut = useMutation({
    mutationFn: revokeCreatorDelegationApiKey,
    onSuccess: () => {
      toast.success("Key revoked");
      qc.invalidateQueries({ queryKey: ["delegation-api", "creator-keys"] });
    },
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold">
            <KeyRound className="h-6 w-6" /> Delegation API Keys
          </h1>
          <p className="text-sm text-muted-foreground">
            Issue scoped programmatic keys for tools acting on a creator's behalf.
          </p>
        </div>
        <Button onClick={() => setCreateOpen(true)}>
          <Plus className="mr-2 h-4 w-4" /> Create API Key
        </Button>
      </div>

      {newKeySecret && (
        <Card className="border-primary">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <ShieldCheck className="h-4 w-4" /> Copy your new API key now
            </CardTitle>
          </CardHeader>
          <CardContent className="flex items-center gap-2">
            <code className="flex-1 break-all rounded bg-muted px-2 py-1 text-sm">
              {newKeySecret}
            </code>
            <Button
              size="icon"
              variant="outline"
              onClick={() => {
                navigator.clipboard.writeText(newKeySecret);
                toast.success("Copied");
              }}
              aria-label="Copy key"
            >
              <Copy className="h-4 w-4" />
            </Button>
            <Button variant="ghost" onClick={() => setNewKeySecret(null)}>
              Dismiss
            </Button>
          </CardContent>
        </Card>
      )}

      <Tabs defaultValue="mine">
        <TabsList>
          <TabsTrigger value="mine">My API Keys</TabsTrigger>
          <TabsTrigger value="creator">Keys For My Account</TabsTrigger>
        </TabsList>
        <TabsContent value="mine" className="space-y-3">
          {myKeys.length === 0 && (
            <p className="text-sm text-muted-foreground">No API keys yet.</p>
          )}
          {myKeys.map((k) => (
            <DelegationApiKeyCard
              key={k.key_id}
              apiKey={k}
              onRevoke={(id) => revokeMineMut.mutate(id)}
            />
          ))}
        </TabsContent>
        <TabsContent value="creator" className="space-y-3">
          {creatorKeys.length === 0 && (
            <p className="text-sm text-muted-foreground">
              No keys are scoped to your account.
            </p>
          )}
          {creatorKeys.map((k) => (
            <DelegationApiKeyCard
              key={k.key_id}
              apiKey={k}
              onRevoke={(id) => revokeCreatorMut.mutate(id)}
            />
          ))}
        </TabsContent>
      </Tabs>

      <DelegationApiCreateDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={(key) => {
          if (key.key_secret) setNewKeySecret(key.key_secret);
          qc.invalidateQueries({ queryKey: ["delegation-api", "my-keys"] });
        }}
      />
    </div>
  );
}
