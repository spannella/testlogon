import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Network,
  Plus,
  Trash2,
  Loader2,
  Route as RouteIcon,
  ArrowRight,
  Server,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
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

import {
  listBastionPaths,
  createBastionPath,
  deleteBastionPath,
  resolveBastionPath,
} from "@/api/endpoints/sshBastion";
import type {
  SshBastionPathOut,
  SshBastionHopIn,
  SshBastionResolvedOut,
} from "@/api/types";
import { ApiError } from "@/api/client";

const BASTION_QUERY_KEY = ["compute", "bastion-paths"];

function emptyHop(): SshBastionHopIn {
  return { hostname: "", port: 22, username: "", ssh_key_id: "", label: "" };
}

interface HopEditorProps {
  hop: SshBastionHopIn;
  title: string;
  onChange: (hop: SshBastionHopIn) => void;
  onRemove?: () => void;
}

function HopEditor({ hop, title, onChange, onRemove }: HopEditorProps) {
  return (
    <div className="rounded-md border p-3 space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium flex items-center gap-1.5">
          <Server className="h-3.5 w-3.5" /> {title}
        </span>
        {onRemove && (
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="h-6 w-6"
            onClick={onRemove}
            aria-label="Remove hop"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        )}
      </div>
      <div className="grid grid-cols-2 gap-2">
        <div className="space-y-1">
          <Label className="text-xs">Hostname / IP</Label>
          <Input
            value={hop.hostname}
            placeholder="10.0.0.1"
            onChange={(e) => onChange({ ...hop, hostname: e.target.value })}
          />
        </div>
        <div className="space-y-1">
          <Label className="text-xs">Port</Label>
          <Input
            type="number"
            value={hop.port ?? 22}
            onChange={(e) => onChange({ ...hop, port: Number(e.target.value) })}
          />
        </div>
        <div className="space-y-1">
          <Label className="text-xs">Username</Label>
          <Input
            value={hop.username}
            placeholder="ubuntu"
            onChange={(e) => onChange({ ...hop, username: e.target.value })}
          />
        </div>
        <div className="space-y-1">
          <Label className="text-xs">SSH Key ID (optional)</Label>
          <Input
            value={hop.ssh_key_id ?? ""}
            placeholder="key-..."
            onChange={(e) => onChange({ ...hop, ssh_key_id: e.target.value })}
          />
        </div>
      </div>
    </div>
  );
}

export default function SshBastionPage() {
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [label, setLabel] = useState("");
  const [description, setDescription] = useState("");
  const [jumpHops, setJumpHops] = useState<SshBastionHopIn[]>([emptyHop()]);
  const [target, setTarget] = useState<SshBastionHopIn>(emptyHop());
  const [resolved, setResolved] = useState<SshBastionResolvedOut | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: BASTION_QUERY_KEY,
    queryFn: listBastionPaths,
  });

  const paths = data?.paths ?? [];

  function resetForm() {
    setLabel("");
    setDescription("");
    setJumpHops([emptyHop()]);
    setTarget(emptyHop());
  }

  const createMut = useMutation({
    mutationFn: () =>
      createBastionPath({
        label,
        description,
        jump_hops: jumpHops,
        target,
      }),
    onSuccess: () => {
      toast.success("Bastion path created");
      qc.invalidateQueries({ queryKey: BASTION_QUERY_KEY });
      setCreateOpen(false);
      resetForm();
    },
    onError: (err) => {
      const msg = err instanceof ApiError ? err.message : "Failed to create path";
      toast.error(msg);
    },
  });

  const deleteMut = useMutation({
    mutationFn: (pathId: string) => deleteBastionPath(pathId),
    onSuccess: () => {
      toast.success("Bastion path deleted");
      qc.invalidateQueries({ queryKey: BASTION_QUERY_KEY });
    },
    onError: () => toast.error("Failed to delete path"),
  });

  const resolveMut = useMutation({
    mutationFn: (pathId: string) => resolveBastionPath(pathId),
    onSuccess: (r) => setResolved(r),
    onError: (err) => {
      const msg = err instanceof ApiError ? err.message : "Failed to resolve path";
      toast.error(msg);
    },
  });

  return (
    <div className="max-w-5xl mx-auto p-4 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold flex items-center gap-2">
            <Network className="h-6 w-6" /> SSH Bastion Paths
          </h1>
          <p className="text-sm text-muted-foreground">
            Multi-hop SSH routes through one or more jump hosts to a target.
          </p>
        </div>
        <Button onClick={() => setCreateOpen(true)} data-testid="bastion-new">
          <Plus className="h-4 w-4 mr-1" /> New Path
        </Button>
      </div>

      {isLoading ? (
        <div className="flex justify-center py-12">
          <Loader2 className="h-6 w-6 animate-spin" />
        </div>
      ) : paths.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground">
            No bastion paths yet. Create one to route through jump hosts.
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {paths.map((p: SshBastionPathOut) => (
            <Card key={p.path_id} data-testid="bastion-path-row">
              <CardHeader className="pb-2">
                <CardTitle className="text-base flex items-center justify-between">
                  <span className="flex items-center gap-2">
                    {p.label}
                    <Badge variant="secondary">{p.total_hops} hops</Badge>
                  </span>
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => resolveMut.mutate(p.path_id)}
                      data-testid="bastion-resolve"
                    >
                      <RouteIcon className="h-4 w-4 mr-1" /> Resolve
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => deleteMut.mutate(p.path_id)}
                      aria-label="Delete path"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </CardTitle>
              </CardHeader>
              <CardContent className="pt-0">
                {p.description && (
                  <p className="text-sm text-muted-foreground mb-2">{p.description}</p>
                )}
                <div className="flex flex-wrap items-center gap-1.5 text-sm">
                  <Badge variant="outline">Platform</Badge>
                  {p.hops.map((h) => (
                    <span key={h.hop_number} className="flex items-center gap-1.5">
                      <ArrowRight className="h-3.5 w-3.5 text-muted-foreground" />
                      <Badge variant={h.is_bastion ? "secondary" : "default"}>
                        {h.is_bastion ? "Bastion" : "Target"}: {h.username}@{h.hostname}:{h.port}
                      </Badge>
                    </span>
                  ))}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Create dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>New Bastion Path</DialogTitle>
            <DialogDescription>
              Define an ordered chain of jump hosts that route to a target host.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1">
              <Label>Label</Label>
              <Input
                value={label}
                placeholder="prod-db via bastion"
                onChange={(e) => setLabel(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <Label>Description (optional)</Label>
              <Input
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label>Jump Hosts (bastions)</Label>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => setJumpHops([...jumpHops, emptyHop()])}
                  data-testid="bastion-add-hop"
                >
                  <Plus className="h-3.5 w-3.5 mr-1" /> Add hop
                </Button>
              </div>
              {jumpHops.map((hop, i) => (
                <HopEditor
                  key={i}
                  hop={hop}
                  title={`Jump host ${i + 1}`}
                  onChange={(h) =>
                    setJumpHops(jumpHops.map((x, j) => (j === i ? h : x)))
                  }
                  onRemove={
                    jumpHops.length > 0
                      ? () => setJumpHops(jumpHops.filter((_, j) => j !== i))
                      : undefined
                  }
                />
              ))}
            </div>

            <HopEditor hop={target} title="Target host" onChange={setTarget} />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => createMut.mutate()}
              disabled={createMut.isPending}
              data-testid="bastion-create-submit"
            >
              {createMut.isPending && (
                <Loader2 className="h-4 w-4 mr-1 animate-spin" />
              )}
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Resolve dialog */}
      <Dialog open={!!resolved} onOpenChange={(o) => !o && setResolved(null)}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Resolved ProxyJump Config</DialogTitle>
            <DialogDescription>{resolved?.label}</DialogDescription>
          </DialogHeader>
          {resolved && (
            <div className="space-y-3 text-sm">
              <div>
                <Label className="text-xs">ProxyJump</Label>
                <pre className="rounded bg-muted p-2 overflow-x-auto" data-testid="resolved-proxyjump">
                  {resolved.proxy_jump || "(direct — no bastion)"}
                </pre>
              </div>
              <div>
                <Label className="text-xs">ssh command</Label>
                <pre className="rounded bg-muted p-2 overflow-x-auto" data-testid="resolved-command">
                  {resolved.ssh_command}
                </pre>
              </div>
              <div>
                <Label className="text-xs">ssh_config</Label>
                <pre className="rounded bg-muted p-2 overflow-x-auto whitespace-pre" data-testid="resolved-config">
                  {resolved.ssh_config}
                </pre>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
