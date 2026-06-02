import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { hostInventoryApi } from "@/api/endpoints/hostInventory";
import type {
  CreateHostInput,
  HostOut,
  HostProtocol,
  HostOsType,
} from "@/api/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useToast } from "@/components/ui/use-toast";
import { Plug, Pencil, Trash2, History as HistoryIcon, Server } from "lucide-react";

const DEFAULT_PORTS: Record<HostProtocol, number> = {
  ssh: 22,
  vnc: 5900,
  rdp: 3389,
};

function relTime(ts: number): string {
  if (!ts) return "Never";
  const diff = Math.max(0, Math.floor(Date.now() / 1000) - ts);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

// ── Add / Edit dialog ──────────────────────────────────────────────────────

interface HostDialogProps {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  editing: HostOut | null;
  groups: string[];
}

function HostDialog({ open, onOpenChange, editing, groups }: HostDialogProps) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [label, setLabel] = useState("");
  const [hostname, setHostname] = useState("");
  const [protocol, setProtocol] = useState<HostProtocol>("ssh");
  const [port, setPort] = useState(22);
  const [username, setUsername] = useState("");
  const [group, setGroup] = useState("");
  const [osType, setOsType] = useState<HostOsType>("unknown");
  const [description, setDescription] = useState("");
  const [tags, setTags] = useState("");

  // Reset form when dialog opens.
  const [lastOpenKey, setLastOpenKey] = useState<string>("");
  const openKey = `${open}:${editing?.host_id ?? "new"}`;
  if (open && openKey !== lastOpenKey) {
    setLastOpenKey(openKey);
    setLabel(editing?.label ?? "");
    setHostname(editing?.hostname ?? "");
    setProtocol((editing?.protocol as HostProtocol) ?? "ssh");
    setPort(editing?.port ?? 22);
    setUsername(editing?.username ?? "");
    setGroup(editing?.group ?? "");
    setOsType((editing?.os_type as HostOsType) ?? "unknown");
    setDescription(editing?.description ?? "");
    setTags((editing?.tags ?? []).join(", "));
  }

  const saveMut = useMutation({
    mutationFn: () => {
      const payload: CreateHostInput = {
        label,
        hostname,
        protocol,
        port,
        username,
        group,
        os_type: osType,
        description,
        tags: tags
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
      };
      if (editing) {
        return hostInventoryApi.update(editing.host_id, payload);
      }
      return hostInventoryApi.create(payload);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["host-inventory"] });
      qc.invalidateQueries({ queryKey: ["host-groups"] });
      toast({ title: editing ? "Host updated" : "Host created" });
      onOpenChange(false);
    },
    onError: () => {
      toast({ title: "Save failed", variant: "destructive" });
    },
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{editing ? "Edit Host" : "Add Host"}</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="hi-label">Label</Label>
            <Input
              id="hi-label"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="Prod Web 1"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="hi-hostname">Hostname / IP</Label>
            <Input
              id="hi-hostname"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              placeholder="10.0.1.10"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label>Protocol</Label>
              <Select
                value={protocol}
                onValueChange={(v) => {
                  const p = v as HostProtocol;
                  setProtocol(p);
                  setPort(DEFAULT_PORTS[p]);
                }}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ssh">SSH</SelectItem>
                  <SelectItem value="vnc">VNC</SelectItem>
                  <SelectItem value="rdp">RDP</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="hi-port">Port</Label>
              <Input
                id="hi-port"
                type="number"
                value={port}
                onChange={(e) => setPort(Number(e.target.value))}
              />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label htmlFor="hi-username">Username</Label>
              <Input
                id="hi-username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="ubuntu"
              />
            </div>
            <div className="space-y-1.5">
              <Label>OS Type</Label>
              <Select value={osType} onValueChange={(v) => setOsType(v as HostOsType)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="linux">Linux</SelectItem>
                  <SelectItem value="windows">Windows</SelectItem>
                  <SelectItem value="macos">macOS</SelectItem>
                  <SelectItem value="unknown">Unknown</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="hi-group">Group</Label>
            <Input
              id="hi-group"
              value={group}
              onChange={(e) => setGroup(e.target.value)}
              placeholder="Production"
              list="hi-groups"
            />
            <datalist id="hi-groups">
              {groups.map((g) => (
                <option key={g} value={g} />
              ))}
            </datalist>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="hi-tags">Tags (comma-separated)</Label>
            <Input
              id="hi-tags"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              placeholder="web, prod"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="hi-desc">Description</Label>
            <Textarea
              id="hi-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={() => saveMut.mutate()} disabled={saveMut.isPending}>
            {editing ? "Save" : "Create"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── CSV import dialog ──────────────────────────────────────────────────────

function ImportCsvDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [csv, setCsv] = useState(
    "label,hostname,port,protocol,group,os_type,description,tags\n",
  );

  const importMut = useMutation({
    mutationFn: () => hostInventoryApi.importCsv(csv),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["host-inventory"] });
      qc.invalidateQueries({ queryKey: ["host-groups"] });
      toast({
        title: "Import complete",
        description: `Imported ${res.imported}, skipped ${res.skipped}, ${res.errors.length} error(s)`,
      });
      if (res.errors.length === 0) onOpenChange(false);
    },
    onError: () => {
      toast({ title: "Import failed", variant: "destructive" });
    },
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Import Hosts from CSV</DialogTitle>
        </DialogHeader>
        <Textarea
          rows={10}
          value={csv}
          onChange={(e) => setCsv(e.target.value)}
          className="font-mono text-xs"
          data-testid="csv-import-textarea"
        />
        {importMut.data && importMut.data.errors.length > 0 && (
          <div className="rounded border border-destructive/40 bg-destructive/5 p-2 text-xs">
            {importMut.data.errors.map((err, i) => (
              <div key={i}>{err}</div>
            ))}
          </div>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Close
          </Button>
          <Button onClick={() => importMut.mutate()} disabled={importMut.isPending}>
            Import
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── History dialog ─────────────────────────────────────────────────────────

function HistoryDialog({
  hostId,
  open,
  onOpenChange,
}: {
  hostId: string | null;
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const { data } = useQuery({
    queryKey: ["host-history", hostId],
    queryFn: () => hostInventoryApi.history(hostId as string),
    enabled: open && !!hostId,
  });
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Connection History</DialogTitle>
        </DialogHeader>
        <p className="text-sm text-muted-foreground">
          {data?.connection_count ?? 0} total connection(s)
        </p>
        <div className="space-y-1 max-h-72 overflow-y-auto">
          {(data?.events ?? []).map((ev, i) => (
            <div key={i} className="flex justify-between text-sm">
              <span>{ev.protocol.toUpperCase()}</span>
              <span className="text-muted-foreground">{relTime(ev.connected_at)}</span>
            </div>
          ))}
          {data && data.events.length === 0 && (
            <p className="text-sm text-muted-foreground">No connections recorded yet.</p>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ── Main page ──────────────────────────────────────────────────────────────

export default function HostInventoryPage() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const { toast } = useToast();

  const [protocolFilter, setProtocolFilter] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<HostOut | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [historyHost, setHistoryHost] = useState<string | null>(null);
  const [historyOpen, setHistoryOpen] = useState(false);

  const { data, isLoading } = useQuery({
    queryKey: ["host-inventory", protocolFilter],
    queryFn: () =>
      hostInventoryApi.list(
        protocolFilter === "all" ? undefined : { protocol: protocolFilter },
      ),
  });

  const { data: groupsData } = useQuery({
    queryKey: ["host-groups"],
    queryFn: () => hostInventoryApi.groups(),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => hostInventoryApi.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["host-inventory"] });
      toast({ title: "Host deleted" });
    },
  });

  const quickConnectMut = useMutation({
    mutationFn: (id: string) => hostInventoryApi.quickConnect(id),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["host-inventory"] });
      toast({
        title: "Quick connect",
        description: `${res.protocol.toUpperCase()} → ${res.hostname}:${res.port}`,
      });
      if (res.connect_path) navigate(res.connect_path);
    },
    onError: () => toast({ title: "Quick connect failed", variant: "destructive" }),
  });

  const hosts = data?.hosts ?? [];
  const groups = groupsData?.groups ?? [];

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    const list = q
      ? hosts.filter(
          (h) =>
            h.label.toLowerCase().includes(q) ||
            h.hostname.toLowerCase().includes(q),
        )
      : hosts;
    return list;
  }, [hosts, search]);

  // Group hosts by their group name for a grouped display.
  const grouped = useMemo(() => {
    const map = new Map<string, HostOut[]>();
    for (const h of filtered) {
      const key = h.group || "Ungrouped";
      const arr = map.get(key) ?? [];
      arr.push(h);
      map.set(key, arr);
    }
    return Array.from(map.entries()).sort((a, b) => a[0].localeCompare(b[0]));
  }, [filtered]);

  return (
    <div className="container mx-auto max-w-5xl py-6 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold">
            <Server className="h-6 w-6" /> Host Inventory
          </h1>
          <p className="text-sm text-muted-foreground">
            Saved remote hosts for quick connect via SSH and VNC.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => setImportOpen(true)}>
            Import CSV
          </Button>
          <Button
            onClick={() => {
              setEditing(null);
              setDialogOpen(true);
            }}
          >
            Add Host
          </Button>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <Input
          placeholder="Search hosts…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="max-w-xs"
          data-testid="host-search"
        />
        <Select value={protocolFilter} onValueChange={setProtocolFilter}>
          <SelectTrigger className="w-36">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All protocols</SelectItem>
            <SelectItem value="ssh">SSH</SelectItem>
            <SelectItem value="vnc">VNC</SelectItem>
            <SelectItem value="rdp">RDP</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {isLoading && <p className="text-sm text-muted-foreground">Loading hosts…</p>}

      {!isLoading && filtered.length === 0 && (
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            No hosts saved. Add your first host or import from CSV.
          </CardContent>
        </Card>
      )}

      {grouped.map(([groupName, groupHosts]) => (
        <div key={groupName} className="space-y-2" data-testid="host-group">
          <h2 className="text-sm font-semibold text-muted-foreground">{groupName}</h2>
          <Card>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Label</TableHead>
                    <TableHead>Hostname</TableHead>
                    <TableHead>Protocol</TableHead>
                    <TableHead>Group</TableHead>
                    <TableHead>Last Connected</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {groupHosts.map((h) => (
                    <TableRow key={h.host_id} data-testid="host-row">
                      <TableCell className="font-medium">{h.label}</TableCell>
                      <TableCell>
                        {h.hostname}:{h.port}
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary">{h.protocol.toUpperCase()}</Badge>
                      </TableCell>
                      <TableCell>{h.group || "—"}</TableCell>
                      <TableCell>{relTime(h.last_connected_at)}</TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-1">
                          <Button
                            size="icon"
                            variant="ghost"
                            title="Connect"
                            data-testid="host-connect"
                            onClick={() => quickConnectMut.mutate(h.host_id)}
                          >
                            <Plug className="h-4 w-4" />
                          </Button>
                          <Button
                            size="icon"
                            variant="ghost"
                            title="History"
                            onClick={() => {
                              setHistoryHost(h.host_id);
                              setHistoryOpen(true);
                            }}
                          >
                            <HistoryIcon className="h-4 w-4" />
                          </Button>
                          <Button
                            size="icon"
                            variant="ghost"
                            title="Edit"
                            data-testid="host-edit"
                            onClick={() => {
                              setEditing(h);
                              setDialogOpen(true);
                            }}
                          >
                            <Pencil className="h-4 w-4" />
                          </Button>
                          <Button
                            size="icon"
                            variant="ghost"
                            title="Delete"
                            data-testid="host-delete"
                            onClick={() => deleteMut.mutate(h.host_id)}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </div>
      ))}

      <HostDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        editing={editing}
        groups={groups}
      />
      <ImportCsvDialog open={importOpen} onOpenChange={setImportOpen} />
      <HistoryDialog
        hostId={historyHost}
        open={historyOpen}
        onOpenChange={setHistoryOpen}
      />
    </div>
  );
}
