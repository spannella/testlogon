import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Shield,
  Plus,
  Trash2,
  ArrowDownToLine,
  ArrowUpFromLine,
  Loader2,
  AlertTriangle,
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import {
  listSecurityGroups,
  createSecurityGroup,
  deleteSecurityGroup,
  addSecurityGroupRule,
  removeSecurityGroupRule,
} from "@/api/endpoints/securityGroups";
import type {
  SecurityGroupOut,
  SecurityRuleOut,
  SgProtocol,
  SgDirection,
} from "@/api/types";

const SG_QUERY_KEY = ["compute", "security-groups"];

function isAnywhere(source: string): boolean {
  return source === "0.0.0.0/0";
}

function portRangeLabel(rule: SecurityRuleOut): string {
  if (rule.protocol === "icmp" || rule.protocol === "all") return "—";
  if (rule.port_from === rule.port_to) return String(rule.port_from);
  return `${rule.port_from}-${rule.port_to}`;
}

function sourceDisplay(source: string) {
  if (source === "platform_only") {
    return <Badge variant="secondary" data-testid="source-platform">Platform Only</Badge>;
  }
  if (isAnywhere(source)) {
    return <Badge variant="destructive" data-testid="source-anywhere">Anywhere</Badge>;
  }
  return <span className="font-mono text-xs">{source}</span>;
}

function isDangerous(rule: SecurityRuleOut): boolean {
  return (
    isAnywhere(rule.source) &&
    rule.direction === "inbound" &&
    (rule.protocol === "tcp" || rule.protocol === "all") &&
    rule.port_from <= 22 &&
    22 <= rule.port_to
  );
}

export default function SecurityGroupsPage() {
  const qc = useQueryClient();
  const sgQ = useQuery({
    queryKey: SG_QUERY_KEY,
    queryFn: () => listSecurityGroups(),
  });

  const [createOpen, setCreateOpen] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");

  const [ruleDialogSgId, setRuleDialogSgId] = useState<string | null>(null);

  const groups = sgQ.data?.security_groups ?? [];

  const createMut = useMutation({
    mutationFn: () =>
      createSecurityGroup({ name: newName, description: newDesc, rules: [] }),
    onSuccess: () => {
      toast.success("Security group created");
      setCreateOpen(false);
      setNewName("");
      setNewDesc("");
      qc.invalidateQueries({ queryKey: SG_QUERY_KEY });
    },
    onError: (e: unknown) => toast.error(String((e as Error)?.message || "Failed to create")),
  });

  const deleteMut = useMutation({
    mutationFn: (sgId: string) => deleteSecurityGroup(sgId),
    onSuccess: () => {
      toast.success("Security group deleted");
      qc.invalidateQueries({ queryKey: SG_QUERY_KEY });
    },
    onError: (e: unknown) => toast.error(String((e as Error)?.message || "Failed to delete")),
  });

  const removeRuleMut = useMutation({
    mutationFn: ({ sgId, ruleId }: { sgId: string; ruleId: string }) =>
      removeSecurityGroupRule(sgId, ruleId),
    onSuccess: () => {
      toast.success("Rule removed");
      qc.invalidateQueries({ queryKey: SG_QUERY_KEY });
    },
    onError: (e: unknown) => toast.error(String((e as Error)?.message || "Failed to remove rule")),
  });

  const hasDangerous = groups.some((g) => g.rules.some(isDangerous));

  return (
    <div className="space-y-6 p-4" data-testid="security-groups-page">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="h-6 w-6" />
          <h1 className="text-2xl font-semibold">Security Groups</h1>
        </div>
        <Button onClick={() => setCreateOpen(true)} data-testid="create-sg-button">
          <Plus className="mr-2 h-4 w-4" /> Create Security Group
        </Button>
      </div>

      {hasDangerous && (
        <div
          className="flex items-center gap-2 rounded-md border border-destructive bg-destructive/10 p-3 text-sm text-destructive"
          data-testid="sg-warning-banner"
        >
          <AlertTriangle className="h-4 w-4" />
          One or more rules expose SSH/VNC to the public internet (0.0.0.0/0).
        </div>
      )}

      {sgQ.isLoading && (
        <div className="flex items-center gap-2 text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading…
        </div>
      )}

      <div className="space-y-4">
        {groups.map((sg) => (
          <SgCard
            key={sg.sg_id}
            sg={sg}
            onAddRule={() => setRuleDialogSgId(sg.sg_id)}
            onDeleteRule={(ruleId) => removeRuleMut.mutate({ sgId: sg.sg_id, ruleId })}
            onDelete={() => deleteMut.mutate(sg.sg_id)}
            deleting={deleteMut.isPending}
          />
        ))}
      </div>

      {/* Create dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent data-testid="create-sg-dialog">
          <DialogHeader>
            <DialogTitle>Create Security Group</DialogTitle>
            <DialogDescription>
              Define a named group of firewall rules to apply to instances.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div>
              <Label htmlFor="sg-name">Name</Label>
              <Input
                id="sg-name"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                data-testid="sg-name-input"
                placeholder="Web Server Rules"
              />
            </div>
            <div>
              <Label htmlFor="sg-desc">Description</Label>
              <Input
                id="sg-desc"
                value={newDesc}
                onChange={(e) => setNewDesc(e.target.value)}
                data-testid="sg-desc-input"
                placeholder="Allow HTTP/HTTPS"
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              onClick={() => createMut.mutate()}
              disabled={!newName.trim() || createMut.isPending}
              data-testid="sg-create-submit"
            >
              {createMut.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Add rule dialog */}
      <AddRuleDialog
        sgId={ruleDialogSgId}
        onClose={() => setRuleDialogSgId(null)}
        onAdded={() => {
          setRuleDialogSgId(null);
          qc.invalidateQueries({ queryKey: SG_QUERY_KEY });
        }}
      />
    </div>
  );
}

function SgCard({
  sg,
  onAddRule,
  onDeleteRule,
  onDelete,
  deleting,
}: {
  sg: SecurityGroupOut;
  onAddRule: () => void;
  onDeleteRule: (ruleId: string) => void;
  onDelete: () => void;
  deleting: boolean;
}) {
  return (
    <Card data-testid={`sg-card-${sg.sg_id}`}>
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <div className="flex items-center gap-2">
          <CardTitle className="text-lg">{sg.name}</CardTitle>
          {sg.is_default && (
            <Badge variant="secondary" data-testid="sg-default-badge">
              Default
            </Badge>
          )}
          <span className="text-sm text-muted-foreground">
            {sg.rules.length} rules · {sg.associated_instances.length} instances
          </span>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="outline" onClick={onAddRule} data-testid={`add-rule-${sg.sg_id}`}>
            <Plus className="mr-1 h-4 w-4" /> Add Rule
          </Button>
          {!sg.is_default && (
            <Button
              size="sm"
              variant="ghost"
              onClick={onDelete}
              disabled={deleting}
              data-testid={`delete-sg-${sg.sg_id}`}
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent>
        {sg.description && (
          <p className="mb-2 text-sm text-muted-foreground">{sg.description}</p>
        )}
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Direction</TableHead>
              <TableHead>Protocol</TableHead>
              <TableHead>Port Range</TableHead>
              <TableHead>Source</TableHead>
              <TableHead>Description</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {sg.rules.map((rule) => (
              <TableRow key={rule.rule_id} data-testid={`rule-row-${rule.rule_id}`}>
                <TableCell>
                  {rule.direction === "inbound" ? (
                    <span className="flex items-center gap-1">
                      <ArrowDownToLine className="h-3 w-3" /> in
                    </span>
                  ) : (
                    <span className="flex items-center gap-1">
                      <ArrowUpFromLine className="h-3 w-3" /> out
                    </span>
                  )}
                </TableCell>
                <TableCell>
                  <Badge variant="outline">{rule.protocol.toUpperCase()}</Badge>
                </TableCell>
                <TableCell>{portRangeLabel(rule)}</TableCell>
                <TableCell>{sourceDisplay(rule.source)}</TableCell>
                <TableCell className="text-sm text-muted-foreground">{rule.description}</TableCell>
                <TableCell className="text-right">
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => onDeleteRule(rule.rule_id)}
                    data-testid={`delete-rule-${rule.rule_id}`}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
            {sg.rules.length === 0 && (
              <TableRow>
                <TableCell colSpan={6} className="text-center text-muted-foreground">
                  No rules
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}

function AddRuleDialog({
  sgId,
  onClose,
  onAdded,
}: {
  sgId: string | null;
  onClose: () => void;
  onAdded: () => void;
}) {
  const [protocol, setProtocol] = useState<SgProtocol>("tcp");
  const [portFrom, setPortFrom] = useState("0");
  const [portTo, setPortTo] = useState("0");
  const [source, setSource] = useState("");
  const [direction, setDirection] = useState<SgDirection>("inbound");
  const [description, setDescription] = useState("");

  const portsDisabled = protocol === "icmp" || protocol === "all";

  const addMut = useMutation({
    mutationFn: () =>
      addSecurityGroupRule(sgId as string, {
        protocol,
        port_from: portsDisabled ? 0 : Number(portFrom) || 0,
        port_to: portsDisabled ? 0 : Number(portTo) || 0,
        source,
        direction,
        description,
      }),
    onSuccess: () => {
      toast.success("Rule added");
      setProtocol("tcp");
      setPortFrom("0");
      setPortTo("0");
      setSource("");
      setDirection("inbound");
      setDescription("");
      onAdded();
    },
    onError: (e: unknown) => toast.error(String((e as Error)?.message || "Failed to add rule")),
  });

  return (
    <Dialog open={sgId !== null} onOpenChange={(o) => !o && onClose()}>
      <DialogContent data-testid="add-rule-dialog">
        <DialogHeader>
          <DialogTitle>Add Rule</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <div>
            <Label>Protocol</Label>
            <Select value={protocol} onValueChange={(v) => setProtocol(v as SgProtocol)}>
              <SelectTrigger data-testid="rule-protocol">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="tcp">TCP</SelectItem>
                <SelectItem value="udp">UDP</SelectItem>
                <SelectItem value="icmp">ICMP</SelectItem>
                <SelectItem value="all">All</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="flex gap-2">
            <div className="flex-1">
              <Label htmlFor="port-from">Port From</Label>
              <Input
                id="port-from"
                type="number"
                value={portFrom}
                disabled={portsDisabled}
                onChange={(e) => setPortFrom(e.target.value)}
                data-testid="rule-port-from"
              />
            </div>
            <div className="flex-1">
              <Label htmlFor="port-to">Port To</Label>
              <Input
                id="port-to"
                type="number"
                value={portTo}
                disabled={portsDisabled}
                onChange={(e) => setPortTo(e.target.value)}
                data-testid="rule-port-to"
              />
            </div>
          </div>
          <div>
            <Label htmlFor="rule-source">Source</Label>
            <Input
              id="rule-source"
              value={source}
              onChange={(e) => setSource(e.target.value)}
              placeholder="10.0.0.0/8"
              data-testid="rule-source"
            />
            <div className="mt-1 flex gap-2">
              <Button
                size="sm"
                variant="secondary"
                type="button"
                onClick={() => setSource("platform_only")}
                data-testid="source-platform-button"
              >
                Platform Only
              </Button>
              <Button
                size="sm"
                variant="outline"
                type="button"
                onClick={() => setSource("0.0.0.0/0")}
                data-testid="source-anywhere-button"
              >
                Anywhere
              </Button>
            </div>
          </div>
          <div>
            <Label>Direction</Label>
            <Select value={direction} onValueChange={(v) => setDirection(v as SgDirection)}>
              <SelectTrigger data-testid="rule-direction">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="inbound">Inbound</SelectItem>
                <SelectItem value="outbound">Outbound</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label htmlFor="rule-desc">Description</Label>
            <Input
              id="rule-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              data-testid="rule-description"
            />
          </div>
        </div>
        <DialogFooter>
          <Button
            onClick={() => addMut.mutate()}
            disabled={!source.trim() || addMut.isPending}
            data-testid="rule-submit"
          >
            {addMut.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Add Rule
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
