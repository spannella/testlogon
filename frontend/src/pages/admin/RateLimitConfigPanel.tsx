import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getRateLimitConfig,
  updateRateLimitConfig,
  type RateLimitGroupConfig,
} from "@/api/endpoints/adminRateLimits";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Pencil, Save } from "lucide-react";

export default function RateLimitConfigPanel() {
  const queryClient = useQueryClient();
  const [editingGroup, setEditingGroup] = useState<string | null>(null);
  const [editForm, setEditForm] = useState<{
    window_seconds: string;
    max_requests_per_user: string;
    max_requests_per_ip: string;
    bypass_roles: string;
  }>({
    window_seconds: "",
    max_requests_per_user: "",
    max_requests_per_ip: "",
    bypass_roles: "",
  });

  const configQ = useQuery({
    queryKey: ["admin", "rate-limits", "config"],
    queryFn: getRateLimitConfig,
  });

  const updateMut = useMutation({
    mutationFn: updateRateLimitConfig,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin", "rate-limits", "config"] });
      setEditingGroup(null);
    },
  });

  const config = configQ.data;

  const startEdit = (groupName: string, group: RateLimitGroupConfig) => {
    setEditingGroup(groupName);
    setEditForm({
      window_seconds: String(group.window_seconds),
      max_requests_per_user: String(group.max_requests_per_user),
      max_requests_per_ip: String(group.max_requests_per_ip),
      bypass_roles: group.bypass_roles.join(", "),
    });
  };

  const saveEdit = () => {
    if (!editingGroup) return;
    updateMut.mutate({
      group: editingGroup,
      window_seconds: Number(editForm.window_seconds) || undefined,
      max_requests_per_user: Number(editForm.max_requests_per_user) || undefined,
      max_requests_per_ip: Number(editForm.max_requests_per_ip) || undefined,
      bypass_roles: editForm.bypass_roles
        ? editForm.bypass_roles.split(",").map((s) => s.trim()).filter(Boolean)
        : undefined,
    });
  };

  return (
    <div className="space-y-6">
      {/* Global IP Config */}
      {config?.global_ip && (
        <Card>
          <CardHeader>
            <CardTitle>Global IP Rate Limit</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-6 text-sm">
              <div>
                <span className="text-muted-foreground">Status: </span>
                <Badge variant={config.global_ip.enabled ? "default" : "secondary"}>
                  {config.global_ip.enabled ? "Enabled" : "Disabled"}
                </Badge>
              </div>
              <div>
                <span className="text-muted-foreground">Window: </span>
                <span className="font-medium">{config.global_ip.window_seconds}s</span>
              </div>
              <div>
                <span className="text-muted-foreground">Max Requests: </span>
                <span className="font-medium">{config.global_ip.max_requests}</span>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Endpoint Groups */}
      <Card>
        <CardHeader>
          <CardTitle>Endpoint Group Configuration</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Group</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Window (s)</TableHead>
                <TableHead>Per-User Limit</TableHead>
                <TableHead>Per-IP Limit</TableHead>
                <TableHead>Bypass Roles</TableHead>
                <TableHead>Override</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {config?.groups &&
                Object.entries(config.groups).map(([name, group]) => (
                  <TableRow key={name}>
                    <TableCell className="font-medium">{name}</TableCell>
                    <TableCell className="max-w-[200px] truncate text-xs text-muted-foreground">
                      {group.description}
                    </TableCell>
                    <TableCell>{group.window_seconds}</TableCell>
                    <TableCell>{group.max_requests_per_user}</TableCell>
                    <TableCell>{group.max_requests_per_ip}</TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {group.bypass_roles.map((role) => (
                          <Badge key={role} variant="outline" className="text-xs">
                            {role}
                          </Badge>
                        ))}
                        {group.bypass_roles.length === 0 && (
                          <span className="text-xs text-muted-foreground">none</span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      {group.is_override ? (
                        <Badge variant="default">Custom</Badge>
                      ) : (
                        <Badge variant="secondary">Default</Badge>
                      )}
                    </TableCell>
                    <TableCell>
                      <Dialog
                        open={editingGroup === name}
                        onOpenChange={(open) => {
                          if (!open) setEditingGroup(null);
                        }}
                      >
                        <DialogTrigger asChild>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => startEdit(name, group)}
                          >
                            <Pencil className="h-4 w-4" />
                          </Button>
                        </DialogTrigger>
                        <DialogContent>
                          <DialogHeader>
                            <DialogTitle>Edit: {name}</DialogTitle>
                          </DialogHeader>
                          <div className="space-y-3">
                            <div>
                              <label className="text-sm font-medium">Window (seconds)</label>
                              <Input
                                type="number"
                                value={editForm.window_seconds}
                                onChange={(e) =>
                                  setEditForm({ ...editForm, window_seconds: e.target.value })
                                }
                              />
                            </div>
                            <div>
                              <label className="text-sm font-medium">Max Requests Per User</label>
                              <Input
                                type="number"
                                value={editForm.max_requests_per_user}
                                onChange={(e) =>
                                  setEditForm({ ...editForm, max_requests_per_user: e.target.value })
                                }
                              />
                            </div>
                            <div>
                              <label className="text-sm font-medium">Max Requests Per IP</label>
                              <Input
                                type="number"
                                value={editForm.max_requests_per_ip}
                                onChange={(e) =>
                                  setEditForm({ ...editForm, max_requests_per_ip: e.target.value })
                                }
                              />
                            </div>
                            <div>
                              <label className="text-sm font-medium">
                                Bypass Roles (comma-separated)
                              </label>
                              <Input
                                value={editForm.bypass_roles}
                                onChange={(e) =>
                                  setEditForm({ ...editForm, bypass_roles: e.target.value })
                                }
                                placeholder="root, admin"
                              />
                            </div>
                            <Button onClick={saveEdit} disabled={updateMut.isPending}>
                              <Save className="mr-1 h-4 w-4" />
                              Save
                            </Button>
                          </div>
                        </DialogContent>
                      </Dialog>
                    </TableCell>
                  </TableRow>
                ))}
              {(!config?.groups || Object.keys(config.groups).length === 0) && (
                <TableRow>
                  <TableCell colSpan={8} className="text-center text-muted-foreground">
                    No endpoint groups configured
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
