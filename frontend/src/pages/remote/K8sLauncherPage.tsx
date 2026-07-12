import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Container,
  Plus,
  Loader2,
  Trash2,
  ScrollText,
  X,
  Terminal,
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
  listPods,
  listImages,
  listPresets,
  launchPod,
  terminatePod,
  getPodLogs,
} from "@/api/endpoints/k8s";
import type { K8sPodOut } from "@/api/types";

function statusBadge(status: string) {
  const variants: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
    running: "default",
    pending: "outline",
    failed: "destructive",
    terminated: "secondary",
    succeeded: "outline",
  };
  return (
    <Badge variant={variants[status] ?? "outline"} data-testid={`status-${status}`}>
      {status}
    </Badge>
  );
}

function ttlCountdown(expiresAt: number): string {
  if (!expiresAt) return "-";
  const remaining = expiresAt - Math.floor(Date.now() / 1000);
  if (remaining <= 0) return "expired";
  const h = Math.floor(remaining / 3600);
  const m = Math.floor((remaining % 3600) / 60);
  return `${h}h ${m}m`;
}

function relativeTime(ts: number): string {
  if (!ts) return "-";
  const diff = Math.floor(Date.now() / 1000 - ts);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export default function K8sLauncherPage() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [showLaunch, setShowLaunch] = useState(false);
  const [showTermConfirm, setShowTermConfirm] = useState<string | null>(null);
  const [showLogs, setShowLogs] = useState<string | null>(null);

  // Form state for launch dialog
  const [launchLabel, setLaunchLabel] = useState("");
  const [launchImage, setLaunchImage] = useState("");
  const [launchPreset, setLaunchPreset] = useState("small");

  const podsQ = useQuery({
    queryKey: ["k8s", "pods"],
    queryFn: () => listPods(),
    refetchInterval: 10_000,
  });

  const imagesQ = useQuery({
    queryKey: ["k8s", "images"],
    queryFn: () => listImages(),
  });

  const presetsQ = useQuery({
    queryKey: ["k8s", "presets"],
    queryFn: () => listPresets(),
  });

  const logsQ = useQuery({
    queryKey: ["k8s", "logs", showLogs],
    queryFn: () => (showLogs ? getPodLogs(showLogs, 100) : Promise.resolve(null)),
    enabled: !!showLogs,
    refetchInterval: showLogs ? 5_000 : false,
  });

  const launchMut = useMutation({
    mutationFn: launchPod,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["k8s", "pods"] });
      toast.success("Container launched");
      setShowLaunch(false);
      setLaunchLabel("");
      setLaunchImage("");
      setLaunchPreset("small");
    },
    onError: (err: any) => {
      toast.error(err?.response?.data?.detail || "Launch failed");
    },
  });

  const terminateMut = useMutation({
    mutationFn: terminatePod,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["k8s", "pods"] });
      toast.success("Container terminated");
      setShowTermConfirm(null);
    },
    onError: (err: any) => {
      toast.error(err?.response?.data?.detail || "Terminate failed");
    },
  });

  const pods: K8sPodOut[] = podsQ.data?.pods ?? [];
  const images = imagesQ.data?.images ?? [];
  const presets = presetsQ.data?.presets ?? [];

  return (
    <div className="mx-auto max-w-5xl space-y-6 p-6">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div className="flex items-center gap-2">
            <Container className="h-5 w-5" />
            <CardTitle>Containers</CardTitle>
          </div>
          <Button onClick={() => setShowLaunch(true)} data-testid="launch-btn">
            <Plus className="mr-1 h-4 w-4" /> Launch Container
          </Button>
        </CardHeader>
        <CardContent>
          {podsQ.isLoading ? (
            <div className="flex justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin" />
            </div>
          ) : pods.length === 0 ? (
            <p className="text-center text-muted-foreground py-12" data-testid="empty-state">
              No containers running. Launch your first container.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Label</TableHead>
                  <TableHead>Image</TableHead>
                  <TableHead>Preset</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Pod IP</TableHead>
                  <TableHead>TTL Remaining</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pods.map((pod) => (
                  <TableRow key={pod.pod_id} data-testid={`pod-${pod.pod_id}`}>
                    <TableCell className="font-medium">{pod.label}</TableCell>
                    <TableCell>{pod.image_display_name}</TableCell>
                    <TableCell>{pod.preset}</TableCell>
                    <TableCell>{statusBadge(pod.status)}</TableCell>
                    <TableCell className="font-mono text-sm">{pod.pod_ip || "-"}</TableCell>
                    <TableCell data-testid={`ttl-${pod.pod_id}`}>
                      {pod.status === "running" ? ttlCountdown(pod.expires_at) : "-"}
                    </TableCell>
                    <TableCell>{relativeTime(pod.created_at)}</TableCell>
                    <TableCell className="text-right space-x-1">
                      {pod.status === "running" && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => setShowLogs(pod.pod_id)}
                          data-testid={`logs-${pod.pod_id}`}
                        >
                          <ScrollText className="h-3 w-3 mr-1" /> View Logs
                        </Button>
                      )}
                      {pod.status === "running" && (pod.host_id || pod.service_hostname) && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() =>
                            navigate(
                              pod.host_id
                                ? `/remote/ssh?host_id=${encodeURIComponent(pod.host_id)}`
                                : `/remote/ssh?host=${encodeURIComponent(pod.service_hostname)}`,
                            )
                          }
                          data-testid={`open-terminal-${pod.pod_id}`}
                        >
                          <Terminal className="h-3 w-3 mr-1" /> Open terminal
                        </Button>
                      )}
                      {pod.status !== "terminated" && (
                        <Button
                          size="sm"
                          variant="destructive"
                          onClick={() => setShowTermConfirm(pod.pod_id)}
                          data-testid={`terminate-${pod.pod_id}`}
                        >
                          <Trash2 className="h-3 w-3 mr-1" /> Terminate
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Launch dialog */}
      <Dialog open={showLaunch} onOpenChange={setShowLaunch}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Launch Container</DialogTitle>
            <DialogDescription>
              Choose a container image, resource preset, and provide a label.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div>
              <Label htmlFor="k8s-label">Label</Label>
              <Input
                id="k8s-label"
                placeholder="My container"
                value={launchLabel}
                onChange={(e) => setLaunchLabel(e.target.value)}
                data-testid="launch-label"
              />
            </div>
            <div>
              <Label>Image</Label>
              <Select value={launchImage} onValueChange={setLaunchImage}>
                <SelectTrigger data-testid="launch-image">
                  <SelectValue placeholder="Select image" />
                </SelectTrigger>
                <SelectContent>
                  {images.map((img) => (
                    <SelectItem key={img.image} value={img.image}>
                      {img.display_name} ({img.os_type})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Resource Preset</Label>
              <Select value={launchPreset} onValueChange={setLaunchPreset}>
                <SelectTrigger data-testid="launch-preset">
                  <SelectValue placeholder="Select preset" />
                </SelectTrigger>
                <SelectContent>
                  {presets.map((p) => (
                    <SelectItem key={p.preset} value={p.preset}>
                      {p.preset} ({p.cpu_millicores}m CPU, {p.memory_mb}MB RAM)
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowLaunch(false)}>
              Cancel
            </Button>
            <Button
              disabled={!launchLabel || !launchImage || launchMut.isPending}
              onClick={() =>
                launchMut.mutate({
                  label: launchLabel,
                  image: launchImage,
                  preset: launchPreset as any,
                })
              }
              data-testid="launch-submit"
            >
              {launchMut.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : null}
              Launch
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Terminate confirmation dialog */}
      <Dialog open={!!showTermConfirm} onOpenChange={() => setShowTermConfirm(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Terminate Container?</DialogTitle>
            <DialogDescription>
              This action is irreversible. The container and its data will be permanently destroyed.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowTermConfirm(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => showTermConfirm && terminateMut.mutate(showTermConfirm)}
              data-testid="confirm-terminate"
            >
              Terminate
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Log viewer slide-over */}
      <Dialog open={!!showLogs} onOpenChange={() => setShowLogs(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh]">
          <DialogHeader>
            <DialogTitle>Container Logs</DialogTitle>
            <DialogDescription>
              Recent log output from the container.
            </DialogDescription>
          </DialogHeader>
          <div
            className="bg-muted rounded p-4 font-mono text-sm overflow-auto max-h-[50vh]"
            data-testid="log-output"
          >
            {logsQ.isLoading ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : logsQ.data?.lines?.length ? (
              logsQ.data.lines.map((line, i) => (
                <div key={i}>{line}</div>
              ))
            ) : (
              <span className="text-muted-foreground">No logs available.</span>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowLogs(null)}>
              <X className="h-4 w-4 mr-1" /> Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
