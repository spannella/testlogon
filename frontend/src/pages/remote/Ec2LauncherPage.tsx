import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Cloud,
  Play,
  Square,
  Trash2,
  RotateCw,
  Plus,
  Loader2,
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
import { Textarea } from "@/components/ui/textarea";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import {
  listInstances,
  listInstanceTypes,
  listAmis,
  launchInstance,
  stopInstance,
  startInstance,
  terminateInstance,
  rebootInstance,
} from "@/api/endpoints/ec2";
import type { Ec2InstanceOut } from "@/api/types";

function statusBadge(status: string) {
  const variants: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
    running: "default",
    stopped: "secondary",
    terminated: "destructive",
    launching: "outline",
    stopping: "outline",
    terminating: "outline",
  };
  return (
    <Badge variant={variants[status] ?? "outline"} data-testid={`status-${status}`}>
      {status}
    </Badge>
  );
}

function relativeTime(ts: number): string {
  if (!ts) return "-";
  const diff = Math.floor(Date.now() / 1000 - ts);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export default function Ec2LauncherPage() {
  const queryClient = useQueryClient();
  const [showLaunch, setShowLaunch] = useState(false);
  const [showTermConfirm, setShowTermConfirm] = useState<string | null>(null);

  // Form state for launch dialog
  const [launchLabel, setLaunchLabel] = useState("");
  const [launchType, setLaunchType] = useState("");
  const [launchAmi, setLaunchAmi] = useState("");
  const [launchScript, setLaunchScript] = useState("");

  const instancesQ = useQuery({
    queryKey: ["ec2", "instances"],
    queryFn: () => listInstances(),
    refetchInterval: 10_000,
  });

  const typesQ = useQuery({
    queryKey: ["ec2", "instance-types"],
    queryFn: () => listInstanceTypes(),
  });

  const amisQ = useQuery({
    queryKey: ["ec2", "amis"],
    queryFn: () => listAmis(),
  });

  const launchMut = useMutation({
    mutationFn: launchInstance,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ec2", "instances"] });
      toast.success("Instance launched");
      setShowLaunch(false);
      setLaunchLabel("");
      setLaunchType("");
      setLaunchAmi("");
      setLaunchScript("");
    },
    onError: (err: any) => {
      toast.error(err?.response?.data?.detail || "Launch failed");
    },
  });

  const stopMut = useMutation({
    mutationFn: stopInstance,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ec2", "instances"] });
      toast.success("Instance stopped");
    },
    onError: (err: any) => {
      toast.error(err?.response?.data?.detail || "Stop failed");
    },
  });

  const startMut = useMutation({
    mutationFn: startInstance,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ec2", "instances"] });
      toast.success("Instance started");
    },
    onError: (err: any) => {
      toast.error(err?.response?.data?.detail || "Start failed");
    },
  });

  const terminateMut = useMutation({
    mutationFn: terminateInstance,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ec2", "instances"] });
      toast.success("Instance terminated");
      setShowTermConfirm(null);
    },
    onError: (err: any) => {
      toast.error(err?.response?.data?.detail || "Terminate failed");
    },
  });

  const rebootMut = useMutation({
    mutationFn: rebootInstance,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ec2", "instances"] });
      toast.success("Instance rebooted");
    },
    onError: (err: any) => {
      toast.error(err?.response?.data?.detail || "Reboot failed");
    },
  });

  const instances: Ec2InstanceOut[] = instancesQ.data?.instances ?? [];
  const types = typesQ.data?.types ?? [];
  const amis = amisQ.data?.amis ?? [];

  return (
    <div className="mx-auto max-w-5xl space-y-6 p-6">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div className="flex items-center gap-2">
            <Cloud className="h-5 w-5" />
            <CardTitle>EC2 Instances</CardTitle>
          </div>
          <Button onClick={() => setShowLaunch(true)} data-testid="launch-btn">
            <Plus className="mr-1 h-4 w-4" /> Launch Instance
          </Button>
        </CardHeader>
        <CardContent>
          {instancesQ.isLoading ? (
            <div className="flex justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin" />
            </div>
          ) : instances.length === 0 ? (
            <p className="text-center text-muted-foreground py-12" data-testid="empty-state">
              No instances running. Launch your first EC2 instance.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Label</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {instances.map((inst) => (
                  <TableRow key={inst.instance_id} data-testid={`instance-${inst.instance_id}`}>
                    <TableCell className="font-medium">{inst.label}</TableCell>
                    <TableCell>{inst.instance_type}</TableCell>
                    <TableCell>{statusBadge(inst.status)}</TableCell>
                    <TableCell className="font-mono text-sm">{inst.public_ip || "-"}</TableCell>
                    <TableCell>{relativeTime(inst.created_at)}</TableCell>
                    <TableCell className="text-right space-x-1">
                      {inst.status === "running" && (
                        <>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => stopMut.mutate(inst.instance_id)}
                            data-testid={`stop-${inst.instance_id}`}
                          >
                            <Square className="h-3 w-3 mr-1" /> Stop
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => rebootMut.mutate(inst.instance_id)}
                            data-testid={`reboot-${inst.instance_id}`}
                          >
                            <RotateCw className="h-3 w-3 mr-1" /> Reboot
                          </Button>
                        </>
                      )}
                      {inst.status === "stopped" && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => startMut.mutate(inst.instance_id)}
                          data-testid={`start-${inst.instance_id}`}
                        >
                          <Play className="h-3 w-3 mr-1" /> Start
                        </Button>
                      )}
                      {inst.status !== "terminated" && (
                        <Button
                          size="sm"
                          variant="destructive"
                          onClick={() => setShowTermConfirm(inst.instance_id)}
                          data-testid={`terminate-${inst.instance_id}`}
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
            <DialogTitle>Launch EC2 Instance</DialogTitle>
            <DialogDescription>
              Choose an instance type, AMI, and provide a label.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div>
              <Label htmlFor="ec2-label">Label</Label>
              <Input
                id="ec2-label"
                placeholder="My instance"
                value={launchLabel}
                onChange={(e) => setLaunchLabel(e.target.value)}
                data-testid="launch-label"
              />
            </div>
            <div>
              <Label>Instance Type</Label>
              <Select value={launchType} onValueChange={setLaunchType}>
                <SelectTrigger data-testid="launch-type">
                  <SelectValue placeholder="Select type" />
                </SelectTrigger>
                <SelectContent>
                  {types.map((t) => (
                    <SelectItem key={t.instance_type} value={t.instance_type}>
                      {t.instance_type} ({t.vcpu} vCPU, {t.memory_gb} GB)
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>AMI</Label>
              <Select value={launchAmi} onValueChange={setLaunchAmi}>
                <SelectTrigger data-testid="launch-ami">
                  <SelectValue placeholder="Select AMI" />
                </SelectTrigger>
                <SelectContent>
                  {amis.map((a) => (
                    <SelectItem key={a.ami_id} value={a.ami_id}>
                      {a.name} ({a.os_type})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label htmlFor="ec2-startup">Startup Script (optional)</Label>
              <Textarea
                id="ec2-startup"
                placeholder="#!/bin/bash"
                value={launchScript}
                onChange={(e) => setLaunchScript(e.target.value)}
                data-testid="launch-script"
                rows={3}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowLaunch(false)}>
              Cancel
            </Button>
            <Button
              disabled={!launchLabel || !launchType || !launchAmi || launchMut.isPending}
              onClick={() =>
                launchMut.mutate({
                  label: launchLabel,
                  instance_type: launchType,
                  ami_id: launchAmi,
                  startup_script: launchScript,
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
            <DialogTitle>Terminate Instance?</DialogTitle>
            <DialogDescription>
              This action is irreversible. The instance and its data will be permanently destroyed.
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
    </div>
  );
}
