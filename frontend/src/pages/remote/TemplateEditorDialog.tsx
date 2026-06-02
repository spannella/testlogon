import { useEffect, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Loader2, Plus, Trash2 } from "lucide-react";

import { Button } from "@/components/ui/button";
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

import { createTemplate, updateTemplate } from "@/api/endpoints/instanceTemplates";
import type {
  InstanceTemplate,
  TemplateCategory,
  TemplateTarget,
  CreateTemplateReq,
} from "@/api/types";

export const TEMPLATES_QUERY_KEY = ["compute", "instance-templates"];

interface TemplateEditorDialogProps {
  open: boolean;
  onClose: () => void;
  template?: InstanceTemplate;
  onSaved?: (template: InstanceTemplate) => void;
}

const CATEGORIES: TemplateCategory[] = ["compute", "database", "web", "ml", "custom"];

interface EnvRow {
  key: string;
  value: string;
}

export function TemplateEditorDialog({
  open,
  onClose,
  template,
  onSaved,
}: TemplateEditorDialogProps) {
  const qc = useQueryClient();
  const isEdit = !!template;

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [category, setCategory] = useState<TemplateCategory>("custom");
  const [target, setTarget] = useState<TemplateTarget>("ec2");
  const [instanceType, setInstanceType] = useState("t3.small");
  const [amiId, setAmiId] = useState("ami-ubuntu-2204");
  const [k8sImage, setK8sImage] = useState("dev-workspace");
  const [k8sPreset, setK8sPreset] = useState("small");
  const [startupScript, setStartupScript] = useState("");
  const [portsStr, setPortsStr] = useState("22");
  const [autoTerminate, setAutoTerminate] = useState(7200);
  const [envRows, setEnvRows] = useState<EnvRow[]>([]);

  useEffect(() => {
    if (!open) return;
    if (template) {
      setName(template.name);
      setDescription(template.description);
      setCategory((template.category as TemplateCategory) || "custom");
      setTarget((template.target as TemplateTarget) || "ec2");
      setInstanceType(template.instance_type || "t3.small");
      setAmiId(template.ami_id || "ami-ubuntu-2204");
      setK8sImage(template.k8s_image || "dev-workspace");
      setK8sPreset(template.k8s_preset || "small");
      setStartupScript(template.startup_script || "");
      setPortsStr((template.ports || []).join(", "));
      setAutoTerminate(template.auto_terminate_after || 7200);
      setEnvRows(
        Object.entries(template.env_vars || {}).map(([key, value]) => ({ key, value })),
      );
    } else {
      setName("");
      setDescription("");
      setCategory("custom");
      setTarget("ec2");
      setInstanceType("t3.small");
      setAmiId("ami-ubuntu-2204");
      setK8sImage("dev-workspace");
      setK8sPreset("small");
      setStartupScript("");
      setPortsStr("22");
      setAutoTerminate(7200);
      setEnvRows([]);
    }
  }, [open, template]);

  const buildBody = (): CreateTemplateReq => {
    const ports = portsStr
      .split(",")
      .map((p) => parseInt(p.trim(), 10))
      .filter((n) => !Number.isNaN(n));
    const env_vars: Record<string, string> = {};
    for (const row of envRows) {
      if (row.key.trim()) env_vars[row.key.trim()] = row.value;
    }
    return {
      name,
      description,
      category,
      target,
      instance_type: target === "ec2" ? instanceType : "",
      ami_id: target === "ec2" ? amiId : "",
      k8s_image: target === "k8s" ? k8sImage : "",
      k8s_preset: target === "k8s" ? k8sPreset : "",
      startup_script: startupScript,
      ports,
      env_vars,
      auto_terminate_after: autoTerminate,
    };
  };

  const mutation = useMutation({
    mutationFn: async () => {
      const body = buildBody();
      if (isEdit && template) {
        return updateTemplate(template.template_id, body);
      }
      return createTemplate(body);
    },
    onSuccess: (saved) => {
      toast.success(isEdit ? "Template updated" : "Template created");
      qc.invalidateQueries({ queryKey: TEMPLATES_QUERY_KEY });
      onSaved?.(saved);
      onClose();
    },
    onError: (err: unknown) => {
      toast.error(err instanceof Error ? err.message : "Failed to save template");
    },
  });

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{isEdit ? "Edit Template" : "Create Template"}</DialogTitle>
          <DialogDescription>
            Save a reusable launch configuration for instances and containers.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="tpl-name">Name</Label>
            <Input
              id="tpl-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="My Dev Environment"
              maxLength={100}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="tpl-desc">Description</Label>
            <Textarea
              id="tpl-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={2}
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-2">
              <Label>Category</Label>
              <Select value={category} onValueChange={(v) => setCategory(v as TemplateCategory)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CATEGORIES.map((c) => (
                    <SelectItem key={c} value={c}>
                      {c}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Target</Label>
              <Select
                value={target}
                onValueChange={(v) => setTarget(v as TemplateTarget)}
                disabled={isEdit}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ec2">EC2</SelectItem>
                  <SelectItem value="k8s">K8s</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          {target === "ec2" ? (
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <Label>Instance Type</Label>
                <Select value={instanceType} onValueChange={setInstanceType}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {["t3.micro", "t3.small", "t3.medium", "t3.large"].map((t) => (
                      <SelectItem key={t} value={t}>
                        {t}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>AMI</Label>
                <Input value={amiId} onChange={(e) => setAmiId(e.target.value)} />
              </div>
            </div>
          ) : (
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <Label>Image</Label>
                <Input value={k8sImage} onChange={(e) => setK8sImage(e.target.value)} />
              </div>
              <div className="space-y-2">
                <Label>Preset</Label>
                <Select value={k8sPreset} onValueChange={setK8sPreset}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {["small", "medium", "large", "xlarge"].map((p) => (
                      <SelectItem key={p} value={p}>
                        {p}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          )}

          <div className="space-y-2">
            <Label>Startup Script</Label>
            <Textarea
              value={startupScript}
              onChange={(e) => setStartupScript(e.target.value)}
              rows={4}
              className="font-mono text-xs"
              placeholder="#!/bin/bash"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-2">
              <Label>Ports (comma-separated)</Label>
              <Input value={portsStr} onChange={(e) => setPortsStr(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label>Auto-terminate (seconds)</Label>
              <Input
                type="number"
                value={autoTerminate}
                onChange={(e) => setAutoTerminate(parseInt(e.target.value, 10) || 7200)}
                min={600}
                max={86400}
              />
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label>Environment Variables</Label>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => setEnvRows([...envRows, { key: "", value: "" }])}
              >
                <Plus className="h-3 w-3 mr-1" /> Add
              </Button>
            </div>
            {envRows.map((row, idx) => (
              <div key={idx} className="flex gap-2">
                <Input
                  placeholder="KEY"
                  value={row.key}
                  onChange={(e) => {
                    const next = [...envRows];
                    next[idx] = { ...next[idx], key: e.target.value };
                    setEnvRows(next);
                  }}
                />
                <Input
                  placeholder="value"
                  value={row.value}
                  onChange={(e) => {
                    const next = [...envRows];
                    next[idx] = { ...next[idx], value: e.target.value };
                    setEnvRows(next);
                  }}
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  onClick={() => setEnvRows(envRows.filter((_, i) => i !== idx))}
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              </div>
            ))}
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={() => mutation.mutate()} disabled={!name.trim() || mutation.isPending}>
            {mutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
            {isEdit ? "Save Changes" : "Create Template"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default TemplateEditorDialog;
