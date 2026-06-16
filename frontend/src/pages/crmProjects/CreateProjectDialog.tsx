import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
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
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import { ApiError } from "@/api/client";
import {
  createCrmProject,
  type CrmProjectOut,
  type CrmProjectStatus,
} from "@/api/endpoints/crmProjects";
import {
  PROJECT_STATUSES,
  PROJECT_STATUS_LABELS,
  PRIORITY_LABELS,
  fromDateInput,
} from "./projectHelpers";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated?: (project: CrmProjectOut) => void;
}

export function CreateProjectDialog({ open, onOpenChange, onCreated }: Props) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [status, setStatus] = useState<CrmProjectStatus>("draft");
  const [priority, setPriority] = useState("0");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");

  function reset() {
    setName("");
    setDescription("");
    setStatus("draft");
    setPriority("0");
    setStartDate("");
    setEndDate("");
  }

  const mutation = useMutation({
    mutationFn: () =>
      createCrmProject({
        name: name.trim(),
        description: description.trim() || null,
        status,
        priority: Number(priority),
        start_date: fromDateInput(startDate),
        end_date: fromDateInput(endDate),
      }),
    onSuccess: (project) => {
      toast.success("Project created");
      qc.invalidateQueries({ queryKey: ["crm-projects"] });
      reset();
      onOpenChange(false);
      onCreated?.(project);
    },
    onError: (err) => {
      const msg = err instanceof ApiError ? err.detail : "Failed to create project";
      toast.error(msg);
    },
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New project</DialogTitle>
          <DialogDescription>
            Create a SuiteCRM project to track tasks, milestones, and team
            assignments.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="proj-name">Name</Label>
            <Input
              id="proj-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Q3 Website Redesign"
              maxLength={120}
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="proj-desc">Description</Label>
            <Textarea
              id="proj-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Optional summary"
              maxLength={2000}
              rows={3}
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label>Status</Label>
              <Select value={status} onValueChange={(v) => setStatus(v as CrmProjectStatus)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {PROJECT_STATUSES.map((s) => (
                    <SelectItem key={s} value={s}>
                      {PROJECT_STATUS_LABELS[s]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-1.5">
              <Label>Priority</Label>
              <Select value={priority} onValueChange={setPriority}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {Object.entries(PRIORITY_LABELS).map(([val, label]) => (
                    <SelectItem key={val} value={val}>
                      {label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label htmlFor="proj-start">Start date</Label>
              <Input
                id="proj-start"
                type="date"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="proj-end">End date</Label>
              <Input
                id="proj-end"
                type="date"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
              />
            </div>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={() => mutation.mutate()}
            disabled={!name.trim() || mutation.isPending}
          >
            {mutation.isPending ? "Creating…" : "Create project"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
