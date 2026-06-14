import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
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

import { ApiError } from "@/api/client";
import { createProjectTask } from "@/api/endpoints/crmProjects";
import { fromDateInput } from "./projectHelpers";

interface Props {
  projectId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function CreateTaskDialog({ projectId, open, onOpenChange }: Props) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [durationDays, setDurationDays] = useState("1");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [isMilestone, setIsMilestone] = useState(false);
  const [assignedUserSub, setAssignedUserSub] = useState("");

  function reset() {
    setName("");
    setDescription("");
    setDurationDays("1");
    setStartDate("");
    setEndDate("");
    setIsMilestone(false);
    setAssignedUserSub("");
  }

  const mutation = useMutation({
    mutationFn: () =>
      createProjectTask(projectId, {
        name: name.trim(),
        description: description.trim() || null,
        duration_days: Math.max(1, Number(durationDays) || 1),
        start_date: fromDateInput(startDate),
        end_date: fromDateInput(endDate),
        is_milestone: isMilestone,
        assigned_user_sub: assignedUserSub.trim() || null,
      }),
    onSuccess: () => {
      toast.success("Task created");
      qc.invalidateQueries({ queryKey: ["crm-project-tasks", projectId] });
      qc.invalidateQueries({ queryKey: ["crm-project-milestones", projectId] });
      qc.invalidateQueries({ queryKey: ["crm-project-workload", projectId] });
      reset();
      onOpenChange(false);
    },
    onError: (err) => {
      const msg = err instanceof ApiError ? err.detail : "Failed to create task";
      toast.error(msg);
    },
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New task</DialogTitle>
          <DialogDescription>Add a task or milestone to this project.</DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="task-name">Name</Label>
            <Input
              id="task-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Draft wireframes"
              maxLength={200}
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="task-desc">Description</Label>
            <Textarea
              id="task-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              maxLength={2000}
              rows={2}
            />
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div className="space-y-1.5">
              <Label htmlFor="task-dur">Duration (days)</Label>
              <Input
                id="task-dur"
                type="number"
                min={1}
                value={durationDays}
                onChange={(e) => setDurationDays(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="task-start">Start</Label>
              <Input
                id="task-start"
                type="date"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="task-end">End</Label>
              <Input
                id="task-end"
                type="date"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="task-assignee">Assigned user (sub)</Label>
            <Input
              id="task-assignee"
              value={assignedUserSub}
              onChange={(e) => setAssignedUserSub(e.target.value)}
              placeholder="Optional user identifier"
            />
          </div>

          <div className="flex items-center gap-2">
            <Checkbox
              id="task-milestone"
              checked={isMilestone}
              onCheckedChange={(v) => setIsMilestone(v === true)}
            />
            <Label htmlFor="task-milestone" className="cursor-pointer">
              This is a milestone
            </Label>
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
            {mutation.isPending ? "Creating…" : "Create task"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
