/**
 * Dialog to add a candidate to a job order's pipeline (PIP-001).
 * Lets the user enter a candidate ID and optionally select an initial status.
 */
import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ApiError } from "@/api/client";
import {
  addToPipeline,
  type PipelineStatusItem,
} from "@/api/endpoints/atsPipeline";

interface AddCandidateToPipelineDialogProps {
  jobOrderId: string;
  statuses: PipelineStatusItem[];
  onClose: () => void;
  onAdded: () => void;
}

export function AddCandidateToPipelineDialog({
  jobOrderId,
  statuses,
  onClose,
  onAdded,
}: AddCandidateToPipelineDialogProps) {
  const [candidateId, setCandidateId] = useState("");
  const [status, setStatus] = useState<string>(
    statuses.find((s) => !s.is_placed && !s.is_terminal)?.status_key ?? "",
  );

  const mut = useMutation({
    mutationFn: () =>
      addToPipeline({
        job_order_id: jobOrderId,
        candidate_id: candidateId.trim(),
        status: status || undefined,
      }),
    onSuccess: () => {
      toast.success("Candidate added to pipeline");
      onAdded();
    },
    onError: (err: unknown) => {
      if (err instanceof ApiError) {
        if (err.status === 409) {
          toast.error("Candidate is already in this job order's pipeline.");
        } else if (err.status === 503) {
          toast.error("ATS Pipeline feature is not enabled.");
        } else if (err.status === 404) {
          toast.error("Candidate or job order not found.");
        } else {
          toast.error(err.detail || "Failed to add candidate to pipeline.");
        }
      } else {
        toast.error("Failed to add candidate to pipeline.");
      }
    },
  });

  const canSubmit = candidateId.trim().length > 0 && !mut.isPending;

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Add Candidate to Pipeline</DialogTitle>
          <DialogDescription>
            Enter the candidate ID and initial stage to add them to this job order's pipeline.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <div className="space-y-1.5">
            <Label htmlFor="cand-id">Candidate ID</Label>
            <Input
              id="cand-id"
              placeholder="cnd_abc123…"
              value={candidateId}
              onChange={(e) => setCandidateId(e.target.value)}
              autoFocus
            />
            <p className="text-xs text-muted-foreground">
              Find candidate IDs in the{" "}
              <a href="/ats/candidates" className="underline">
                Candidates list
              </a>
              .
            </p>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="init-status">Initial Stage</Label>
            <Select value={status} onValueChange={setStatus}>
              <SelectTrigger id="init-status">
                <SelectValue placeholder="Select initial stage…" />
              </SelectTrigger>
              <SelectContent>
                {statuses.map((s) => (
                  <SelectItem key={s.status_key} value={s.status_key}>
                    {s.label}
                    {s.is_placed ? " (Placed)" : ""}
                    {s.is_terminal ? " (Terminal)" : ""}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={mut.isPending}>
            Cancel
          </Button>
          <Button
            onClick={() => mut.mutate()}
            disabled={!canSubmit}
          >
            {mut.isPending ? "Adding…" : "Add to Pipeline"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
