import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { approveDeployment, rejectDeployment } from "@/api/endpoints/devopsAgent";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle } from "lucide-react";
import type { DevOpsOutput } from "@/api/types";

interface Props {
  runId: string;
  output: DevOpsOutput;
}

export default function DeploymentApprovalPanel({ runId, output }: Props) {
  const queryClient = useQueryClient();
  const [notes, setNotes] = useState("");

  const approveMut = useMutation({
    mutationFn: () => approveDeployment(runId, notes),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["devops-output", runId] }),
  });
  const rejectMut = useMutation({
    mutationFn: () => rejectDeployment(runId, notes),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["devops-output", runId] }),
  });

  return (
    <div data-testid="deployment-approval-panel" className="space-y-4">
      <div className="flex items-center gap-2 rounded border border-amber-500 bg-amber-50 p-3 text-amber-900 dark:bg-amber-950/30 dark:text-amber-200">
        <AlertTriangle className="h-5 w-5" />
        <span className="font-semibold">Production Deployment Pending Approval</span>
        <Badge variant="secondary">{output.environment}</Badge>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Deployment Plan</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <p>
            Deployment: <code>{output.deployment_id}</code>
          </p>
          <p>Version: {output.version_deployed ?? "(latest)"}</p>
          <p>Steps: {output.steps_completed} / {output.steps_total}</p>
        </CardContent>
      </Card>
      <div>
        <Textarea
          data-testid="approver-notes"
          placeholder="Approver notes"
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
        />
      </div>
      <div className="flex gap-2">
        <Button
          data-testid="approve-btn"
          onClick={() => approveMut.mutate()}
          disabled={approveMut.isPending || rejectMut.isPending}
        >
          Approve
        </Button>
        <Button
          data-testid="reject-btn"
          variant="destructive"
          onClick={() => rejectMut.mutate()}
          disabled={approveMut.isPending || rejectMut.isPending}
        >
          Reject
        </Button>
      </div>
    </div>
  );
}
