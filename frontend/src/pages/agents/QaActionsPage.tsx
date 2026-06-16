import { useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  TerminalSquare,
  Play,
  Square,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Clock,
  AlertTriangle,
  ShieldAlert,
} from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import { listWorkers } from "@/api/endpoints/agentWorkers";
import { hostInventoryApi } from "@/api/endpoints/hostInventory";
import {
  submitAgentAction,
  listAgentActions,
  cancelAgentAction,
} from "@/api/endpoints/agentActions";
import type {
  AgentActionOut,
  AgentActionStatus,
  AgentActionType,
} from "@/api/types";
import { isAgentSshQaEnabled } from "@/lib/featureFlags";

const TERMINAL: AgentActionStatus[] = [
  "completed",
  "failed",
  "timed_out",
  "cancelled",
  "denied",
];

function statusBadge(status: AgentActionStatus) {
  switch (status) {
    case "completed":
      return (
        <Badge variant="outline" className="border-green-500 text-green-600">
          <CheckCircle2 className="mr-1 h-3 w-3" />
          Completed
        </Badge>
      );
    case "failed":
      return (
        <Badge variant="outline" className="border-red-500 text-red-600">
          <XCircle className="mr-1 h-3 w-3" />
          Failed
        </Badge>
      );
    case "timed_out":
      return (
        <Badge variant="outline" className="border-orange-500 text-orange-600">
          <AlertTriangle className="mr-1 h-3 w-3" />
          Timed out
        </Badge>
      );
    case "denied":
      return (
        <Badge variant="outline" className="border-red-500 text-red-600">
          <ShieldAlert className="mr-1 h-3 w-3" />
          Denied
        </Badge>
      );
    case "running":
      return (
        <Badge variant="outline" className="border-blue-500 text-blue-600">
          <RefreshCw className="mr-1 h-3 w-3 animate-spin" />
          Running
        </Badge>
      );
    case "cancelled":
      return <Badge variant="outline">Cancelled</Badge>;
    default:
      return (
        <Badge variant="outline" className="border-yellow-500 text-yellow-600">
          <Clock className="mr-1 h-3 w-3" />
          Pending
        </Badge>
      );
  }
}

function ActionRow({
  action,
  workerId,
}: {
  action: AgentActionOut;
  workerId: string;
}) {
  const queryClient = useQueryClient();
  const cancelMut = useMutation({
    mutationFn: () => cancelAgentAction(workerId, action.action_id),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ["qa-actions", workerId] }),
  });
  const isTerminal = TERMINAL.includes(action.status);
  const hasOutput = action.stdout_tail || action.stderr_tail;

  return (
    <Card>
      <CardContent className="space-y-2 p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            {statusBadge(action.status)}
            <Badge variant="secondary">{action.action_type}</Badge>
            {action.exit_code != null && (
              <span className="text-xs text-muted-foreground">
                exit {action.exit_code}
              </span>
            )}
          </div>
          {!isTerminal && (
            <Button
              size="sm"
              variant="ghost"
              onClick={() => cancelMut.mutate()}
              disabled={cancelMut.isPending}
            >
              <Square className="mr-1 h-3 w-3" />
              Cancel
            </Button>
          )}
        </div>
        <pre className="overflow-x-auto rounded bg-muted px-2 py-1 text-xs">
          {action.command}
        </pre>
        {action.error_message && (
          <p className="text-xs text-red-600">
            {action.error_code}: {action.error_message}
          </p>
        )}
        {hasOutput && (
          <div className="space-y-1">
            {action.stdout_tail && (
              <pre className="max-h-48 overflow-auto rounded bg-black px-2 py-1 text-xs text-green-300">
                {action.stdout_tail}
              </pre>
            )}
            {action.stderr_tail && (
              <pre className="max-h-32 overflow-auto rounded bg-black px-2 py-1 text-xs text-red-300">
                {action.stderr_tail}
              </pre>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default function QaActionsPage() {
  const queryClient = useQueryClient();
  const [workerId, setWorkerId] = useState<string>("");
  const [hostId, setHostId] = useState<string>("");
  const [actionType, setActionType] = useState<AgentActionType>("run_command");
  const [command, setCommand] = useState<string>("");

  const enabled = isAgentSshQaEnabled();

  const workersQuery = useQuery({
    queryKey: ["agent-workers", "qa-actions"],
    queryFn: () => listWorkers(),
    enabled,
  });
  const hostsQuery = useQuery({
    queryKey: ["hosts", "qa-actions"],
    queryFn: () => hostInventoryApi.list({ protocol: "ssh" }),
    enabled,
  });

  const actionsQuery = useQuery({
    queryKey: ["qa-actions", workerId],
    queryFn: () => listAgentActions(workerId),
    enabled: enabled && !!workerId,
    refetchInterval: 5_000,
  });

  const submitMut = useMutation({
    mutationFn: () =>
      submitAgentAction(workerId, {
        action_type: actionType,
        command,
        host_id: hostId || undefined,
      }),
    onSuccess: () => {
      setCommand("");
      queryClient.invalidateQueries({ queryKey: ["qa-actions", workerId] });
    },
  });

  const workers = workersQuery.data?.workers ?? [];
  const hosts = hostsQuery.data?.hosts ?? [];
  const actions = actionsQuery.data?.actions ?? [];

  const submitError = useMemo(() => {
    const err = submitMut.error as
      | { response?: { data?: { detail?: { message?: string } | string } } }
      | undefined;
    const detail = err?.response?.data?.detail;
    if (!detail) return "";
    return typeof detail === "string" ? detail : detail.message ?? "";
  }, [submitMut.error]);

  if (!enabled) {
    return (
      <div className="mx-auto max-w-2xl p-6">
        <Card>
          <CardContent className="p-6 text-center text-muted-foreground">
            Agent SSH QA is not enabled. Set{" "}
            <code>VITE_AGENT_SSH_QA_ENABLED=true</code> (and the backend{" "}
            <code>AGENT_SSH_QA_ENABLED</code>) to use this page.
          </CardContent>
        </Card>
      </div>
    );
  }

  const canSubmit = !!workerId && command.trim().length > 0;

  return (
    <div className="mx-auto max-w-3xl space-y-6 p-6">
      <div className="flex items-center gap-2">
        <TerminalSquare className="h-6 w-6" />
        <h1 className="text-2xl font-semibold">Agent QA Actions</h1>
      </div>
      <p className="text-sm text-muted-foreground">
        Run a non-interactive QA command or test suite on a registered host
        through an agent worker. Credentials are resolved server-side — you only
        choose a worker and a host.
      </p>

      <Card>
        <CardHeader>
          <CardTitle>Submit a QA action</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1">
              <Label>Worker</Label>
              <Select value={workerId} onValueChange={setWorkerId}>
                <SelectTrigger>
                  <SelectValue placeholder="Select a worker" />
                </SelectTrigger>
                <SelectContent>
                  {workers.map((w) => (
                    <SelectItem key={w.worker_id} value={w.worker_id}>
                      {w.label || w.worker_id} ({w.worker_status})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label>Host (optional — defaults to worker host)</Label>
              <Select value={hostId} onValueChange={setHostId}>
                <SelectTrigger>
                  <SelectValue placeholder="Worker default host" />
                </SelectTrigger>
                <SelectContent>
                  {hosts.map((h) => (
                    <SelectItem key={h.host_id} value={h.host_id}>
                      {h.label} ({h.hostname})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-1">
            <Label>Action type</Label>
            <Select
              value={actionType}
              onValueChange={(v) => setActionType(v as AgentActionType)}
            >
              <SelectTrigger className="w-56">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="run_command">Run command</SelectItem>
                <SelectItem value="run_test_suite">Run test suite</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-1">
            <Label>Command / script</Label>
            <Textarea
              value={command}
              onChange={(e) => setCommand(e.target.value)}
              placeholder="pytest -q"
              rows={3}
              className="font-mono text-sm"
            />
          </div>

          {submitError && (
            <p className="text-sm text-red-600">{submitError}</p>
          )}

          <Button
            onClick={() => submitMut.mutate()}
            disabled={!canSubmit || submitMut.isPending}
          >
            <Play className="mr-1 h-4 w-4" />
            {submitMut.isPending ? "Submitting…" : "Submit action"}
          </Button>
        </CardContent>
      </Card>

      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Recent actions</h2>
        {workerId && (
          <Button
            size="sm"
            variant="ghost"
            onClick={() =>
              queryClient.invalidateQueries({
                queryKey: ["qa-actions", workerId],
              })
            }
          >
            <RefreshCw className="mr-1 h-3 w-3" />
            Refresh
          </Button>
        )}
      </div>

      {!workerId && (
        <p className="text-sm text-muted-foreground">
          Select a worker to view its QA actions.
        </p>
      )}
      {workerId && actions.length === 0 && (
        <p className="text-sm text-muted-foreground">No actions yet.</p>
      )}
      <div className="space-y-3">
        {actions.map((a) => (
          <ActionRow key={a.action_id} action={a} workerId={workerId} />
        ))}
      </div>
    </div>
  );
}
