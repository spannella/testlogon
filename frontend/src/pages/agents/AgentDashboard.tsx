import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  getAgentStatus,
  startAgent,
  pauseAgent,
  resumeAgent,
  stopAgent,
  releaseTicket,
  getEligibleTickets,
  updateTicketFilter,
  sendHeartbeat,
  getCheckpoint,
} from "@/api/endpoints/agentOrchestrator";
import type {
  AgentStatus,
  AgentState,
  EligibleTicketsResponse,
  TicketFilterConfig,
  CheckpointData,
} from "@/api/types";

const STATE_COLORS: Record<AgentState, string> = {
  idle: "bg-green-100 text-green-800",
  claiming: "bg-yellow-100 text-yellow-800",
  working: "bg-blue-100 text-blue-800",
  awaiting_feedback: "bg-orange-100 text-orange-800",
  completing: "bg-green-200 text-green-900",
  paused: "bg-gray-100 text-gray-800",
  error: "bg-red-100 text-red-800",
};

function HeartbeatIndicator({ heartbeatAt }: { heartbeatAt: number }) {
  const now = Math.floor(Date.now() / 1000);
  const age = heartbeatAt > 0 ? now - heartbeatAt : -1;
  let color = "bg-gray-400";
  if (age >= 0 && age < 30) color = "bg-green-500";
  else if (age >= 30 && age < 90) color = "bg-yellow-500";
  else if (age >= 90) color = "bg-red-500";

  return (
    <div className="flex items-center gap-2">
      <div className={`h-3 w-3 rounded-full ${color}`} />
      <span className="text-sm text-muted-foreground">
        {age < 0 ? "No heartbeat" : `Last heartbeat: ${age}s ago`}
      </span>
    </div>
  );
}

export default function AgentDashboard() {
  const [workerId, setWorkerId] = useState("");
  const [activeWorkerId, setActiveWorkerId] = useState("");
  const queryClient = useQueryClient();

  const statusQuery = useQuery({
    queryKey: ["agent-orchestrator", "status", activeWorkerId],
    queryFn: () => getAgentStatus(activeWorkerId),
    enabled: !!activeWorkerId,
    refetchInterval: 5000,
  });

  const eligibleQuery = useQuery({
    queryKey: ["agent-orchestrator", "eligible", activeWorkerId],
    queryFn: () => getEligibleTickets(activeWorkerId),
    enabled: !!activeWorkerId,
    staleTime: 30000,
  });

  const checkpointQuery = useQuery({
    queryKey: ["agent-orchestrator", "checkpoint", activeWorkerId],
    queryFn: () => getCheckpoint(activeWorkerId),
    enabled: !!activeWorkerId && !!statusQuery.data?.current_ticket_id,
  });

  const invalidateAll = () => {
    queryClient.invalidateQueries({ queryKey: ["agent-orchestrator"] });
  };

  const startMut = useMutation({ mutationFn: () => startAgent(activeWorkerId), onSuccess: invalidateAll });
  const pauseMut = useMutation({ mutationFn: () => pauseAgent(activeWorkerId), onSuccess: invalidateAll });
  const resumeMut = useMutation({ mutationFn: () => resumeAgent(activeWorkerId), onSuccess: invalidateAll });
  const stopMut = useMutation({ mutationFn: () => stopAgent(activeWorkerId), onSuccess: invalidateAll });
  const releaseMut = useMutation({ mutationFn: () => releaseTicket(activeWorkerId), onSuccess: invalidateAll });
  const heartbeatMut = useMutation({ mutationFn: () => sendHeartbeat(activeWorkerId), onSuccess: invalidateAll });

  const status = statusQuery.data as AgentStatus | undefined;
  const eligible = eligibleQuery.data as EligibleTicketsResponse | undefined;
  const checkpoint = checkpointQuery.data as CheckpointData | undefined;

  const [filterTypes, setFilterTypes] = useState("");
  const [filterPriorities, setFilterPriorities] = useState("");

  const filterMut = useMutation({
    mutationFn: (filter: TicketFilterConfig) => updateTicketFilter(activeWorkerId, filter),
    onSuccess: invalidateAll,
  });

  const handleSaveFilter = () => {
    filterMut.mutate({
      types: filterTypes ? filterTypes.split(",").map((s) => s.trim()) : [],
      tags: [],
      space_ids: [],
      priorities: filterPriorities ? filterPriorities.split(",").map((s) => s.trim()) : [],
    });
  };

  return (
    <div className="space-y-6 p-6">
      <h1 className="text-2xl font-bold">Agent Dashboard</h1>

      {/* Worker ID input */}
      <Card>
        <CardHeader>
          <CardTitle>Select Worker</CardTitle>
        </CardHeader>
        <CardContent className="flex gap-2">
          <Input
            placeholder="Enter worker ID..."
            value={workerId}
            onChange={(e) => setWorkerId(e.target.value)}
          />
          <Button onClick={() => setActiveWorkerId(workerId)}>Load</Button>
        </CardContent>
      </Card>

      {activeWorkerId && status && (
        <>
          {/* Agent State Card */}
          <Card>
            <CardHeader>
              <CardTitle>Agent State</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center gap-4">
                <Badge className={STATE_COLORS[status.agent_state] || "bg-gray-100"}>
                  {status.agent_state}
                </Badge>
                <HeartbeatIndicator heartbeatAt={status.heartbeat_at} />
                {status.loop_running && (
                  <Badge variant="outline" className="border-green-500 text-green-700">
                    Loop Running
                  </Badge>
                )}
              </div>

              {status.current_ticket_id && (
                <div className="rounded border p-3">
                  <p className="text-sm font-medium">Current Ticket</p>
                  <p className="text-sm text-muted-foreground">{status.current_ticket_id}</p>
                  {status.current_ticket_title && (
                    <p className="text-sm">{status.current_ticket_title}</p>
                  )}
                </div>
              )}

              {/* Control buttons */}
              <div className="flex flex-wrap gap-2">
                <Button
                  size="sm"
                  onClick={() => startMut.mutate()}
                  disabled={status.loop_running}
                >
                  Start Agent
                </Button>
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={() => pauseMut.mutate()}
                  disabled={status.agent_state === "paused"}
                >
                  Pause
                </Button>
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={() => resumeMut.mutate()}
                  disabled={status.agent_state !== "paused"}
                >
                  Resume
                </Button>
                <Button
                  size="sm"
                  variant="destructive"
                  onClick={() => stopMut.mutate()}
                >
                  Stop
                </Button>
                {status.current_ticket_id && (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => releaseMut.mutate()}
                  >
                    Release Ticket
                  </Button>
                )}
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => heartbeatMut.mutate()}
                >
                  Heartbeat
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Stats */}
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <Card>
              <CardContent className="p-4">
                <p className="text-sm text-muted-foreground">Tickets Completed</p>
                <p className="text-2xl font-bold">{status.tickets_completed}</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <p className="text-sm text-muted-foreground">Tickets Failed</p>
                <p className="text-2xl font-bold">{status.tickets_failed}</p>
              </CardContent>
            </Card>
          </div>

          {/* Ticket Filter */}
          <Card>
            <CardHeader>
              <CardTitle>Ticket Filter</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label>Types (comma-separated)</Label>
                <Input
                  value={filterTypes}
                  onChange={(e) => setFilterTypes(e.target.value)}
                  placeholder="bug, feature, task"
                />
              </div>
              <div>
                <Label>Priorities (comma-separated)</Label>
                <Input
                  value={filterPriorities}
                  onChange={(e) => setFilterPriorities(e.target.value)}
                  placeholder="critical, high, medium"
                />
              </div>
              <Button size="sm" onClick={handleSaveFilter}>
                Save Filter
              </Button>
              {status.ticket_filter && (
                <div className="text-xs text-muted-foreground">
                  Current: types={JSON.stringify(status.ticket_filter.types)},
                  priorities={JSON.stringify(status.ticket_filter.priorities)}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Eligible Tickets Preview */}
          <Card>
            <CardHeader>
              <CardTitle>
                Eligible Tickets ({eligible?.count ?? 0})
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Button
                size="sm"
                variant="outline"
                className="mb-3"
                onClick={() => eligibleQuery.refetch()}
              >
                Refresh Preview
              </Button>
              {eligible?.tickets?.length ? (
                <div className="space-y-2">
                  {eligible.tickets.map((t) => (
                    <div key={t.ticket_id} className="flex items-center gap-2 rounded border p-2 text-sm">
                      <Badge variant="outline">{t.priority}</Badge>
                      <span className="font-medium">{t.title || t.ticket_id}</span>
                      <span className="text-muted-foreground">{t.type}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">No eligible tickets found.</p>
              )}
            </CardContent>
          </Card>

          {/* Checkpoint Viewer */}
          {checkpoint && checkpoint.ticket_id && (
            <Card>
              <CardHeader>
                <CardTitle>Checkpoint Data</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-2">
                  Ticket: {checkpoint.ticket_id} | Claimed at: {new Date(checkpoint.claimed_at * 1000).toLocaleString()}
                </p>
                <pre className="rounded bg-muted p-3 text-xs overflow-auto">
                  {JSON.stringify(checkpoint.checkpoint, null, 2)}
                </pre>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
