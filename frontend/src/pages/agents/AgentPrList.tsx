import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  listPrs,
  getStatusFlow,
  setStatusFlow,
} from "@/api/endpoints/agentPrIntegration";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { GitPullRequest, ExternalLink, Ticket, Bot } from "lucide-react";
import type { AgentPr, StatusFlowConfig } from "@/api/types";

function statusVariant(status: string): "default" | "secondary" | "outline" {
  if (status === "merged") return "default";
  if (status === "closed") return "secondary";
  return "outline";
}

function statusColor(status: string): string {
  if (status === "open") return "bg-green-100 text-green-800 border-green-300";
  if (status === "merged") return "bg-purple-100 text-purple-800 border-purple-300";
  return "bg-gray-100 text-gray-700 border-gray-300";
}

const AGENT_TYPES = ["coder", "qa", "reviewer", "devops"];
const FLOW_FIELDS: Array<{ key: keyof StatusFlowConfig; label: string }> = [
  { key: "on_claim", label: "On Claim" },
  { key: "on_working", label: "On Working" },
  { key: "on_complete", label: "On Complete" },
  { key: "on_pr_created", label: "On PR Created" },
  { key: "on_pr_merged", label: "On PR Merged" },
  { key: "next_agent_type", label: "Next Agent Type" },
];

function StatusFlowEditor() {
  const qc = useQueryClient();
  const [agentType, setAgentType] = useState("coder");
  const [draft, setDraft] = useState<Partial<StatusFlowConfig>>({});

  const { data: flow } = useQuery({
    queryKey: ["agent-status-flow", agentType],
    queryFn: () => getStatusFlow(agentType),
  });

  const saveMut = useMutation({
    mutationFn: () => setStatusFlow(agentType, draft),
    onSuccess: () => {
      setDraft({});
      qc.invalidateQueries({ queryKey: ["agent-status-flow", agentType] });
    },
  });

  const value = (key: keyof StatusFlowConfig): string =>
    (draft[key] as string) ?? (flow ? (flow[key] as string) : "") ?? "";

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Bot className="h-5 w-5" /> Status Flow Editor
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="w-48">
          <Select
            value={agentType}
            onValueChange={(v) => {
              setAgentType(v);
              setDraft({});
            }}
          >
            <SelectTrigger aria-label="Agent type">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {AGENT_TYPES.map((t) => (
                <SelectItem key={t} value={t}>
                  {t}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {FLOW_FIELDS.map((f) => (
            <label key={f.key} className="flex flex-col gap-1 text-sm">
              <span className="text-muted-foreground">{f.label}</span>
              <Input
                aria-label={f.label}
                value={value(f.key)}
                onChange={(e) =>
                  setDraft((d) => ({ ...d, [f.key]: e.target.value }))
                }
              />
            </label>
          ))}
        </div>
        <Button
          onClick={() => saveMut.mutate()}
          disabled={saveMut.isPending || Object.keys(draft).length === 0}
        >
          Save Status Flow
        </Button>
      </CardContent>
    </Card>
  );
}

export default function AgentPrList() {
  const [statusFilter, setStatusFilter] = useState("all");

  const { data, isLoading } = useQuery({
    queryKey: ["agent-prs"],
    queryFn: () => listPrs(),
  });

  const prs: AgentPr[] = (data?.prs ?? []).filter((p) =>
    statusFilter === "all" ? true : p.status === statusFilter,
  );

  return (
    <div className="space-y-6 p-4">
      <div className="flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-2xl font-semibold">
          <GitPullRequest className="h-6 w-6" /> Agent PRs
        </h1>
        <div className="w-44">
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger aria-label="Status filter">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All statuses</SelectItem>
              <SelectItem value="open">Open</SelectItem>
              <SelectItem value="merged">Merged</SelectItem>
              <SelectItem value="closed">Closed</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <Card>
        <CardContent className="p-0">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b text-left text-muted-foreground">
                <th className="p-3">Ticket</th>
                <th className="p-3">PR Title</th>
                <th className="p-3">Branch</th>
                <th className="p-3">Status</th>
                <th className="p-3">Worker</th>
                <th className="p-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {isLoading && (
                <tr>
                  <td className="p-4 text-muted-foreground" colSpan={6}>
                    Loading…
                  </td>
                </tr>
              )}
              {!isLoading && prs.length === 0 && (
                <tr>
                  <td className="p-4 text-muted-foreground" colSpan={6}>
                    No agent PRs yet.
                  </td>
                </tr>
              )}
              {prs.map((pr) => (
                <tr key={pr.pr_id} className="border-b align-top">
                  <td className="p-3 font-mono text-xs">{pr.ticket_id}</td>
                  <td className="p-3">{pr.title}</td>
                  <td className="p-3 font-mono text-xs">{pr.branch}</td>
                  <td className="p-3">
                    <Badge
                      variant={statusVariant(pr.status)}
                      className={statusColor(pr.status)}
                      data-testid={`pr-status-${pr.status}`}
                    >
                      {pr.status}
                    </Badge>
                  </td>
                  <td className="p-3 font-mono text-xs">{pr.worker_id}</td>
                  <td className="p-3">
                    <div className="flex items-center gap-2">
                      {pr.pr_url && (
                        <a
                          href={pr.pr_url}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 text-blue-600 hover:underline"
                        >
                          <ExternalLink className="h-4 w-4" /> Open PR
                        </a>
                      )}
                      <a
                        href={`/tickets`}
                        className="inline-flex items-center gap-1 text-muted-foreground hover:underline"
                      >
                        <Ticket className="h-4 w-4" /> View Ticket
                      </a>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>

      <StatusFlowEditor />
    </div>
  );
}
