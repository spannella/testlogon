import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  listAllFeedback,
  respondToFeedback,
  skipFeedback,
} from "@/api/endpoints/agentFeedback";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { MessageCircleQuestion, Clock, CheckCircle2, SkipForward, AlertTriangle } from "lucide-react";

function statusBadge(status: string) {
  switch (status) {
    case "pending":
      return <Badge variant="outline" className="border-yellow-500 text-yellow-600"><Clock className="mr-1 h-3 w-3" />Pending</Badge>;
    case "responded":
      return <Badge variant="outline" className="border-green-500 text-green-600"><CheckCircle2 className="mr-1 h-3 w-3" />Responded</Badge>;
    case "skipped":
      return <Badge variant="outline" className="border-gray-500 text-gray-600"><SkipForward className="mr-1 h-3 w-3" />Skipped</Badge>;
    case "timed_out":
      return <Badge variant="outline" className="border-red-500 text-red-600"><AlertTriangle className="mr-1 h-3 w-3" />Timed Out</Badge>;
    default:
      return <Badge variant="outline">{status}</Badge>;
  }
}

function timeAgo(ts: number): string {
  if (!ts) return "";
  const seconds = Math.floor(Date.now() / 1000) - ts;
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export default function AgentFeedbackPage() {
  const queryClient = useQueryClient();
  const [responseTexts, setResponseTexts] = useState<Record<string, string>>({});
  const [expandedContexts, setExpandedContexts] = useState<Set<string>>(new Set());

  const feedbackQuery = useQuery({
    queryKey: ["agent-feedback"],
    queryFn: () => listAllFeedback().then((r) => r.data),
    refetchInterval: 10_000,
  });

  const respondMut = useMutation({
    mutationFn: ({ workerId, requestId, text }: { workerId: string; requestId: string; text: string }) =>
      respondToFeedback(workerId, requestId, { response_text: text }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["agent-feedback"] });
    },
  });

  const skipMut = useMutation({
    mutationFn: ({ workerId, requestId }: { workerId: string; requestId: string }) =>
      skipFeedback(workerId, requestId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["agent-feedback"] });
    },
  });

  const requests = feedbackQuery.data?.requests ?? [];
  const pendingCount = feedbackQuery.data?.pending_count ?? 0;

  const toggleContext = (id: string) => {
    setExpandedContexts((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <div className="container mx-auto max-w-4xl py-8 px-4">
      <div className="mb-6 flex items-center gap-3">
        <MessageCircleQuestion className="h-7 w-7 text-primary" />
        <h1 className="text-2xl font-bold">Agent Feedback</h1>
        {pendingCount > 0 && (
          <Badge className="ml-2">{pendingCount} pending</Badge>
        )}
      </div>

      {requests.length === 0 && (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground">
            No feedback requests. Agents are working autonomously.
          </CardContent>
        </Card>
      )}

      <div className="space-y-4">
        {requests.map((req) => {
          const key = `${req.worker_id}:${req.request_id}`;
          const responseText = responseTexts[key] ?? "";
          const isPending = req.feedback_status === "pending";
          const isContextExpanded = expandedContexts.has(key);

          return (
            <Card key={key} data-testid="feedback-card">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-base font-medium">
                    {req.question}
                  </CardTitle>
                  {statusBadge(req.feedback_status)}
                </div>
                <div className="flex gap-4 text-xs text-muted-foreground mt-1">
                  <span>Worker: {req.worker_id.slice(0, 8)}</span>
                  <span>Ticket: {req.ticket_id}</span>
                  <span>{timeAgo(req.created_at)}</span>
                  {req.detected_pattern && (
                    <span>Pattern: {req.detected_pattern}</span>
                  )}
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                {req.terminal_context && (
                  <div>
                    <button
                      type="button"
                      className="text-xs text-blue-600 hover:underline"
                      onClick={() => toggleContext(key)}
                    >
                      {isContextExpanded ? "Hide" : "Show"} terminal context
                    </button>
                    {isContextExpanded && (
                      <pre className="mt-2 max-h-48 overflow-auto rounded bg-muted p-3 text-xs font-mono whitespace-pre-wrap">
                        {req.terminal_context}
                      </pre>
                    )}
                  </div>
                )}

                {req.feedback_status === "responded" && req.response_text && (
                  <div className="rounded bg-green-50 p-3 text-sm dark:bg-green-950">
                    <span className="font-medium">Response:</span> {req.response_text}
                  </div>
                )}

                {isPending && (
                  <div className="space-y-2">
                    <Textarea
                      placeholder="Type your response..."
                      value={responseText}
                      onChange={(e) =>
                        setResponseTexts((prev) => ({ ...prev, [key]: e.target.value }))
                      }
                      rows={3}
                      data-testid="response-textarea"
                    />
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        disabled={!responseText.trim() || respondMut.isPending}
                        onClick={() => {
                          respondMut.mutate({
                            workerId: req.worker_id,
                            requestId: req.request_id,
                            text: responseText.trim(),
                          });
                          setResponseTexts((prev) => ({ ...prev, [key]: "" }));
                        }}
                      >
                        Send Response
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={skipMut.isPending}
                        onClick={() =>
                          skipMut.mutate({
                            workerId: req.worker_id,
                            requestId: req.request_id,
                          })
                        }
                      >
                        Skip
                      </Button>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
