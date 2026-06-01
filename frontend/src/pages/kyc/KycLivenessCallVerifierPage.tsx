import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  conductKycLivenessCall,
  listKycLivenessCallsByStatus,
  recordKycLivenessCallResult,
} from "@/api/endpoints/kycLivenessCall";
import type { KycLivenessCallOut, KycLivenessCallStatus } from "@/api/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";

const STATUS_TABS: KycLivenessCallStatus[] = [
  "scheduled",
  "in_progress",
  "passed",
  "failed",
  "cancelled",
  "expired",
];

const STATUS_VARIANTS: Record<
  KycLivenessCallStatus,
  "default" | "secondary" | "destructive" | "outline"
> = {
  scheduled: "secondary",
  in_progress: "default",
  passed: "default",
  failed: "destructive",
  cancelled: "outline",
  expired: "outline",
};

function fmtTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

function VerifierCallPanel({
  call,
  onChanged,
}: {
  call: KycLivenessCallOut;
  onChanged: () => void;
}) {
  const [notes, setNotes] = useState("");
  const conductMutation = useMutation({
    mutationFn: () => conductKycLivenessCall(call.call_id),
    onSuccess: onChanged,
  });
  const resultMutation = useMutation({
    mutationFn: (result: "passed" | "failed") =>
      recordKycLivenessCallResult(call.call_id, { result, notes: notes.trim(), recording_linked: true }),
    onSuccess: onChanged,
  });
  const conductable = call.status === "scheduled";
  const recordable = call.status === "scheduled" || call.status === "in_progress";

  return (
    <div className="space-y-3 rounded-md border p-4">
      <div className="flex items-center justify-between gap-2">
        <div>
          <div className="font-medium">Case {call.case_id}</div>
          <div className="text-xs text-muted-foreground">
            {call.user_sub} &middot; scheduled {fmtTs(call.scheduled_at)} &middot;{" "}
            {call.duration_minutes} min
          </div>
        </div>
        <Badge variant={STATUS_VARIANTS[call.status] ?? "outline"}>{call.status}</Badge>
      </div>
      {call.note && <p className="text-sm text-muted-foreground">Note: {call.note}</p>}
      {call.result && (
        <div className="text-sm">
          Result: <span className="font-medium">{call.result}</span>
          {call.result_notes ? ` — ${call.result_notes}` : ""}
        </div>
      )}
      {call.recording_ref && (
        <div className="text-xs text-muted-foreground">Recording: {call.recording_ref}</div>
      )}

      <div className="flex flex-wrap items-center gap-2">
        {conductable && (
          <Button
            size="sm"
            disabled={conductMutation.isPending}
            onClick={() => conductMutation.mutate()}
          >
            Conduct call
          </Button>
        )}
        {call.join_url && (
          <Button asChild size="sm" variant="outline">
            <a href={call.join_url}>Join</a>
          </Button>
        )}
      </div>

      {recordable && (
        <div className="space-y-2 rounded-md border-t pt-3">
          <Input
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Outcome notes (required)"
          />
          <div className="flex gap-2">
            <Button
              size="sm"
              disabled={resultMutation.isPending || notes.trim().length === 0}
              onClick={() => resultMutation.mutate("passed")}
            >
              Mark passed
            </Button>
            <Button
              size="sm"
              variant="destructive"
              disabled={resultMutation.isPending || notes.trim().length === 0}
              onClick={() => resultMutation.mutate("failed")}
            >
              Mark failed
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

export function KycLivenessCallVerifierPage() {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<KycLivenessCallStatus>("scheduled");

  const queueQuery = useQuery({
    queryKey: ["kyc", "liveness-call", "by-status", status],
    queryFn: () => listKycLivenessCallsByStatus(status),
  });

  const calls = queueQuery.data?.calls ?? [];

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-4">
      <div>
        <h1 className="text-2xl font-semibold">Liveness Call Verifier Panel</h1>
        <p className="text-sm text-muted-foreground">
          Conduct scheduled liveness verification calls and record the pass/fail outcome.
        </p>
      </div>

      <div className="flex flex-wrap gap-2">
        {STATUS_TABS.map((s) => (
          <Button
            key={s}
            size="sm"
            variant={s === status ? "default" : "outline"}
            onClick={() => setStatus(s)}
          >
            {s}
          </Button>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{status} calls</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {queueQuery.isLoading && <p className="text-sm">Loading…</p>}
          {!queueQuery.isLoading && calls.length === 0 && (
            <p className="text-sm text-muted-foreground">No calls in this queue.</p>
          )}
          {calls.map((call) => (
            <VerifierCallPanel
              key={call.call_id}
              call={call}
              onChanged={() =>
                queryClient.invalidateQueries({ queryKey: ["kyc", "liveness-call", "by-status"] })
              }
            />
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

export default KycLivenessCallVerifierPage;
