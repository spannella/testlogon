import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  cancelMyKycLivenessCall,
  listMyKycLivenessCalls,
  scheduleKycLivenessCall,
} from "@/api/endpoints/kycLivenessCall";
import type { KycLivenessCallOut, KycLivenessCallStatus } from "@/api/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";

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

const DURATIONS = [5, 10, 15, 30, 60];

function fmtTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

function CallRow({
  call,
  onCancelled,
}: {
  call: KycLivenessCallOut;
  onCancelled: () => void;
}) {
  const cancelMutation = useMutation({
    mutationFn: () => cancelMyKycLivenessCall(call.call_id),
    onSuccess: onCancelled,
  });
  const cancellable = call.status === "scheduled" || call.status === "in_progress";
  return (
    <div className="space-y-2 rounded-md border p-4">
      <div className="flex items-center justify-between gap-2">
        <div>
          <div className="font-medium">Case {call.case_id}</div>
          <div className="text-xs text-muted-foreground">
            Scheduled {fmtTs(call.scheduled_at)} &middot; {call.duration_minutes} min
          </div>
        </div>
        <Badge variant={STATUS_VARIANTS[call.status] ?? "outline"}>{call.status}</Badge>
      </div>
      {call.result && (
        <div className="text-sm">
          Result: <span className="font-medium">{call.result}</span>
        </div>
      )}
      <div className="flex items-center gap-2">
        {call.join_url && (
          <Button asChild size="sm" variant="outline">
            <a href={call.join_url}>Join call</a>
          </Button>
        )}
        {cancellable && (
          <Button
            size="sm"
            variant="destructive"
            disabled={cancelMutation.isPending}
            onClick={() => cancelMutation.mutate()}
          >
            Cancel
          </Button>
        )}
      </div>
    </div>
  );
}

export function KycLivenessCallSchedulePage() {
  const queryClient = useQueryClient();
  const [caseId, setCaseId] = useState("");
  const [scheduledAt, setScheduledAt] = useState("");
  const [durationMinutes, setDurationMinutes] = useState(15);
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);

  const callsQuery = useQuery({
    queryKey: ["kyc", "liveness-call", "mine"],
    queryFn: () => listMyKycLivenessCalls(),
  });

  const scheduleMutation = useMutation({
    mutationFn: () =>
      scheduleKycLivenessCall({
        case_id: caseId.trim(),
        scheduled_at: Math.floor(new Date(scheduledAt).getTime() / 1000),
        duration_minutes: durationMinutes,
        note: note.trim() || null,
      }),
    onSuccess: () => {
      setError(null);
      setCaseId("");
      setScheduledAt("");
      setNote("");
      queryClient.invalidateQueries({ queryKey: ["kyc", "liveness-call", "mine"] });
    },
    onError: (e: unknown) => {
      const detail = (e as { response?: { data?: { detail?: { message?: string } } } })?.response
        ?.data?.detail?.message;
      setError(detail ?? "Could not schedule the call.");
    },
  });

  const calls = callsQuery.data?.calls ?? [];
  const canSubmit = caseId.trim().length > 0 && scheduledAt.length > 0;

  return (
    <div className="mx-auto max-w-3xl space-y-6 p-4">
      <div>
        <h1 className="text-2xl font-semibold">Liveness Verification Call</h1>
        <p className="text-sm text-muted-foreground">
          Schedule a live video verification call for your KYC case. A verifier will join and
          confirm your identity.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Schedule a call</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1">
            <Label htmlFor="case-id">KYC case ID</Label>
            <Input
              id="case-id"
              value={caseId}
              onChange={(e) => setCaseId(e.target.value)}
              placeholder="kyc_..."
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="scheduled-at">Scheduled time</Label>
            <Input
              id="scheduled-at"
              type="datetime-local"
              value={scheduledAt}
              onChange={(e) => setScheduledAt(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="duration">Duration (minutes)</Label>
            <select
              id="duration"
              className="h-9 w-full rounded-md border bg-background px-3 text-sm"
              value={durationMinutes}
              onChange={(e) => setDurationMinutes(Number(e.target.value))}
            >
              {DURATIONS.map((d) => (
                <option key={d} value={d}>
                  {d} min
                </option>
              ))}
            </select>
          </div>
          <div className="space-y-1">
            <Label htmlFor="note">Note (optional)</Label>
            <Input
              id="note"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Anything the verifier should know"
            />
          </div>
          {error && <p className="text-sm text-destructive">{error}</p>}
          <Button
            disabled={!canSubmit || scheduleMutation.isPending}
            onClick={() => scheduleMutation.mutate()}
          >
            Schedule call
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>My verification calls</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {callsQuery.isLoading && <p className="text-sm">Loading…</p>}
          {!callsQuery.isLoading && calls.length === 0 && (
            <p className="text-sm text-muted-foreground">No verification calls yet.</p>
          )}
          {calls.map((call) => (
            <CallRow
              key={call.call_id}
              call={call}
              onCancelled={() =>
                queryClient.invalidateQueries({ queryKey: ["kyc", "liveness-call", "mine"] })
              }
            />
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

export default KycLivenessCallSchedulePage;
