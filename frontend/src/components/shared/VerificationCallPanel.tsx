import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  PhoneCall,
  PhoneOff,
  CheckCircle,
  XCircle,
  Clock,
  ChevronDown,
  ChevronUp,
} from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ApiError } from "@/api/client";
import {
  scheduleKycLivenessCall,
  adminGetKycLivenessCall,
  adminGetKycLivenessCallForCase,
  conductKycLivenessCall,
  recordKycLivenessCallResult,
  adminCancelKycLivenessCall,
  listKycLivenessCallsByStatus,
} from "@/api/endpoints/kycLivenessCall";
import type { KycLivenessCallOut } from "@/api/types";

// ─── helpers ──────────────────────────────────────────────────────────────────

function statusVariant(
  s: string,
): "default" | "secondary" | "destructive" | "outline" {
  if (s === "passed") return "default";
  if (s === "failed") return "destructive";
  if (s === "in_progress") return "secondary";
  return "outline"; // scheduled / expired / cancelled
}

function formatTs(ts: number | null | undefined): string {
  if (!ts) return "--";
  return new Date(ts * 1000).toLocaleString();
}

function errorCode(err: unknown): string | undefined {
  if (err instanceof ApiError) {
    const detail = (err.body as Record<string, unknown> | null)?.detail;
    if (detail && typeof detail === "object") {
      return (detail as Record<string, unknown>).code as string | undefined;
    }
  }
  return undefined;
}

// ─── Schedule Call dialog ───────────────────────────────────────────────────────

interface ScheduleDialogProps {
  caseId: string;
  open: boolean;
  onClose: () => void;
  onScheduled: () => void;
}

function ScheduleCallDialog({
  caseId,
  open,
  onClose,
  onScheduled,
}: ScheduleDialogProps) {
  const [scheduledAt, setScheduledAt] = useState("");
  const [durationMinutes, setDurationMinutes] = useState(30);
  const [note, setNote] = useState("");

  const schedMut = useMutation({
    mutationFn: () => {
      const ts = Math.floor(new Date(scheduledAt).getTime() / 1000);
      return scheduleKycLivenessCall({
        case_id: caseId,
        scheduled_at: ts,
        duration_minutes: durationMinutes,
        note: note || null,
      });
    },
    onSuccess: () => {
      toast.success("Verification call scheduled.");
      onScheduled();
      onClose();
    },
    onError: (err: unknown) => {
      if (errorCode(err) === "kyc_call_already_scheduled") {
        toast.error("A call is already scheduled for this case. Cancel it first.");
      } else {
        toast.error("Failed to schedule call.");
      }
    },
  });

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Schedule Verification Call</DialogTitle>
          <DialogDescription>
            Choose a date/time and duration for the liveness verification call.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label htmlFor="call-scheduled-at">Scheduled At</Label>
            <Input
              id="call-scheduled-at"
              type="datetime-local"
              value={scheduledAt}
              onChange={(e) => setScheduledAt(e.target.value)}
            />
          </div>
          <div>
            <Label htmlFor="call-duration">Duration (minutes)</Label>
            <Input
              id="call-duration"
              type="number"
              min={5}
              max={120}
              value={durationMinutes}
              onChange={(e) => setDurationMinutes(Number(e.target.value))}
            />
          </div>
          <div>
            <Label htmlFor="call-note">Note (optional)</Label>
            <Textarea
              id="call-note"
              placeholder="Add a note for the applicant..."
              value={note}
              onChange={(e) => setNote(e.target.value)}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            onClick={() => schedMut.mutate()}
            disabled={!scheduledAt || schedMut.isPending}
            data-testid="schedule-call-submit"
          >
            {schedMut.isPending ? "Scheduling..." : "Schedule"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Main panel ───────────────────────────────────────────────────────────────

interface Props {
  caseId: string;
  /**
   * Optional direct call_id reference. If provided, the panel looks it up
   * directly instead of resolving the latest call for the case.
   */
  initialCallId?: string | null;
}

const TERMINAL_STATUSES = ["expired", "cancelled", "passed", "failed"];

export function VerificationCallPanel({ caseId, initialCallId }: Props) {
  const [open, setOpen] = useState(true);
  const [scheduleOpen, setScheduleOpen] = useState(false);
  const [resultOpen, setResultOpen] = useState(false);
  const [resultValue, setResultValue] = useState<"passed" | "failed">("passed");
  const [resultNotes, setResultNotes] = useState("");
  const [recordingRef, setRecordingRef] = useState("");
  const qc = useQueryClient();

  const callQuery = useQuery({
    queryKey: ["kyc-liveness-call", caseId],
    queryFn: async (): Promise<KycLivenessCallOut | null> => {
      if (initialCallId) {
        return adminGetKycLivenessCall(initialCallId);
      }
      // Prefer the admin per-case endpoint (GAP-0251); fall back to scanning
      // the by-status lists if it is not deployed in this environment.
      try {
        const resp = await adminGetKycLivenessCallForCase(caseId);
        const vc = resp.verification_call;
        if (!vc) return null;
        // The per-case status view is a status projection; fetch the full
        // record by id so admin-only fields (result_notes, recording_ref,
        // verifier_sub) are available.
        return adminGetKycLivenessCall(vc.call_id);
      } catch (err) {
        if (err instanceof ApiError && (err.status === 404 || err.status === 405)) {
          const results = await Promise.all([
            listKycLivenessCallsByStatus("scheduled", 100),
            listKycLivenessCallsByStatus("in_progress", 100),
          ]);
          const all = [...results[0].calls, ...results[1].calls];
          const forCase = all
            .filter((c) => c.case_id === caseId)
            .sort((a, b) => b.created_at - a.created_at);
          return forCase[0] ?? null;
        }
        throw err;
      }
    },
    enabled: !!caseId,
  });

  const call = callQuery.data;

  const invalidate = () =>
    qc.invalidateQueries({ queryKey: ["kyc-liveness-call", caseId] });

  const conductMut = useMutation({
    mutationFn: () => conductKycLivenessCall(call!.call_id),
    onSuccess: () => {
      toast.success("Call marked as in progress.");
      invalidate();
    },
    onError: () => toast.error("Failed to mark call in progress."),
  });

  const cancelMut = useMutation({
    mutationFn: () => adminCancelKycLivenessCall(call!.call_id),
    onSuccess: () => {
      toast.success("Call cancelled.");
      invalidate();
    },
    onError: () => toast.error("Failed to cancel call."),
  });

  const recordMut = useMutation({
    mutationFn: () =>
      recordKycLivenessCallResult(call!.call_id, {
        result: resultValue,
        notes: resultNotes,
        recording_linked: !!recordingRef,
      }),
    onSuccess: () => {
      toast.success("Call result recorded.");
      setResultOpen(false);
      setResultNotes("");
      setRecordingRef("");
      invalidate();
    },
    onError: () => toast.error("Failed to record call result."),
  });

  const canSchedule = !call || TERMINAL_STATUSES.includes(call.status);

  return (
    <Card data-testid="verification-call-panel">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <PhoneCall className="h-4 w-4" />
            Verification Call
            {call && (
              <Badge
                variant={statusVariant(call.status)}
                data-testid="call-status-badge"
              >
                {call.status}
              </Badge>
            )}
          </CardTitle>
          <div className="flex items-center gap-2">
            {canSchedule && (
              <Button
                size="sm"
                variant="outline"
                onClick={() => setScheduleOpen(true)}
                data-testid="schedule-call-btn"
              >
                Schedule Call
              </Button>
            )}
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setOpen((o) => !o)}
              aria-label={open ? "Collapse" : "Expand"}
              data-testid="call-panel-toggle"
            >
              {open ? (
                <ChevronUp className="h-4 w-4" />
              ) : (
                <ChevronDown className="h-4 w-4" />
              )}
            </Button>
          </div>
        </div>
      </CardHeader>

      {open && (
        <CardContent>
          {callQuery.isLoading && (
            <p
              className="text-sm text-muted-foreground"
              data-testid="call-loading"
            >
              Loading call status...
            </p>
          )}
          {!callQuery.isLoading && !call && (
            <p
              className="text-sm text-muted-foreground"
              data-testid="call-none"
            >
              No verification call scheduled for this case.
            </p>
          )}
          {call && (
            <div className="space-y-3 text-sm" data-testid="call-detail">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Call ID</span>
                <span className="font-mono text-xs">{call.call_id}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Scheduled</span>
                <span>{formatTs(call.scheduled_at)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Duration</span>
                <span>{call.duration_minutes} min</span>
              </div>
              {call.verifier_sub && (
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Verifier</span>
                  <span className="font-mono text-xs">{call.verifier_sub}</span>
                </div>
              )}
              {call.result && (
                <>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Outcome</span>
                    <Badge
                      variant={
                        call.result === "passed" ? "default" : "destructive"
                      }
                      data-testid="call-result"
                    >
                      {call.result}
                    </Badge>
                  </div>
                  {call.result_notes && (
                    <div>
                      <span className="text-muted-foreground">Notes</span>
                      <p className="mt-1 text-xs bg-muted rounded px-2 py-1">
                        {call.result_notes}
                      </p>
                    </div>
                  )}
                  {call.recording_ref && (
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Recording</span>
                      <a
                        href={call.recording_ref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-primary underline text-xs"
                        data-testid="recording-link"
                      >
                        View recording
                      </a>
                    </div>
                  )}
                </>
              )}
              {call.note && (
                <div>
                  <span className="text-muted-foreground">Note</span>
                  <p className="mt-1 text-xs bg-muted rounded px-2 py-1">
                    {call.note}
                  </p>
                </div>
              )}
              {/* Admin action buttons */}
              <div className="flex flex-wrap gap-2 pt-2">
                {call.status === "scheduled" && (
                  <>
                    <Button
                      size="sm"
                      onClick={() => conductMut.mutate()}
                      disabled={conductMut.isPending}
                      data-testid="conduct-call-btn"
                    >
                      <Clock className="mr-1 h-3 w-3" />
                      {conductMut.isPending ? "Starting..." : "Start Call"}
                    </Button>
                    <Button
                      size="sm"
                      variant="destructive"
                      onClick={() => cancelMut.mutate()}
                      disabled={cancelMut.isPending}
                      data-testid="cancel-call-btn"
                    >
                      <PhoneOff className="mr-1 h-3 w-3" />
                      {cancelMut.isPending ? "Cancelling..." : "Cancel Call"}
                    </Button>
                  </>
                )}
                {call.status === "in_progress" && (
                  <Button
                    size="sm"
                    onClick={() => setResultOpen(true)}
                    data-testid="record-result-btn"
                  >
                    Record Outcome
                  </Button>
                )}
              </div>
            </div>
          )}
        </CardContent>
      )}

      {/* Schedule dialog */}
      <ScheduleCallDialog
        caseId={caseId}
        open={scheduleOpen}
        onClose={() => setScheduleOpen(false)}
        onScheduled={invalidate}
      />

      {/* Record result dialog */}
      <Dialog open={resultOpen} onOpenChange={setResultOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Record Call Outcome</DialogTitle>
            <DialogDescription>
              Record the result of the conducted liveness verification call.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="flex gap-4">
              <Button
                variant={resultValue === "passed" ? "default" : "outline"}
                onClick={() => setResultValue("passed")}
                data-testid="result-passed-btn"
              >
                <CheckCircle className="mr-1 h-4 w-4" /> Passed
              </Button>
              <Button
                variant={resultValue === "failed" ? "destructive" : "outline"}
                onClick={() => setResultValue("failed")}
                data-testid="result-failed-btn"
              >
                <XCircle className="mr-1 h-4 w-4" /> Failed
              </Button>
            </div>
            <div>
              <Label htmlFor="result-notes">Notes</Label>
              <Textarea
                id="result-notes"
                value={resultNotes}
                onChange={(e) => setResultNotes(e.target.value)}
                placeholder="Outcome notes..."
              />
            </div>
            <div>
              <Label htmlFor="recording-ref">Recording Reference (optional)</Label>
              <Input
                id="recording-ref"
                value={recordingRef}
                onChange={(e) => setRecordingRef(e.target.value)}
                placeholder="/mock/s3/..."
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setResultOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => recordMut.mutate()}
              disabled={recordMut.isPending}
              data-testid="save-outcome-btn"
            >
              {recordMut.isPending ? "Saving..." : "Save Outcome"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
