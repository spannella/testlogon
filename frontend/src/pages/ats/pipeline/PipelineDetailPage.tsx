/**
 * ATS Pipeline Detail — PIP-003, PIP-004, PIP-006.
 *
 * Route: /ats/pipeline/detail/:jobOrderId/:candidateId
 *
 * Shows:
 *   - Current stage, rating, timestamps for the pipeline entry
 *   - Stage advance/retreat control
 *   - Star rating widget
 *   - Placement section (record or view existing placement)
 */
import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  DollarSign,
} from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ApiError } from "@/api/client";
import {
  listPipelineByJob,
  getPipelineStatuses,
  changePipelineStatus,
  setPipelineRating,
  getPlacement,
  createPlacement,
  type PipelineEntry,
  type PipelineStatusItem,
  type Placement,
} from "@/api/endpoints/atsPipeline";
import { PipelineNotEnabled } from "./PipelineNotEnabled";
import { statusBadgeClass, fmtTs, fmtDate, formatCents, isNotEnabled } from "./pipelineUtils";

// ─── Rating widget ────────────────────────────────────────────────────────────

function StarRatingWidget({
  rating,
  disabled,
  onChange,
}: {
  rating: number;
  disabled?: boolean;
  onChange: (r: number) => void;
}) {
  return (
    <div className="flex items-center gap-1">
      {[1, 2, 3, 4, 5].map((star) => (
        <button
          key={star}
          disabled={disabled}
          onClick={() => onChange(rating === star ? 0 : star)}
          className={`text-2xl transition-colors disabled:cursor-not-allowed ${
            star <= rating
              ? "text-amber-400 hover:text-amber-500"
              : "text-muted-foreground hover:text-amber-300"
          }`}
          title={`${star} star${star > 1 ? "s" : ""}${rating === star ? " (click to clear)" : ""}`}
        >
          ★
        </button>
      ))}
      <span className="text-sm text-muted-foreground ml-1">
        {rating > 0 ? `${rating}/5` : "Not rated"}
      </span>
    </div>
  );
}

// ─── Placement panel ──────────────────────────────────────────────────────────

function PlacementPanel({
  jobOrderId,
  candidateId,
  statuses,
  onPlaced,
}: {
  jobOrderId: string;
  candidateId: string;
  statuses: PipelineStatusItem[];
  onPlaced: () => void;
}) {
  const qc = useQueryClient();
  const [startDateStr, setStartDateStr] = useState("");
  const [feeDollars, setFeeDollars] = useState("");
  const [notes, setNotes] = useState("");

  const placementQuery = useQuery({
    queryKey: ["ats-pipeline", "placement", jobOrderId, candidateId],
    queryFn: () => getPlacement(jobOrderId, candidateId),
    retry: false,
  });

  const isAlreadyPlaced = !placementQuery.isLoading && !placementQuery.isError;

  const placementMut = useMutation({
    mutationFn: () => {
      const startTs = startDateStr
        ? Math.floor(new Date(startDateStr).getTime() / 1000)
        : Math.floor(Date.now() / 1000);
      const feeCents = Math.round(parseFloat(feeDollars || "0") * 100);
      return createPlacement(jobOrderId, candidateId, {
        start_date: startTs,
        fee_cents: feeCents,
        notes: notes.trim() || null,
      });
    },
    onSuccess: () => {
      qc.invalidateQueries({
        queryKey: ["ats-pipeline", "placement", jobOrderId, candidateId],
      });
      toast.success("Placement recorded — candidate marked as Placed");
      onPlaced();
    },
    onError: (err: unknown) => {
      if (err instanceof ApiError) {
        if (err.status === 409) {
          toast.error("Placement already exists for this candidate/job.");
        } else {
          toast.error(err.detail || "Failed to record placement.");
        }
      } else {
        toast.error("Failed to record placement.");
      }
    },
  });

  // Loading state
  if (placementQuery.isLoading) {
    return <Skeleton className="h-16 w-full" />;
  }

  // Existing placement
  if (isAlreadyPlaced && placementQuery.data) {
    const p: Placement = placementQuery.data;
    return (
      <div className="space-y-2">
        <div className="flex items-center gap-2 text-emerald-600 dark:text-emerald-400">
          <CheckCircle2 className="h-5 w-5" />
          <span className="font-semibold text-sm">Placed</span>
        </div>
        <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
          <span className="text-muted-foreground">Placement ID</span>
          <span className="font-mono text-xs">{p.placement_id}</span>
          <span className="text-muted-foreground">Start Date</span>
          <span>{fmtDate(p.start_date)}</span>
          <span className="text-muted-foreground">Placement Fee</span>
          <span className="font-medium">{formatCents(p.fee_cents)}</span>
          <span className="text-muted-foreground">Status at Placement</span>
          <span>{p.status_at_placement}</span>
          <span className="text-muted-foreground">Recorded</span>
          <span>{fmtTs(p.created_at)}</span>
        </div>
        {p.notes && (
          <div>
            <p className="text-xs text-muted-foreground mb-0.5">Notes</p>
            <p className="text-sm">{p.notes}</p>
          </div>
        )}
      </div>
    );
  }

  // Placement form
  const placedStatus = statuses.find((s) => s.is_placed);

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Record a formal placement for this candidate. This will advance their
        status to{" "}
        <span className="font-medium">{placedStatus?.label ?? "Placed"}</span>.
      </p>
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-1.5">
          <Label htmlFor="start-date">Start Date</Label>
          <Input
            id="start-date"
            type="date"
            value={startDateStr}
            onChange={(e) => setStartDateStr(e.target.value)}
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="fee">Placement Fee (USD)</Label>
          <div className="relative">
            <DollarSign className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              id="fee"
              type="number"
              min="0"
              step="0.01"
              placeholder="0.00"
              className="pl-8"
              value={feeDollars}
              onChange={(e) => setFeeDollars(e.target.value)}
            />
          </div>
        </div>
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="place-notes">Notes (optional)</Label>
        <Textarea
          id="place-notes"
          placeholder="Any placement notes…"
          rows={3}
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          maxLength={2000}
        />
      </div>
      <Button
        onClick={() => placementMut.mutate()}
        disabled={placementMut.isPending}
        className="bg-emerald-600 hover:bg-emerald-700 text-white"
      >
        <CheckCircle2 className="h-4 w-4 mr-1.5" />
        {placementMut.isPending ? "Recording…" : "Record Placement"}
      </Button>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function PipelineDetailPage() {
  const { jobOrderId = "", candidateId = "" } = useParams<{
    jobOrderId: string;
    candidateId: string;
  }>();
  const qc = useQueryClient();
  const [statusNote, setStatusNote] = useState("");
  const [newStatus, setNewStatus] = useState<string>("");

  // Load status config
  const statusQuery = useQuery({
    queryKey: ["ats-pipeline", "statuses"],
    queryFn: getPipelineStatuses,
    retry: false,
  });

  // Load the pipeline entry for this job+candidate
  // We use list-by-job + filter client-side (the service doesn't expose a single
  // "get-by-job-and-candidate" GET, only an internal function — but we can list
  // and find).
  const entriesQuery = useQuery({
    queryKey: ["ats-pipeline", "by-job", jobOrderId],
    queryFn: () => listPipelineByJob(jobOrderId, { limit: 200 }),
    enabled: !!jobOrderId,
    retry: false,
  });

  const statuses: PipelineStatusItem[] = statusQuery.data?.statuses ?? [];
  const entry: PipelineEntry | undefined = entriesQuery.data?.entries.find(
    (e) => e.candidate_id === candidateId,
  );

  // Status change mutation
  const statusMut = useMutation({
    mutationFn: ({ ns, note }: { ns: string; note?: string }) =>
      changePipelineStatus(jobOrderId, candidateId, {
        new_status: ns,
        note: note ?? null,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ats-pipeline", "by-job", jobOrderId] });
      setStatusNote("");
      setNewStatus("");
      toast.success("Stage updated");
    },
    onError: (err: unknown) => {
      const msg = err instanceof ApiError ? err.detail : "Failed to update stage";
      toast.error(msg);
    },
  });

  // Rating mutation
  const ratingMut = useMutation({
    mutationFn: (rating: number) =>
      setPipelineRating(jobOrderId, candidateId, { rating }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ats-pipeline", "by-job", jobOrderId] });
      toast.success("Rating updated");
    },
    onError: (err: unknown) => {
      const msg = err instanceof ApiError ? err.detail : "Failed to set rating";
      toast.error(msg);
    },
  });

  if (isNotEnabled(statusQuery.error)) {
    return <PipelineNotEnabled />;
  }

  const isLoading = statusQuery.isLoading || entriesQuery.isLoading;

  const currentStatusCfg = statuses.find((s) => s.status_key === entry?.status);
  const currentIdx = statuses.findIndex((s) => s.status_key === entry?.status);
  const prevStatus = currentIdx > 0 ? statuses[currentIdx - 1] : null;
  const nextStatus = currentIdx >= 0 && currentIdx < statuses.length - 1 ? statuses[currentIdx + 1] : null;

  return (
    <div className="p-6 space-y-6 max-w-3xl">
      <div className="flex items-center gap-2">
        <Button variant="ghost" size="sm" asChild>
          <Link to="/ats/pipeline">
            <ArrowLeft className="h-4 w-4 mr-1" />
            Back to Board
          </Link>
        </Button>
      </div>

      <PageHeader
        title="Pipeline Entry Detail"
        description={`Job: ${jobOrderId} · Candidate: ${candidateId}`}
      />

      {isLoading && (
        <div className="space-y-4">
          <Skeleton className="h-32 w-full" />
          <Skeleton className="h-48 w-full" />
        </div>
      )}

      {!isLoading && !entry && !entriesQuery.isError && (
        <Card>
          <CardContent className="py-10 text-center text-muted-foreground">
            <p className="text-sm">
              No pipeline entry found for this candidate in this job order.
            </p>
            <Button variant="outline" size="sm" className="mt-4" asChild>
              <Link to={`/ats/pipeline`}>Go to Pipeline Board</Link>
            </Button>
          </CardContent>
        </Card>
      )}

      {!isLoading && entriesQuery.isError && (
        <Card>
          <CardContent className="py-10 text-center text-muted-foreground">
            <p className="text-sm">Failed to load pipeline entry.</p>
          </CardContent>
        </Card>
      )}

      {!isLoading && entry && (
        <>
          {/* Overview card */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Pipeline Entry</CardTitle>
              <CardDescription>
                ID: <span className="font-mono">{entry.pipeline_id}</span>
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
                <div>
                  <p className="text-muted-foreground text-xs mb-0.5">Candidate</p>
                  <Link
                    to={`/ats/candidates/${candidateId}`}
                    className="font-mono text-primary hover:underline"
                  >
                    {candidateId}
                  </Link>
                </div>
                <div>
                  <p className="text-muted-foreground text-xs mb-0.5">Job Order</p>
                  <Link
                    to={`/ats/jobs/${jobOrderId}`}
                    className="font-mono text-primary hover:underline"
                  >
                    {jobOrderId}
                  </Link>
                </div>
                <div>
                  <p className="text-muted-foreground text-xs mb-0.5">Current Stage</p>
                  <Badge
                    className={`text-xs ${statusBadgeClass(entry.status, currentStatusCfg)}`}
                    style={
                      currentStatusCfg?.color
                        ? {
                            backgroundColor: currentStatusCfg.color + "22",
                            color: currentStatusCfg.color,
                          }
                        : {}
                    }
                  >
                    {currentStatusCfg?.label ?? entry.status}
                  </Badge>
                </div>
                <div>
                  <p className="text-muted-foreground text-xs mb-0.5">Status Rank</p>
                  <span>{entry.status_rank}</span>
                </div>
                <div>
                  <p className="text-muted-foreground text-xs mb-0.5">Added</p>
                  <span>{fmtTs(entry.created_at)}</span>
                </div>
                <div>
                  <p className="text-muted-foreground text-xs mb-0.5">Last Updated</p>
                  <span>{fmtTs(entry.updated_at)}</span>
                </div>
              </div>

              <Separator />

              {/* Rating */}
              <div>
                <p className="text-sm font-medium mb-2">Candidate Rating</p>
                <StarRatingWidget
                  rating={entry.rating}
                  disabled={ratingMut.isPending}
                  onChange={(r) => ratingMut.mutate(r)}
                />
              </div>

              <Separator />

              {/* Stage advance controls */}
              <div className="space-y-3">
                <p className="text-sm font-medium">Change Stage</p>
                <div className="flex gap-2">
                  {prevStatus && (
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={statusMut.isPending}
                      onClick={() =>
                        statusMut.mutate({ ns: prevStatus.status_key })
                      }
                    >
                      <ChevronLeft className="h-3.5 w-3.5 mr-1" />
                      {prevStatus.label}
                    </Button>
                  )}
                  {nextStatus && (
                    <Button
                      size="sm"
                      disabled={statusMut.isPending}
                      onClick={() =>
                        statusMut.mutate({
                          ns: nextStatus.status_key,
                          note: statusNote || undefined,
                        })
                      }
                    >
                      {nextStatus.label}
                      <ChevronRight className="h-3.5 w-3.5 ml-1" />
                    </Button>
                  )}
                </div>

                {/* Arbitrary stage select */}
                <div className="flex gap-2 items-end">
                  <div className="flex-1 space-y-1">
                    <Label htmlFor="jump-status" className="text-xs">
                      Jump to stage
                    </Label>
                    <Select
                      value={newStatus}
                      onValueChange={setNewStatus}
                    >
                      <SelectTrigger id="jump-status" className="h-8 text-xs">
                        <SelectValue placeholder="Select stage…" />
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
                  <div className="flex-1 space-y-1">
                    <Label htmlFor="status-note" className="text-xs">
                      Note (optional)
                    </Label>
                    <Input
                      id="status-note"
                      className="h-8 text-xs"
                      placeholder="Reason for stage change…"
                      value={statusNote}
                      onChange={(e) => setStatusNote(e.target.value)}
                    />
                  </div>
                  <Button
                    size="sm"
                    disabled={!newStatus || statusMut.isPending}
                    onClick={() =>
                      statusMut.mutate({ ns: newStatus, note: statusNote || undefined })
                    }
                  >
                    {statusMut.isPending ? "Updating…" : "Update"}
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Placement card */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 text-emerald-600" />
                Placement
              </CardTitle>
              <CardDescription>
                Record a formal placement when the candidate accepts an offer.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <PlacementPanel
                jobOrderId={jobOrderId}
                candidateId={candidateId}
                statuses={statuses}
                onPlaced={() => {
                  qc.invalidateQueries({
                    queryKey: ["ats-pipeline", "by-job", jobOrderId],
                  });
                }}
              />
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
