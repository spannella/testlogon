import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Clock3, Flag, ShieldCheck, Video } from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  approveVideoReviewEntry,
  claimVideoReviewEntry,
  escalateVideoReviewEntry,
  getVideoReviewQueueStats,
  listVideoReviewQueue,
  rejectVideoReviewEntry,
} from "@/api/endpoints/moderationVideoQueue";
import type { VideoReviewQueueItem } from "@/api/types";

const STATUS_TABS: { key: string; label: string }[] = [
  { key: "pending", label: "Pending" },
  { key: "in_review", label: "In Review" },
  { key: "escalated", label: "Escalated" },
  { key: "approved", label: "Approved" },
  { key: "rejected", label: "Rejected" },
];

const PRIORITY_VARIANT: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
  urgent: "destructive",
  high: "destructive",
  normal: "secondary",
  low: "outline",
};

function relativeAge(createdAt: number): string {
  if (!createdAt) return "";
  const seconds = Math.max(0, Math.floor(Date.now() / 1000) - createdAt);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

interface VideoReviewQueueCardProps {
  item: VideoReviewQueueItem;
  busy: boolean;
  onClaim: () => void;
  onApprove: () => void;
  onReject: () => void;
  onEscalate: () => void;
}

function VideoReviewQueueCard({ item, busy, onClaim, onApprove, onReject, onEscalate }: VideoReviewQueueCardProps) {
  const isOpen = ["pending", "in_review", "escalated"].includes(item.status);
  return (
    <Card data-testid={`vrq-card-${item.entry_id}`}>
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <CardTitle className="flex items-center gap-2 truncate text-base">
              <Video className="h-4 w-4 shrink-0" />
              <span className="truncate">{item.title || item.video_id}</span>
            </CardTitle>
            <CardDescription className="truncate">
              @{item.owner_user_id} · {item.video_id}
            </CardDescription>
          </div>
          <div className="flex shrink-0 flex-col items-end gap-1">
            <Badge variant={PRIORITY_VARIANT[item.priority] ?? "secondary"}>{item.priority}</Badge>
            <span className="flex items-center gap-1 text-xs text-muted-foreground">
              <Clock3 className="h-3 w-3" />
              {relativeAge(item.created_at)}
            </span>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {item.thumbnail_url ? (
          <img
            src={item.thumbnail_url}
            alt={item.title || item.video_id}
            className="h-32 w-full rounded-md bg-muted object-cover"
          />
        ) : (
          <div className="flex h-32 w-full items-center justify-center rounded-md bg-muted text-muted-foreground">
            <Video className="h-8 w-8" />
          </div>
        )}
        <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
          <Badge variant="outline">{item.source}</Badge>
          {item.duration_seconds != null && <span>{Math.round(item.duration_seconds)}s</span>}
          {item.flag_reason && (
            <span className="flex items-center gap-1 text-destructive">
              <Flag className="h-3 w-3" />
              {item.flag_reason}
            </span>
          )}
        </div>
        {item.review_notes && (
          <p className="rounded bg-muted p-2 text-xs text-muted-foreground">{item.review_notes}</p>
        )}
        {isOpen && (
          <div className="flex flex-wrap gap-2">
            {item.status === "pending" && (
              <Button size="sm" variant="outline" disabled={busy} onClick={onClaim} data-testid="vrq-claim">
                Claim
              </Button>
            )}
            <Button size="sm" disabled={busy} onClick={onApprove} data-testid="vrq-approve">
              <ShieldCheck className="mr-1 h-4 w-4" /> Approve
            </Button>
            <Button size="sm" variant="destructive" disabled={busy} onClick={onReject} data-testid="vrq-reject">
              Reject
            </Button>
            <Button size="sm" variant="secondary" disabled={busy} onClick={onEscalate} data-testid="vrq-escalate">
              Escalate
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

interface ReasonState {
  entryId: string;
  mode: "reject" | "escalate";
}

export default function VideoReviewQueueModerationPage() {
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<string>("pending");
  const [ownerFilter, setOwnerFilter] = useState("");
  const [appliedOwner, setAppliedOwner] = useState("");
  const [reason, setReason] = useState<ReasonState | null>(null);
  const [reasonText, setReasonText] = useState("");

  const queueQuery = useQuery({
    queryKey: ["video-review-queue", tab, appliedOwner],
    queryFn: () =>
      listVideoReviewQueue({
        status: tab,
        order_by: "priority",
        limit: 50,
        owner_user_id: appliedOwner || undefined,
      }),
  });

  const statsQuery = useQuery({
    queryKey: ["video-review-queue-stats"],
    queryFn: getVideoReviewQueueStats,
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["video-review-queue"] });
    queryClient.invalidateQueries({ queryKey: ["video-review-queue-stats"] });
  };

  const claimMut = useMutation({
    mutationFn: (entryId: string) => claimVideoReviewEntry(entryId),
    onSuccess: () => {
      toast.success("Claimed for review");
      invalidate();
    },
    onError: () => toast.error("Could not claim entry"),
  });

  const approveMut = useMutation({
    mutationFn: (entryId: string) => approveVideoReviewEntry(entryId, { review_notes: "", notify_creator: true }),
    onSuccess: () => {
      toast.success("Video approved");
      invalidate();
    },
    onError: () => toast.error("Could not approve video"),
  });

  const decideMut = useMutation({
    mutationFn: async (state: ReasonState & { text: string }) => {
      if (state.mode === "reject") {
        return rejectVideoReviewEntry(state.entryId, { rejection_reason: state.text, notify_creator: true });
      }
      return escalateVideoReviewEntry(state.entryId, { escalation_reason: state.text });
    },
    onSuccess: (_data, vars) => {
      toast.success(vars.mode === "reject" ? "Video rejected" : "Video escalated");
      setReason(null);
      setReasonText("");
      invalidate();
    },
    onError: () => toast.error("Could not submit decision"),
  });

  const items = queueQuery.data?.items ?? [];
  const counts = statsQuery.data?.counts ?? {};
  const busy = claimMut.isPending || approveMut.isPending || decideMut.isPending;

  const reasonDialogTitle = useMemo(
    () => (reason?.mode === "reject" ? "Reject Video" : "Escalate Video"),
    [reason],
  );

  return (
    <div className="space-y-4">
      <PageHeader
        title="Video Review Queue"
        description="Review videos queued for moderation. Claim, approve, reject, or escalate."
      />

      <div className="flex flex-wrap items-center gap-2">
        {STATUS_TABS.map((t) => (
          <Button
            key={t.key}
            size="sm"
            variant={tab === t.key ? "default" : "outline"}
            onClick={() => setTab(t.key)}
            data-testid={`vrq-tab-${t.key}`}
          >
            {t.label}
            {counts[t.key] != null && (
              <Badge variant="secondary" className="ml-2">
                {counts[t.key]}
              </Badge>
            )}
          </Button>
        ))}
      </div>

      <div className="flex flex-wrap items-end gap-2">
        <div className="flex flex-col">
          <label className="text-xs text-muted-foreground" htmlFor="vrq-owner-filter">
            Filter by uploader ID
          </label>
          <Input
            id="vrq-owner-filter"
            value={ownerFilter}
            onChange={(e) => setOwnerFilter(e.target.value)}
            placeholder="owner_user_id"
            className="w-64"
            data-testid="vrq-owner-input"
          />
        </div>
        <Button size="sm" variant="outline" onClick={() => setAppliedOwner(ownerFilter.trim())} data-testid="vrq-apply-filter">
          Apply
        </Button>
        {appliedOwner && (
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              setOwnerFilter("");
              setAppliedOwner("");
            }}
          >
            Clear
          </Button>
        )}
        <Button size="sm" variant="outline" onClick={() => invalidate()} data-testid="vrq-refresh">
          Refresh
        </Button>
      </div>

      {queueQuery.isLoading ? (
        <p className="text-muted-foreground">Loading queue…</p>
      ) : items.length === 0 ? (
        <p className="text-muted-foreground" data-testid="vrq-empty">
          No videos in this status.
        </p>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {items.map((item) => (
            <VideoReviewQueueCard
              key={item.entry_id}
              item={item}
              busy={busy}
              onClaim={() => claimMut.mutate(item.entry_id)}
              onApprove={() => approveMut.mutate(item.entry_id)}
              onReject={() => {
                setReason({ entryId: item.entry_id, mode: "reject" });
                setReasonText("");
              }}
              onEscalate={() => {
                setReason({ entryId: item.entry_id, mode: "escalate" });
                setReasonText("");
              }}
            />
          ))}
        </div>
      )}

      <Dialog open={reason != null} onOpenChange={(open) => !open && setReason(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{reasonDialogTitle}</DialogTitle>
            <DialogDescription>
              {reason?.mode === "reject"
                ? "Provide a reason for rejection. This will be shared with the creator."
                : "Provide a reason for escalating to a senior moderator."}
            </DialogDescription>
          </DialogHeader>
          <Textarea
            value={reasonText}
            onChange={(e) => setReasonText(e.target.value)}
            placeholder="Reason (min 5 characters)"
            rows={4}
            data-testid="vrq-reason-input"
          />
          <DialogFooter>
            <Button variant="outline" onClick={() => setReason(null)}>
              Cancel
            </Button>
            <Button
              disabled={reasonText.trim().length < 5 || decideMut.isPending}
              onClick={() => reason && decideMut.mutate({ ...reason, text: reasonText.trim() })}
              data-testid="vrq-reason-submit"
            >
              {reason?.mode === "reject" ? "Reject Video" : "Escalate Video"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
