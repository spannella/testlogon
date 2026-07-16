import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Video, CheckCircle, XCircle, RefreshCw } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useAuthStore } from "@/stores/authStore";
import { canAccessModerationBoard } from "@/lib/adminCapabilities";
import {
  fetchVideoReviewQueue,
  approveVideo,
  rejectVideo,
  batchReviewVideos,
  type VideoReviewQueueItem,
} from "@/api/endpoints/adminVideoReview";

function fmt(ts?: number) {
  if (!ts) return "--";
  return new Date(ts * 1000).toLocaleString();
}

function formatDuration(seconds?: number) {
  if (!seconds) return "--";
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return `${m}:${s.toString().padStart(2, "0")}`;
}

function formatFileSize(bytes?: number) {
  if (!bytes) return "--";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024)
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export default function VideoReviewQueuePage() {
  const token = useAuthStore((s) => s.accessToken);
  const canAccess = canAccessModerationBoard(token);
  const queryClient = useQueryClient();

  const [ownerFilter, setOwnerFilter] = useState("");
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [rejectDialogVideo, setRejectDialogVideo] = useState<VideoReviewQueueItem | null>(null);
  const [rejectionReason, setRejectionReason] = useState("");
  const [notifyCreator, setNotifyCreator] = useState(true);
  const [batchRejectDialog, setBatchRejectDialog] = useState(false);
  const [batchRejectionReason, setBatchRejectionReason] = useState("");

  const queueQuery = useQuery({
    queryKey: ["video-review-queue", cursor, ownerFilter],
    queryFn: () =>
      fetchVideoReviewQueue({
        limit: 25,
        cursor,
        owner_user_id: ownerFilter || undefined,
      }),
    enabled: canAccess,
  });

  const approveMutation = useMutation({
    mutationFn: (videoId: string) =>
      approveVideo(videoId, { review_notes: "", auto_publish: true }),
    onSuccess: (data) => {
      toast.success(`Video approved (${data.new_status})`);
      setSelectedIds((prev) => {
        const next = new Set(prev);
        next.delete(data.video_id);
        return next;
      });
      void queryClient.invalidateQueries({ queryKey: ["video-review-queue"] });
    },
    onError: (err: unknown) =>
      toast.error(
        err instanceof Error ? err.message : "Failed to approve video",
      ),
  });

  const rejectMutation = useMutation({
    mutationFn: ({
      videoId,
      reason,
      notify,
    }: {
      videoId: string;
      reason: string;
      notify: boolean;
    }) =>
      rejectVideo(videoId, {
        rejection_reason: reason,
        notify_creator: notify,
      }),
    onSuccess: (data) => {
      toast.success("Video rejected");
      setRejectDialogVideo(null);
      setRejectionReason("");
      setSelectedIds((prev) => {
        const next = new Set(prev);
        next.delete(data.video_id);
        return next;
      });
      void queryClient.invalidateQueries({ queryKey: ["video-review-queue"] });
    },
    onError: (err: unknown) =>
      toast.error(
        err instanceof Error ? err.message : "Failed to reject video",
      ),
  });

  const batchApproveMutation = useMutation({
    mutationFn: (videoIds: string[]) =>
      batchReviewVideos(
        videoIds.map((id) => ({ video_id: id, action: "approve" as const })),
      ),
    onSuccess: (data) => {
      toast.success(`Batch complete: ${data.succeeded} approved, ${data.failed} failed`);
      setSelectedIds(new Set());
      void queryClient.invalidateQueries({ queryKey: ["video-review-queue"] });
    },
    onError: (err: unknown) =>
      toast.error(
        err instanceof Error ? err.message : "Batch approve failed",
      ),
  });

  const batchRejectMutation = useMutation({
    mutationFn: ({
      videoIds,
      reason,
    }: {
      videoIds: string[];
      reason: string;
    }) =>
      batchReviewVideos(
        videoIds.map((id) => ({
          video_id: id,
          action: "reject" as const,
          reason,
        })),
      ),
    onSuccess: (data) => {
      toast.success(`Batch complete: ${data.succeeded} rejected, ${data.failed} failed`);
      setSelectedIds(new Set());
      setBatchRejectDialog(false);
      setBatchRejectionReason("");
      void queryClient.invalidateQueries({ queryKey: ["video-review-queue"] });
    },
    onError: (err: unknown) =>
      toast.error(
        err instanceof Error ? err.message : "Batch reject failed",
      ),
  });

  if (!canAccess) {
    return (
      <div className="p-6">
        <PageHeader title="Video Review Queue" />
        <p className="text-muted-foreground">
          You do not have permission to access the video review queue.
        </p>
      </div>
    );
  }

  const items = queueQuery.data?.items ?? [];
  const totalPending = queueQuery.data?.total_pending ?? 0;
  const nextCursor = queueQuery.data?.next_cursor;

  const toggleSelect = (videoId: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(videoId)) next.delete(videoId);
      else next.add(videoId);
      return next;
    });
  };

  const selectAll = () => {
    setSelectedIds(new Set(items.map((v) => v.video_id)));
  };

  const deselectAll = () => {
    setSelectedIds(new Set());
  };

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        title="Video Review Queue"
        description="Review and approve or reject pending video uploads"
      />

      {/* Stats + Refresh */}
      <div className="flex items-center gap-4 flex-wrap">
        <Badge variant="secondary" data-testid="pending-count">
          {totalPending} pending
        </Badge>
        <Button
          variant="outline"
          size="sm"
          onClick={() => queueQuery.refetch()}
          disabled={queueQuery.isFetching}
        >
          <RefreshCw className="h-4 w-4 mr-1" />
          Refresh
        </Button>
      </div>

      {/* Owner filter */}
      <div className="flex items-end gap-2 max-w-md">
        <div className="flex-1">
          <Label htmlFor="owner-filter">Filter by owner</Label>
          <Input
            id="owner-filter"
            placeholder="owner user ID"
            value={ownerFilter}
            onChange={(e) => setOwnerFilter(e.target.value)}
          />
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => {
            setCursor(undefined);
            void queueQuery.refetch();
          }}
        >
          Apply
        </Button>
      </div>

      {/* Batch toolbar */}
      {selectedIds.size > 0 && (
        <div className="flex items-center gap-2 p-3 bg-muted rounded-md">
          <span className="text-sm font-medium">
            {selectedIds.size} selected
          </span>
          <Button size="sm" variant="outline" onClick={selectAll}>
            Select All
          </Button>
          <Button size="sm" variant="outline" onClick={deselectAll}>
            Deselect All
          </Button>
          <Button
            size="sm"
            onClick={() =>
              batchApproveMutation.mutate(Array.from(selectedIds))
            }
            disabled={batchApproveMutation.isPending}
          >
            <CheckCircle className="h-4 w-4 mr-1" />
            Approve Selected ({selectedIds.size})
          </Button>
          <Button
            size="sm"
            variant="destructive"
            onClick={() => setBatchRejectDialog(true)}
            disabled={batchRejectMutation.isPending}
          >
            <XCircle className="h-4 w-4 mr-1" />
            Reject Selected ({selectedIds.size})
          </Button>
        </div>
      )}

      {/* Queue list */}
      {queueQuery.isLoading ? (
        <p className="text-muted-foreground">Loading...</p>
      ) : items.length === 0 ? (
        <Card>
          <CardContent className="py-8 text-center text-muted-foreground">
            <Video className="h-12 w-12 mx-auto mb-3 opacity-50" />
            <p>No videos pending review</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {items.map((video) => (
            <Card key={video.video_id} data-testid={`review-card-${video.video_id}`}>
              <CardContent className="p-4">
                <div className="flex items-start gap-3">
                  <Checkbox
                    checked={selectedIds.has(video.video_id)}
                    onCheckedChange={() => toggleSelect(video.video_id)}
                    aria-label={`Select ${video.title}`}
                  />

                  {/* Thumbnail */}
                  <div className="w-24 h-16 bg-muted rounded flex items-center justify-center flex-shrink-0">
                    {video.thumbnail_url ? (
                      <img
                        src={video.thumbnail_url}
                        alt={video.title}
                        className="w-full h-full object-cover rounded"
                      />
                    ) : (
                      <Video className="h-6 w-6 text-muted-foreground" />
                    )}
                  </div>

                  {/* Info */}
                  <div className="flex-1 min-w-0">
                    <p className="font-medium truncate">{video.title}</p>
                    <p className="text-sm text-muted-foreground">
                      {video.owner_display_name || video.owner_user_id} |{" "}
                      {formatDuration(video.duration_seconds)} |{" "}
                      {video.width && video.height
                        ? `${video.width}x${video.height}`
                        : "--"}{" "}
                      | {formatFileSize(video.file_size_bytes)}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      Uploaded {fmt(video.created_at)}
                    </p>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => approveMutation.mutate(video.video_id)}
                      disabled={approveMutation.isPending}
                    >
                      <CheckCircle className="h-4 w-4 mr-1" />
                      Approve
                    </Button>
                    <Button
                      size="sm"
                      variant="destructive"
                      onClick={() => {
                        setRejectDialogVideo(video);
                        setRejectionReason("");
                        setNotifyCreator(true);
                      }}
                    >
                      <XCircle className="h-4 w-4 mr-1" />
                      Reject
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Pagination */}
      {nextCursor && (
        <div className="flex justify-center">
          <Button
            variant="outline"
            onClick={() => setCursor(nextCursor)}
            disabled={queueQuery.isFetching}
          >
            Load More
          </Button>
        </div>
      )}

      {/* Single reject dialog */}
      <Dialog
        open={!!rejectDialogVideo}
        onOpenChange={(open) => {
          if (!open) setRejectDialogVideo(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Reject Video</DialogTitle>
            <DialogDescription>
              Please provide a reason for rejection. This will be shown to the
              video creator.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="rejection-reason">Reason</Label>
              <Textarea
                id="rejection-reason"
                value={rejectionReason}
                onChange={(e) => setRejectionReason(e.target.value)}
                placeholder="Explain why this video was rejected (min 5 characters)"
                rows={4}
              />
              <p className="text-xs text-muted-foreground mt-1">
                {rejectionReason.length} / 2000 characters
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Checkbox
                id="notify-creator"
                checked={notifyCreator}
                onCheckedChange={(checked) =>
                  setNotifyCreator(checked === true)
                }
              />
              <Label htmlFor="notify-creator">Notify creator</Label>
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setRejectDialogVideo(null)}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={
                rejectionReason.length < 5 || rejectMutation.isPending
              }
              onClick={() => {
                if (rejectDialogVideo) {
                  rejectMutation.mutate({
                    videoId: rejectDialogVideo.video_id,
                    reason: rejectionReason,
                    notify: notifyCreator,
                  });
                }
              }}
            >
              Reject Video
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Batch reject dialog */}
      <Dialog
        open={batchRejectDialog}
        onOpenChange={(open) => {
          if (!open) setBatchRejectDialog(false);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Batch Reject Videos</DialogTitle>
            <DialogDescription>
              Reject {selectedIds.size} selected videos with the same reason.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="batch-rejection-reason">Reason</Label>
              <Textarea
                id="batch-rejection-reason"
                value={batchRejectionReason}
                onChange={(e) => setBatchRejectionReason(e.target.value)}
                placeholder="Explain why these videos were rejected (min 5 characters)"
                rows={4}
              />
              <p className="text-xs text-muted-foreground mt-1">
                {batchRejectionReason.length} / 2000 characters
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setBatchRejectDialog(false)}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={
                batchRejectionReason.length < 5 ||
                batchRejectMutation.isPending
              }
              onClick={() => {
                batchRejectMutation.mutate({
                  videoIds: Array.from(selectedIds),
                  reason: batchRejectionReason,
                });
              }}
            >
              Reject {selectedIds.size} Videos
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
