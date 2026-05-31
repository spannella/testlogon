import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { approveIdea, rejectIdea, archiveIdea } from "@/api/endpoints/productAgent";
import type { FeatureIdea } from "@/api/types";

interface Props {
  idea: FeatureIdea | null;
  open: boolean;
  onClose: () => void;
}

export default function IdeaDetailDialog({ idea, open, onClose }: Props) {
  const queryClient = useQueryClient();
  const [showReject, setShowReject] = useState(false);
  const [reason, setReason] = useState("");

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["pm-ideas"] });

  const approveMut = useMutation({
    mutationFn: () => approveIdea(idea!.idea_id),
    onSuccess: () => {
      toast.success("Idea approved — ticket created");
      invalidate();
      onClose();
    },
    onError: (e: Error) => toast.error(e.message || "Approve failed"),
  });

  const rejectMut = useMutation({
    mutationFn: () => rejectIdea(idea!.idea_id, reason),
    onSuccess: () => {
      toast.success("Idea rejected");
      setShowReject(false);
      setReason("");
      invalidate();
      onClose();
    },
    onError: (e: Error) => toast.error(e.message || "Reject failed"),
  });

  const archiveMut = useMutation({
    mutationFn: () => archiveIdea(idea!.idea_id),
    onSuccess: () => {
      toast.success("Idea archived");
      invalidate();
      onClose();
    },
    onError: (e: Error) => toast.error(e.message || "Archive failed"),
  });

  if (!idea) return null;

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent data-testid="idea-detail-dialog" className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>{idea.title}</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="flex flex-wrap gap-2">
            <Badge data-testid="idea-detail-category">{idea.category}</Badge>
            <Badge variant="secondary" data-testid="idea-detail-priority">
              {idea.priority_suggestion}
            </Badge>
            <Badge variant="outline">{idea.status}</Badge>
          </div>
          <div>
            <p className="text-xs font-semibold text-muted-foreground">User Impact</p>
            <p className="text-sm">{idea.user_impact}</p>
          </div>
          <div>
            <p className="text-xs font-semibold text-muted-foreground">Description</p>
            <p className="text-sm whitespace-pre-wrap">{idea.description}</p>
          </div>
          {idea.mockup_description && (
            <div>
              <p className="text-xs font-semibold text-muted-foreground">Mockup</p>
              <p className="text-sm whitespace-pre-wrap">{idea.mockup_description}</p>
            </div>
          )}
          {idea.evidence && idea.evidence.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-muted-foreground">Evidence</p>
              <ul className="list-disc pl-5 text-sm">
                {idea.evidence.map((e, i) => (
                  <li key={i}>{e.description}</li>
                ))}
              </ul>
            </div>
          )}
          {idea.competitor_refs && idea.competitor_refs.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-muted-foreground">Competitor Refs</p>
              <ul className="list-disc pl-5 text-sm">
                {idea.competitor_refs.map((c, i) => (
                  <li key={i}>
                    {c.feature} — {c.url}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {idea.support_ticket_refs && idea.support_ticket_refs.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-muted-foreground">Support Tickets</p>
              <p className="text-sm">{idea.support_ticket_refs.join(", ")}</p>
            </div>
          )}
          {idea.status === "rejected" && idea.rejection_reason && (
            <div>
              <p className="text-xs font-semibold text-muted-foreground">Rejection Reason</p>
              <p className="text-sm">{idea.rejection_reason}</p>
            </div>
          )}
          {idea.created_ticket_id && (
            <div>
              <p className="text-xs font-semibold text-muted-foreground">Created Ticket</p>
              <p className="text-sm">{idea.created_ticket_id}</p>
            </div>
          )}
        </div>

        {idea.status === "pending" && !showReject && (
          <div className="flex gap-2">
            <Button
              data-testid="idea-approve-btn"
              onClick={() => approveMut.mutate()}
              disabled={approveMut.isPending}
            >
              Approve
            </Button>
            <Button
              variant="outline"
              data-testid="idea-reject-btn"
              onClick={() => setShowReject(true)}
            >
              Reject
            </Button>
          </div>
        )}

        {idea.status === "pending" && showReject && (
          <div className="space-y-2">
            <Textarea
              data-testid="idea-reject-reason"
              placeholder="Reason for rejection"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
            <div className="flex gap-2">
              <Button
                variant="destructive"
                data-testid="idea-reject-confirm"
                onClick={() => rejectMut.mutate()}
                disabled={!reason.trim() || rejectMut.isPending}
              >
                Confirm Reject
              </Button>
              <Button variant="ghost" onClick={() => setShowReject(false)}>
                Cancel
              </Button>
            </div>
          </div>
        )}

        {(idea.status === "approved" || idea.status === "rejected") && (
          <div className="flex gap-2">
            <Button
              variant="outline"
              data-testid="idea-archive-btn"
              onClick={() => archiveMut.mutate()}
              disabled={archiveMut.isPending}
            >
              Archive
            </Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
