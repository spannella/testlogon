import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";

import { FLAG_REASONS, flagContent } from "@/api/endpoints/licenseCompliance";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";

interface Props {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  contentId?: string;
  reporterType?: "viewer" | "creator";
  onFlagged?: () => void;
}

export function FlagContentDialog({
  open,
  onOpenChange,
  contentId: initialContentId = "",
  reporterType = "viewer",
  onFlagged,
}: Props) {
  const [contentId, setContentId] = useState(initialContentId);
  const [reason, setReason] = useState<string>("unlicensed_music");
  const [evidence, setEvidence] = useState("");

  const flagMut = useMutation({
    mutationFn: async () =>
      flagContent({
        content_id: contentId.trim(),
        reason,
        evidence: evidence.trim(),
        reporter_type: reporterType,
      }),
    onSuccess: () => {
      toast.success("Report submitted");
      setEvidence("");
      onOpenChange(false);
      onFlagged?.();
    },
    onError: (e: Error) => toast.error(e.message || "Failed to submit report"),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Report Licensing Issue</DialogTitle>
          <DialogDescription>
            Flag content that you believe uses unlicensed material. Your report
            is shared only with platform administrators.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1">
            <Label htmlFor="flag-content-id">Content ID</Label>
            <Input
              id="flag-content-id"
              value={contentId}
              onChange={(e) => setContentId(e.target.value)}
              placeholder="vid_xyz789"
              disabled={!!initialContentId}
            />
          </div>
          <div className="space-y-1">
            <Label>Reason</Label>
            <Select value={reason} onValueChange={setReason}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {FLAG_REASONS.map((r) => (
                  <SelectItem key={r} value={r}>
                    {r.replace(/_/g, " ")}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1">
            <Label htmlFor="flag-evidence">Evidence (optional)</Label>
            <Textarea
              id="flag-evidence"
              value={evidence}
              maxLength={2000}
              onChange={(e) => setEvidence(e.target.value)}
              placeholder="Describe what you observed (max 2000 chars)"
            />
          </div>
        </div>
        <DialogFooter>
          <Button
            onClick={() => flagMut.mutate()}
            disabled={flagMut.isPending || !contentId.trim()}
          >
            {flagMut.isPending ? "Submitting…" : "Submit Flag"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default FlagContentDialog;
