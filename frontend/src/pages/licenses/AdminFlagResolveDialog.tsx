import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { adminResolveComplianceFlag } from "@/api/endpoints/licenseCompliance";
import type { ComplianceFlagOut } from "@/api/types";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
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
  flag: ComplianceFlagOut | null;
  open: boolean;
  onOpenChange: (v: boolean) => void;
}

const RESOLUTIONS = ["resolved", "dismissed", "action_required"] as const;

export function AdminFlagResolveDialog({ flag, open, onOpenChange }: Props) {
  const queryClient = useQueryClient();
  const [resolution, setResolution] = useState<string>("resolved");
  const [notes, setNotes] = useState("");

  const resolveMut = useMutation({
    mutationFn: async () =>
      adminResolveComplianceFlag(flag!.flag_id, {
        content_id: flag!.content_id,
        resolution,
        notes: notes.trim(),
      }),
    onSuccess: () => {
      toast.success("Flag resolved");
      setNotes("");
      onOpenChange(false);
      queryClient.invalidateQueries({ queryKey: ["admin-compliance"] });
    },
    onError: (e: Error) => toast.error(e.message || "Resolve failed"),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Resolve Flag</DialogTitle>
          <DialogDescription>
            {flag ? `${flag.reason.replace(/_/g, " ")} · ${flag.content_id}` : ""}
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          {flag?.evidence && (
            <p className="rounded border bg-muted/40 p-2 text-sm">
              {flag.evidence}
            </p>
          )}
          <div className="space-y-1">
            <Label>Resolution</Label>
            <Select value={resolution} onValueChange={setResolution}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {RESOLUTIONS.map((r) => (
                  <SelectItem key={r} value={r}>
                    {r.replace(/_/g, " ")}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1">
            <Label htmlFor="resolve-notes">Notes</Label>
            <Textarea
              id="resolve-notes"
              value={notes}
              maxLength={1000}
              onChange={(e) => setNotes(e.target.value)}
            />
          </div>
        </div>
        <DialogFooter>
          <Button
            onClick={() => resolveMut.mutate()}
            disabled={resolveMut.isPending || !flag}
          >
            {resolveMut.isPending ? "Saving…" : "Resolve"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default AdminFlagResolveDialog;
