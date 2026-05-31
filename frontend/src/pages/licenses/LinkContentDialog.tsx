import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";

import {
  CONTENT_TYPES,
  linkLicenseAgreementContent,
} from "@/api/endpoints/licenseAgreements";
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

interface Props {
  licenseId: string;
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onLinked: () => void;
}

export function LinkContentDialog({
  licenseId,
  open,
  onOpenChange,
  onLinked,
}: Props) {
  const [contentId, setContentId] = useState("");
  const [contentType, setContentType] = useState<string>("video");

  const linkMut = useMutation({
    mutationFn: async () =>
      linkLicenseAgreementContent(licenseId, {
        content_id: contentId.trim(),
        content_type: contentType,
      }),
    onSuccess: () => {
      toast.success("Content linked");
      setContentId("");
      onOpenChange(false);
      onLinked();
    },
    onError: (e: Error) => toast.error(e.message || "Link failed"),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Link Content</DialogTitle>
          <DialogDescription>
            Attach a video, post, or broadcast to this license agreement.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1">
            <Label htmlFor="lc-id">Content ID</Label>
            <Input
              id="lc-id"
              value={contentId}
              onChange={(e) => setContentId(e.target.value)}
              placeholder="vid_xyz789"
            />
          </div>
          <div className="space-y-1">
            <Label>Content type</Label>
            <Select value={contentType} onValueChange={setContentType}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {CONTENT_TYPES.map((t) => (
                  <SelectItem key={t} value={t}>
                    {t}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
        <DialogFooter>
          <Button
            onClick={() => linkMut.mutate()}
            disabled={linkMut.isPending || !contentId.trim()}
          >
            {linkMut.isPending ? "Linking…" : "Link"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
