import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogTrigger,
} from "@/components/ui/dialog";
import { registerOpenLicensingContent } from "@/api/endpoints/syndicateOpenLicensing";

const CONTENT_TYPES = ["video", "music", "image", "post", "broadcast", "clip"];

export default function SyndicateOpenLicensingRegisterDialog({
  syndicateId,
}: {
  syndicateId: string;
}) {
  const [open, setOpen] = useState(false);
  const [contentId, setContentId] = useState("");
  const [contentType, setContentType] = useState("post");
  const qc = useQueryClient();

  const mut = useMutation({
    mutationFn: () =>
      registerOpenLicensingContent(syndicateId, contentId.trim(), contentType),
    onSuccess: (res) => {
      toast.success(`Registered. ${res.licenses_created} auto-license(s) created.`);
      qc.invalidateQueries({ queryKey: ["open-licensing-content", syndicateId] });
      setContentId("");
      setOpen(false);
    },
    onError: () => toast.error("Failed to register content"),
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">
          <Plus className="mr-1 h-4 w-4" /> Register Content
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Register Content for Open Licensing</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-1">
            <Label htmlFor="ol-content-id">Content ID</Label>
            <Input
              id="ol-content-id"
              value={contentId}
              onChange={(e) => setContentId(e.target.value)}
              placeholder="e.g. vid_123"
            />
          </div>
          <div className="space-y-1">
            <Label>Content Type</Label>
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
            onClick={() => mut.mutate()}
            disabled={!contentId.trim() || mut.isPending}
          >
            Register
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
