import { useEffect, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  getComputeQuota,
  setComputeQuota,
  deleteComputeQuota,
} from "@/api/endpoints/adminCompute";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";

interface Props {
  userSub: string | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export default function QuotaEditorDialog({ userSub, open, onOpenChange }: Props) {
  const qc = useQueryClient();
  const [maxEc2, setMaxEc2] = useState(3);
  const [maxK8s, setMaxK8s] = useState(5);
  const [maxSpend, setMaxSpend] = useState(50); // dollars
  const [allowedTypes, setAllowedTypes] = useState("");
  const [notes, setNotes] = useState("");

  const quotaQuery = useQuery({
    queryKey: ["admin-compute", "quota", userSub],
    queryFn: () => getComputeQuota(userSub as string),
    enabled: open && !!userSub,
  });

  useEffect(() => {
    const q = quotaQuery.data;
    if (q) {
      setMaxEc2(q.max_ec2_instances);
      setMaxK8s(q.max_k8s_pods);
      setMaxSpend(Math.round(q.max_monthly_spend_cents / 100));
      setAllowedTypes(q.allowed_instance_types.join(", "));
      setNotes(q.notes);
    }
  }, [quotaQuery.data]);

  const saveMut = useMutation({
    mutationFn: () =>
      setComputeQuota(userSub as string, {
        max_ec2_instances: maxEc2,
        max_k8s_pods: maxK8s,
        max_monthly_spend_cents: Math.round(maxSpend * 100),
        allowed_instance_types: allowedTypes
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
        allowed_k8s_presets: [],
        notes,
      }),
    onSuccess: () => {
      toast.success("Quota saved");
      qc.invalidateQueries({ queryKey: ["admin-compute"] });
      onOpenChange(false);
    },
    onError: (e: unknown) => toast.error((e as Error).message || "Failed to save quota"),
  });

  const resetMut = useMutation({
    mutationFn: () => deleteComputeQuota(userSub as string),
    onSuccess: () => {
      toast.success("Reverted to platform defaults");
      qc.invalidateQueries({ queryKey: ["admin-compute"] });
      onOpenChange(false);
    },
    onError: (e: unknown) => toast.error((e as Error).message || "Failed to reset quota"),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Edit Compute Quota</DialogTitle>
          <DialogDescription className="break-all">{userSub}</DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="text-xs text-muted-foreground">
            {quotaQuery.data?.is_custom
              ? "Custom quota in effect"
              : "Using platform defaults"}
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label htmlFor="max-ec2">Max EC2 instances</Label>
              <Input
                id="max-ec2"
                type="number"
                min={0}
                max={100}
                value={maxEc2}
                onChange={(e) => setMaxEc2(Number(e.target.value))}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="max-k8s">Max K8s pods</Label>
              <Input
                id="max-k8s"
                type="number"
                min={0}
                max={100}
                value={maxK8s}
                onChange={(e) => setMaxK8s(Number(e.target.value))}
              />
            </div>
          </div>

          <div className="space-y-1">
            <Label htmlFor="max-spend">Monthly spending cap (USD)</Label>
            <Input
              id="max-spend"
              type="number"
              min={0}
              value={maxSpend}
              onChange={(e) => setMaxSpend(Number(e.target.value))}
            />
          </div>

          <div className="space-y-1">
            <Label htmlFor="allowed-types">
              Allowed instance types (comma-separated, blank = all)
            </Label>
            <Input
              id="allowed-types"
              placeholder="t3.micro, t3.small"
              value={allowedTypes}
              onChange={(e) => setAllowedTypes(e.target.value)}
            />
          </div>

          <div className="space-y-1">
            <Label htmlFor="quota-notes">Admin notes</Label>
            <Textarea
              id="quota-notes"
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
            />
          </div>
        </div>

        <DialogFooter className="gap-2">
          <Button
            variant="outline"
            onClick={() => resetMut.mutate()}
            disabled={resetMut.isPending}
          >
            Reset to Defaults
          </Button>
          <Button onClick={() => saveMut.mutate()} disabled={saveMut.isPending}>
            Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
