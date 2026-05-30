import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
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
import { issueLicense } from "@/api/endpoints/issuedLicenses";
import { Plus } from "lucide-react";

const CONTENT_TYPES = ["video", "music", "image", "post", "broadcast", "clip"] as const;

export function IssueLicenseDialog() {
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [contentId, setContentId] = useState("");
  const [contentType, setContentType] = useState<string>("video");
  const [licenseMode, setLicenseMode] = useState<"per_user" | "blanket">("blanket");
  const [licenseeId, setLicenseeId] = useState("");
  const [profitSharePct, setProfitSharePct] = useState(0);
  const [fixedCostCents, setFixedCostCents] = useState(0);
  const [revenueSharePct, setRevenueSharePct] = useState(0);
  const [title, setTitle] = useState("");

  const mut = useMutation({
    mutationFn: () =>
      issueLicense({
        content_id: contentId,
        content_type: contentType,
        license_mode: licenseMode,
        licensee_id: licenseMode === "per_user" ? licenseeId : undefined,
        profit_share_pct: profitSharePct,
        fixed_cost_cents: fixedCostCents,
        revenue_share_pct: revenueSharePct,
        title,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["issued-licenses"] });
      queryClient.invalidateQueries({ queryKey: ["licensed-library"] });
      setOpen(false);
      resetForm();
    },
  });

  function resetForm() {
    setContentId("");
    setContentType("video");
    setLicenseMode("blanket");
    setLicenseeId("");
    setProfitSharePct(0);
    setFixedCostCents(0);
    setRevenueSharePct(0);
    setTitle("");
  }

  const canSubmit = contentId.trim() && (licenseMode !== "per_user" || licenseeId.trim());

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">
          <Plus className="mr-1 h-4 w-4" />
          Issue License
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Issue a License</DialogTitle>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div>
            <Label>Content ID</Label>
            <Input value={contentId} onChange={(e) => setContentId(e.target.value)} placeholder="e.g., vid_abc123" />
          </div>
          <div>
            <Label>Title</Label>
            <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Content title" />
          </div>
          <div>
            <Label>Content Type</Label>
            <Select value={contentType} onValueChange={setContentType}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {CONTENT_TYPES.map((ct) => (
                  <SelectItem key={ct} value={ct}>{ct.charAt(0).toUpperCase() + ct.slice(1)}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label>License Mode</Label>
            <Select value={licenseMode} onValueChange={(v) => setLicenseMode(v as "per_user" | "blanket")}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="blanket">Blanket (open to all)</SelectItem>
                <SelectItem value="per_user">Per-User (specific creator)</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {licenseMode === "per_user" && (
            <div>
              <Label>Licensee ID</Label>
              <Input value={licenseeId} onChange={(e) => setLicenseeId(e.target.value)} placeholder="e.g., bob@test.local" />
            </div>
          )}
          <div className="grid grid-cols-3 gap-2">
            <div>
              <Label>Profit Share %</Label>
              <Input type="number" min={0} max={100} value={profitSharePct} onChange={(e) => setProfitSharePct(Number(e.target.value))} />
            </div>
            <div>
              <Label>Fixed Cost (cents)</Label>
              <Input type="number" min={0} value={fixedCostCents} onChange={(e) => setFixedCostCents(Number(e.target.value))} />
            </div>
            <div>
              <Label>Revenue Share %</Label>
              <Input type="number" min={0} max={100} value={revenueSharePct} onChange={(e) => setRevenueSharePct(Number(e.target.value))} />
            </div>
          </div>
          <Button onClick={() => mut.mutate()} disabled={!canSubmit || mut.isPending} className="w-full">
            {mut.isPending ? "Issuing..." : "Issue License"}
          </Button>
          {mut.isError && (
            <p className="text-sm text-destructive">
              {(mut.error as Error)?.message || "Failed to issue license"}
            </p>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
