import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link2, Plus, Trash2, Copy, BarChart3 } from "lucide-react";
import { toast } from "sonner";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

import {
  listAffiliateLinks,
  createAffiliateLink,
  deleteAffiliateLink,
  type AffiliateLinkOut,
} from "@/api/endpoints/affiliates";

function formatCents(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

function formatDate(ts: number): string {
  if (!ts) return "N/A";
  return new Date(ts * 1000).toLocaleDateString();
}

export default function AffiliateDashboard() {
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [targetType, setTargetType] = useState("catalog_item");
  const [targetId, setTargetId] = useState("");
  const [commissionPercent, setCommissionPercent] = useState("");
  const [customCode, setCustomCode] = useState("");

  const { data, isLoading } = useQuery({
    queryKey: ["affiliate-links"],
    queryFn: () => listAffiliateLinks(),
  });

  const createMut = useMutation({
    mutationFn: createAffiliateLink,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["affiliate-links"] });
      setCreateOpen(false);
      setTargetId("");
      setCommissionPercent("");
      setCustomCode("");
      toast.success("Affiliate link created");
    },
    onError: (err: any) => {
      toast.error(err?.response?.data?.detail || "Failed to create link");
    },
  });

  const deleteMut = useMutation({
    mutationFn: deleteAffiliateLink,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["affiliate-links"] });
      toast.success("Link revoked");
    },
  });

  const links: AffiliateLinkOut[] = data?.links ?? [];

  const handleCreate = () => {
    createMut.mutate({
      target_type: targetType,
      target_id: targetId,
      commission_percent: commissionPercent ? Number(commissionPercent) : undefined,
      custom_code: customCode || undefined,
    });
  };

  const handleCopy = (url: string) => {
    navigator.clipboard.writeText(window.location.origin + url);
    toast.success("Link copied to clipboard");
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <Link2 className="h-5 w-5" />
            Affiliate Links
          </CardTitle>
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <Plus className="mr-1 h-4 w-4" />
            Create Link
          </Button>
        </CardHeader>
        <CardContent>
          {isLoading && <p className="text-muted-foreground">Loading...</p>}
          {!isLoading && links.length === 0 && (
            <p className="text-muted-foreground">No affiliate links yet. Create one to get started.</p>
          )}
          {links.length > 0 && (
            <div className="space-y-4">
              {links.map((link) => (
                <div
                  key={link.link_id}
                  className="flex items-center justify-between rounded-lg border p-4"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{link.target_name}</span>
                      <Badge variant={link.status === "active" ? "default" : "secondary"}>
                        {link.status}
                      </Badge>
                    </div>
                    <p className="text-sm text-muted-foreground">
                      Code: <code>{link.tracking_code}</code> | Commission: {link.commission_percent}%
                    </p>
                    <div className="flex gap-4 text-xs text-muted-foreground">
                      <span><BarChart3 className="inline h-3 w-3 mr-1" />{link.click_count} clicks</span>
                      <span>{link.conversion_count} conversions</span>
                      <span>{formatCents(link.commission_earned_cents)} earned</span>
                      <span>Created {formatDate(link.created_at)}</span>
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleCopy(link.short_url)}
                    >
                      <Copy className="h-4 w-4" />
                    </Button>
                    {link.status === "active" && (
                      <Button
                        variant="destructive"
                        size="sm"
                        onClick={() => deleteMut.mutate(link.link_id)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Create Link Dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Affiliate Link</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div>
              <Label htmlFor="target_id">Product ID</Label>
              <Input
                id="target_id"
                value={targetId}
                onChange={(e) => setTargetId(e.target.value)}
                placeholder="Enter product ID"
              />
            </div>
            <div>
              <Label htmlFor="commission">Commission %</Label>
              <Input
                id="commission"
                type="number"
                value={commissionPercent}
                onChange={(e) => setCommissionPercent(e.target.value)}
                placeholder={`Default: ${10}%`}
                min={1}
                max={50}
              />
            </div>
            <div>
              <Label htmlFor="custom_code">Custom Code (optional)</Label>
              <Input
                id="custom_code"
                value={customCode}
                onChange={(e) => setCustomCode(e.target.value)}
                placeholder="e.g. MYLINK2026"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleCreate} disabled={!targetId || createMut.isPending}>
              {createMut.isPending ? "Creating..." : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
