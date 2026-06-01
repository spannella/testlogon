import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  listSponsorshipDeals,
  createSponsorshipDeal,
  completeSponsorshipDeal,
  cancelSponsorshipDeal,
} from "@/api/endpoints/sponsorshipDeals";
import type { SponsorshipDeal } from "@/api/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Handshake, Plus } from "lucide-react";

function formatCents(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

export function statusBadge(status: string) {
  const map: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
    proposed: "secondary",
    negotiating: "outline",
    accepted: "default",
    content_submitted: "default",
    completed: "default",
    rejected: "destructive",
    cancelled: "destructive",
  };
  return <Badge variant={map[status] || "secondary"}>{status}</Badge>;
}

export default function SponsorshipManager() {
  const queryClient = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [form, setForm] = useState({
    advertiser_account_id: "",
    creator_sub: "",
    content_type: "post",
    brief: "",
    deliverables: "",
    compensation_cents: "",
    deadline: "",
  });

  const { data: deals = [] } = useQuery<SponsorshipDeal[]>({
    queryKey: ["sponsorship-deals", "advertiser"],
    queryFn: () => listSponsorshipDeals({ role: "advertiser" }),
  });

  const createMut = useMutation({
    mutationFn: () =>
      createSponsorshipDeal({
        advertiser_account_id: form.advertiser_account_id,
        creator_sub: form.creator_sub,
        content_type: form.content_type as "post" | "video" | "broadcast",
        brief: form.brief,
        deliverables: form.deliverables.split("\n").map((s) => s.trim()).filter(Boolean),
        compensation_cents: Math.round(Number(form.compensation_cents) * 100),
        deadline: form.deadline,
      }),
    onSuccess: () => {
      toast.success("Deal proposed");
      setCreateOpen(false);
      queryClient.invalidateQueries({ queryKey: ["sponsorship-deals"] });
    },
    onError: () => toast.error("Failed to propose deal"),
  });

  const completeMut = useMutation({
    mutationFn: (id: string) => completeSponsorshipDeal(id),
    onSuccess: () => {
      toast.success("Deal completed; payment released");
      queryClient.invalidateQueries({ queryKey: ["sponsorship-deals"] });
    },
    onError: () => toast.error("Cannot complete deal"),
  });

  const cancelMut = useMutation({
    mutationFn: (id: string) => cancelSponsorshipDeal(id, "Cancelled by advertiser"),
    onSuccess: () => {
      toast.success("Deal cancelled");
      queryClient.invalidateQueries({ queryKey: ["sponsorship-deals"] });
    },
    onError: () => toast.error("Cannot cancel deal"),
  });

  return (
    <div className="space-y-4 p-4" data-testid="sponsorship-manager">
      <div className="flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-2xl font-semibold">
          <Handshake className="h-6 w-6" /> Sponsorship Manager
        </h1>
        <Button onClick={() => setCreateOpen(true)} data-testid="new-deal-btn">
          <Plus className="mr-1 h-4 w-4" /> New Deal
        </Button>
      </div>

      {deals.length === 0 ? (
        <p className="text-muted-foreground" data-testid="empty-state">
          No sponsorship deals yet.
        </p>
      ) : (
        <div className="grid gap-3">
          {deals.map((d) => (
            <Card key={d.deal_id} data-testid={`deal-${d.deal_id}`}>
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle className="text-base">
                  <Link to={`/ads/sponsorships/${d.deal_id}`} className="hover:underline">
                    Deal with {d.creator_sub}
                  </Link>
                </CardTitle>
                {statusBadge(d.status)}
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                <p className="line-clamp-2 text-muted-foreground">{d.brief}</p>
                <p className="font-medium">{formatCents(d.compensation_cents)} · due {d.deadline}</p>
                <div className="flex gap-2">
                  {d.status === "content_submitted" && (
                    <Button size="sm" onClick={() => completeMut.mutate(d.deal_id)}>
                      Approve &amp; Pay
                    </Button>
                  )}
                  {["proposed", "negotiating", "accepted", "content_submitted"].includes(d.status) && (
                    <Button size="sm" variant="outline" onClick={() => cancelMut.mutate(d.deal_id)}>
                      Cancel
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Propose Sponsorship Deal</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <Input
              placeholder="Advertiser account ID"
              value={form.advertiser_account_id}
              onChange={(e) => setForm({ ...form, advertiser_account_id: e.target.value })}
            />
            <Input
              placeholder="Creator (user id / email)"
              value={form.creator_sub}
              onChange={(e) => setForm({ ...form, creator_sub: e.target.value })}
            />
            <Textarea
              placeholder="Brief (what you want the creator to do)"
              value={form.brief}
              onChange={(e) => setForm({ ...form, brief: e.target.value })}
            />
            <Textarea
              placeholder="Deliverables (one per line)"
              value={form.deliverables}
              onChange={(e) => setForm({ ...form, deliverables: e.target.value })}
            />
            <Input
              type="number"
              placeholder="Compensation (USD)"
              value={form.compensation_cents}
              onChange={(e) => setForm({ ...form, compensation_cents: e.target.value })}
            />
            <Input
              type="date"
              value={form.deadline}
              onChange={(e) => setForm({ ...form, deadline: e.target.value })}
            />
          </div>
          <DialogFooter>
            <Button onClick={() => createMut.mutate()} disabled={createMut.isPending}>
              Propose
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
