import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  listSponsorshipDeals,
  acceptSponsorshipDeal,
  rejectSponsorshipDeal,
  submitSponsorshipContent,
} from "@/api/endpoints/sponsorshipDeals";
import type { SponsorshipDeal } from "@/api/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Inbox } from "lucide-react";
import { statusBadge } from "./SponsorshipManager";

function formatCents(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

const TABS: { key: string; label: string; statuses: string[] }[] = [
  { key: "pending", label: "Pending", statuses: ["proposed", "negotiating"] },
  { key: "active", label: "Active", statuses: ["accepted", "content_submitted"] },
  { key: "completed", label: "Completed", statuses: ["completed"] },
  { key: "cancelled", label: "Cancelled", statuses: ["rejected", "cancelled"] },
];

export default function SponsorshipInbox() {
  const queryClient = useQueryClient();
  const [contentIds, setContentIds] = useState<Record<string, string>>({});

  const { data: deals = [] } = useQuery<SponsorshipDeal[]>({
    queryKey: ["sponsorship-deals", "creator"],
    queryFn: () => listSponsorshipDeals({ role: "creator" }),
  });

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["sponsorship-deals"] });

  const acceptMut = useMutation({
    mutationFn: (id: string) => acceptSponsorshipDeal(id),
    onSuccess: () => {
      toast.success("Deal accepted");
      invalidate();
    },
    onError: () => toast.error("Cannot accept deal"),
  });
  const rejectMut = useMutation({
    mutationFn: (id: string) => rejectSponsorshipDeal(id, "Not a fit"),
    onSuccess: () => {
      toast.success("Deal rejected");
      invalidate();
    },
    onError: () => toast.error("Cannot reject deal"),
  });
  const submitMut = useMutation({
    mutationFn: ({ id, contentId }: { id: string; contentId: string }) =>
      submitSponsorshipContent(id, contentId),
    onSuccess: () => {
      toast.success("Content submitted");
      invalidate();
    },
    onError: () => toast.error("Cannot submit content"),
  });

  return (
    <div className="space-y-4 p-4" data-testid="sponsorship-inbox">
      <h1 className="flex items-center gap-2 text-2xl font-semibold">
        <Inbox className="h-6 w-6" /> Sponsorship Inbox
      </h1>

      <Tabs defaultValue="pending">
        <TabsList>
          {TABS.map((t) => (
            <TabsTrigger key={t.key} value={t.key} data-testid={`tab-${t.key}`}>
              {t.label}
            </TabsTrigger>
          ))}
        </TabsList>
        {TABS.map((t) => {
          const filtered = deals.filter((d) => t.statuses.includes(d.status));
          return (
            <TabsContent key={t.key} value={t.key} className="space-y-3">
              {filtered.length === 0 ? (
                <p className="text-muted-foreground" data-testid={`empty-${t.key}`}>
                  Nothing here.
                </p>
              ) : (
                filtered.map((d) => (
                  <Card key={d.deal_id} data-testid={`deal-${d.deal_id}`}>
                    <CardHeader className="flex flex-row items-center justify-between">
                      <CardTitle className="text-base">
                        <Link to={`/ads/sponsorships/${d.deal_id}`} className="hover:underline">
                          From {d.advertiser_sub}
                        </Link>
                      </CardTitle>
                      {statusBadge(d.status)}
                    </CardHeader>
                    <CardContent className="space-y-2 text-sm">
                      <p className="line-clamp-2 text-muted-foreground">{d.brief}</p>
                      <p className="font-medium">
                        {formatCents(d.compensation_cents)} · due {d.deadline}
                      </p>
                      {d.status === "proposed" || d.status === "negotiating" ? (
                        <div className="flex gap-2">
                          <Button size="sm" onClick={() => acceptMut.mutate(d.deal_id)}>
                            Accept
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => rejectMut.mutate(d.deal_id)}
                          >
                            Reject
                          </Button>
                        </div>
                      ) : null}
                      {d.status === "accepted" ? (
                        <div className="flex gap-2">
                          <Input
                            placeholder="Content / post id"
                            value={contentIds[d.deal_id] || ""}
                            onChange={(e) =>
                              setContentIds({ ...contentIds, [d.deal_id]: e.target.value })
                            }
                          />
                          <Button
                            size="sm"
                            onClick={() =>
                              submitMut.mutate({
                                id: d.deal_id,
                                contentId: contentIds[d.deal_id] || "",
                              })
                            }
                          >
                            Submit
                          </Button>
                        </div>
                      ) : null}
                    </CardContent>
                  </Card>
                ))
              )}
            </TabsContent>
          );
        })}
      </Tabs>
    </div>
  );
}
