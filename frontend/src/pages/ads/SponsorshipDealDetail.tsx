import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  getSponsorshipDeal,
  getSponsorshipDealHistory,
} from "@/api/endpoints/sponsorshipDeals";
import type { SponsorshipDeal, SponsorshipDealEvent } from "@/api/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { statusBadge } from "./SponsorshipManager";

function formatCents(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

export default function SponsorshipDealDetail() {
  const { dealId = "" } = useParams();

  const { data: deal } = useQuery<SponsorshipDeal>({
    queryKey: ["sponsorship-deal", dealId],
    queryFn: () => getSponsorshipDeal(dealId),
    enabled: !!dealId,
  });

  const { data: events = [] } = useQuery<SponsorshipDealEvent[]>({
    queryKey: ["sponsorship-deal-history", dealId],
    queryFn: () => getSponsorshipDealHistory(dealId),
    enabled: !!dealId,
  });

  if (!deal) {
    return (
      <div className="p-4" data-testid="deal-detail-loading">
        Loading deal…
      </div>
    );
  }

  return (
    <div className="space-y-4 p-4" data-testid="deal-detail">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Sponsorship Deal</h1>
        {statusBadge(deal.status)}
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Terms</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <p>
            <span className="text-muted-foreground">Advertiser:</span> {deal.advertiser_sub}
          </p>
          <p>
            <span className="text-muted-foreground">Creator:</span> {deal.creator_sub}
          </p>
          <p>
            <span className="text-muted-foreground">Compensation:</span>{" "}
            {formatCents(deal.compensation_cents)}
          </p>
          <p>
            <span className="text-muted-foreground">Deadline:</span> {deal.deadline}
          </p>
          <p>
            <span className="text-muted-foreground">Brief:</span> {deal.brief}
          </p>
          <div>
            <span className="text-muted-foreground">Deliverables:</span>
            <ul className="ml-4 list-disc">
              {deal.deliverables.map((d, i) => (
                <li key={i}>{d}</li>
              ))}
            </ul>
          </div>
          {deal.content_id ? (
            <p data-testid="deal-content-id">
              <span className="text-muted-foreground">Linked content:</span> {deal.content_id}
            </p>
          ) : null}
          {deal.payment_details ? (
            <p data-testid="deal-payment">
              Paid creator {formatCents(deal.payment_details.creator_cents || 0)} (commission{" "}
              {formatCents(deal.payment_details.commission_cents || 0)})
            </p>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Timeline</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          {events.length === 0 ? (
            <p className="text-muted-foreground">No events.</p>
          ) : (
            <ul className="space-y-1">
              {events.map((e) => (
                <li key={e.event_id} data-testid={`event-${e.event_type}`}>
                  <span className="font-medium">{e.event_type}</span> by {e.actor_sub}
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
