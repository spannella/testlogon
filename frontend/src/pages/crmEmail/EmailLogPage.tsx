import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { History, BarChart3 } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { ApiError } from "@/api/client";
import {
  getCampaignAttribution,
  listCampaigns,
  type CrmCampaign,
} from "@/api/endpoints/crmEmail";
import { NotEnabledState, isNotEnabledError } from "./NotEnabledState";

function fmt(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

function pct(rate: number): string {
  return `${(rate * 100).toFixed(1)}%`;
}

function AttributionPanel({ campaign }: { campaign: CrmCampaign }) {
  const q = useQuery({
    queryKey: ["crm-email", "attribution", campaign.campaign_id],
    queryFn: () => getCampaignAttribution(campaign.campaign_id),
    retry: false,
  });

  if (q.isLoading) {
    return <Skeleton className="h-24 w-full" />;
  }
  if (q.isError) {
    return (
      <p className="text-sm text-destructive">
        {(q.error as ApiError)?.detail ?? "Failed to load attribution"}
      </p>
    );
  }

  const a = q.data!;
  const stats = [
    { label: "Sent", value: String(a.total_sent) },
    { label: "Email sent", value: String(a.email_sent) },
    { label: "Opens", value: String(a.open_count) },
    { label: "Open rate", value: pct(a.open_rate) },
    { label: "Clicks", value: String(a.click_count) },
    { label: "Click rate", value: pct(a.click_rate) },
  ];

  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
      {stats.map((s) => (
        <div key={s.label} className="rounded-md border p-3">
          <p className="text-xs text-muted-foreground">{s.label}</p>
          <p className="text-lg font-semibold tabular-nums">{s.value}</p>
        </div>
      ))}
    </div>
  );
}

export default function EmailLogPage() {
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const campaignsQuery = useQuery({
    queryKey: ["crm-email", "campaigns", "email"],
    queryFn: () => listCampaigns({ campaign_type: "email", limit: 100 }),
    retry: false,
  });

  const campaigns = campaignsQuery.data?.campaigns ?? [];
  const selected = campaigns.find((c) => c.campaign_id === selectedId) ?? null;

  if (campaignsQuery.isError && isNotEnabledError(campaignsQuery.error)) {
    return (
      <div className="space-y-6">
        <PageHeader title="Email Log" description="SuiteCRM email send history & attribution" />
        <NotEnabledState feature="Email log" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Email Log"
        description="Email campaign send history with open / click attribution."
      />

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <History className="h-4 w-4" /> Campaign history
          </CardTitle>
          <CardDescription>
            {campaignsQuery.data
              ? `${campaignsQuery.data.count} email campaign(s)`
              : "Loading…"}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {campaignsQuery.isLoading && (
            <div className="space-y-2">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          )}
          {campaignsQuery.isError && !isNotEnabledError(campaignsQuery.error) && (
            <p className="text-sm text-destructive">
              {(campaignsQuery.error as ApiError)?.detail ?? "Failed to load campaigns"}
            </p>
          )}
          {!campaignsQuery.isLoading && campaigns.length === 0 && (
            <p className="py-8 text-center text-sm text-muted-foreground">
              No email campaigns have been created yet.
            </p>
          )}
          {campaigns.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Campaign</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Updated</TableHead>
                  <TableHead className="text-right">Attribution</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {campaigns.map((c) => (
                  <TableRow
                    key={c.campaign_id}
                    className={`cursor-pointer ${
                      selectedId === c.campaign_id ? "bg-accent" : ""
                    }`}
                    onClick={() =>
                      setSelectedId((prev) => (prev === c.campaign_id ? null : c.campaign_id))
                    }
                  >
                    <TableCell className="font-medium">{c.name}</TableCell>
                    <TableCell>
                      <Badge variant={c.status === "draft" ? "secondary" : "default"}>
                        {c.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">{fmt(c.created_at)}</TableCell>
                    <TableCell className="text-muted-foreground">{fmt(c.updated_at)}</TableCell>
                    <TableCell className="text-right">
                      <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
                        <BarChart3 className="h-3.5 w-3.5" />
                        {selectedId === c.campaign_id ? "Hide" : "View"}
                      </span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {selected && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <BarChart3 className="h-4 w-4" /> Attribution — {selected.name}
            </CardTitle>
            <CardDescription>Opens and clicks tracked for this campaign.</CardDescription>
          </CardHeader>
          <CardContent>
            <AttributionPanel campaign={selected} />
          </CardContent>
        </Card>
      )}
    </div>
  );
}
