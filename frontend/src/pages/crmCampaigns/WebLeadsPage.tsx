import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Users, RefreshCw } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { ApiError } from "@/api/client";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import { adminListLeads } from "@/api/endpoints/crmCampaigns";
import { CampaignsNotEnabled, isCampaignsDisabled } from "./CampaignsNotEnabled";

function fmt(ts?: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

export default function WebLeadsPage() {
  const [campaignFilter, setCampaignFilter] = useState("");
  const [cursor, setCursor] = useState<string | undefined>(undefined);

  const leadsQuery = useQuery({
    queryKey: ["crm-campaigns", "leads", campaignFilter, cursor],
    queryFn: () =>
      adminListLeads({
        campaign_id: campaignFilter.trim() || undefined,
        limit: 50,
        cursor,
      }),
    retry: false,
  });

  if (leadsQuery.isError && isCampaignsDisabled(leadsQuery.error)) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Web Leads"
          description="Leads captured via web-to-lead forms."
        />
        <CampaignsNotEnabled
          feature="Web-to-lead capture"
          status={(leadsQuery.error as ApiError)?.status}
        />
      </div>
    );
  }

  if (leadsQuery.isError && leadsQuery.error instanceof ApiError && leadsQuery.error.status === 403) {
    return (
      <div className="space-y-6">
        <PageHeader title="Web Leads" description="Leads captured via web-to-lead forms." />
        <CampaignsNotEnabled feature="Web Leads" status={403} />
      </div>
    );
  }

  const leads = leadsQuery.data?.leads ?? [];
  const nextCursor = leadsQuery.data?.cursor ?? null;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Web Leads"
        description="Leads captured via web-to-lead forms (admin view)."
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => leadsQuery.refetch()}
            disabled={leadsQuery.isFetching}
          >
            <RefreshCw className="mr-1 h-4 w-4" /> Refresh
          </Button>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Captured leads</CardTitle>
          <CardDescription>{leadsQuery.data?.count ?? 0} on this page</CardDescription>
          <div className="pt-2">
            <Input
              className="h-8 max-w-xs"
              placeholder="Filter by campaign ID"
              value={campaignFilter}
              onChange={(e) => {
                setCampaignFilter(e.target.value);
                setCursor(undefined);
              }}
            />
          </div>
        </CardHeader>
        <CardContent>
          {leadsQuery.isLoading ? (
            <div className="space-y-2">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : leads.length === 0 ? (
            <div className="flex flex-col items-center gap-2 py-10 text-center">
              <Users className="h-8 w-8 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">No leads captured yet.</p>
            </div>
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Email</TableHead>
                    <TableHead>Company</TableHead>
                    <TableHead>Phone</TableHead>
                    <TableHead>Campaign</TableHead>
                    <TableHead>Captured</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {leads.map((l) => (
                    <TableRow key={l.capture_id}>
                      <TableCell className="font-medium">
                        {[l.first_name, l.last_name].filter(Boolean).join(" ") || "—"}
                      </TableCell>
                      <TableCell>{l.email || "—"}</TableCell>
                      <TableCell>{l.company || "—"}</TableCell>
                      <TableCell>{l.phone || "—"}</TableCell>
                      <TableCell className="max-w-[160px] truncate">
                        {l.campaign_id || "—"}
                      </TableCell>
                      <TableCell>{fmt(l.created_at)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {nextCursor && (
                <div className="flex justify-end pt-3">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCursor(nextCursor)}
                  >
                    Load more
                  </Button>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
