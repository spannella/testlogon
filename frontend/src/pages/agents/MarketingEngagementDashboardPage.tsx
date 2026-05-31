import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { BarChart3 } from "lucide-react";
import { getEngagementSummary } from "@/api/endpoints/marketingAgent";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export default function MarketingEngagementDashboardPage() {
  const { data, isLoading } = useQuery({
    queryKey: ["marketing-engagement-summary"],
    queryFn: () => getEngagementSummary(30),
    staleTime: 5_000,
  });

  const conversion =
    data && data.total_views > 0
      ? ((data.total_clicks / data.total_views) * 100).toFixed(1)
      : "0.0";

  return (
    <div data-testid="engagement-dashboard-page" className="space-y-4 p-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <BarChart3 className="h-6 w-6" />
          <h1 className="text-2xl font-bold">Engagement Dashboard</h1>
        </div>
        <Button asChild variant="outline" size="sm">
          <Link to="/agents/marketing">Back to Content</Link>
        </Button>
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4" data-testid="summary-cards">
        <SummaryCard label="Total Content" value={data?.total_content ?? 0} />
        <SummaryCard label="Total Views" value={data?.total_views ?? 0} />
        <SummaryCard label="Total Clicks" value={data?.total_clicks ?? 0} />
        <SummaryCard label="Conversion" value={`${conversion}%`} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Top Performing</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p>Loading…</p>
          ) : (data?.top_performing?.length ?? 0) === 0 ? (
            <p data-testid="engagement-empty" className="text-muted-foreground">
              No engagement data yet.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Title</TableHead>
                  <TableHead className="text-right">Clicks</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data!.top_performing.map((p) => (
                  <TableRow key={p.content_id}>
                    <TableCell>
                      <Link
                        to={`/agents/marketing/content/${p.content_id}`}
                        className="hover:underline"
                      >
                        {p.title}
                      </Link>
                    </TableCell>
                    <TableCell className="text-right">{p.clicks}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function SummaryCard({ label, value }: { label: string; value: number | string }) {
  return (
    <Card>
      <CardContent className="p-4">
        <p className="text-sm text-muted-foreground">{label}</p>
        <p className="text-2xl font-bold">{value}</p>
      </CardContent>
    </Card>
  );
}
