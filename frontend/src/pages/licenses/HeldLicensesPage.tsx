import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { listHeldLicenses } from "@/api/endpoints/issuedLicenses";
import { Scale } from "lucide-react";

function statusBadge(status: string) {
  switch (status) {
    case "active":
      return <Badge variant="default">Active</Badge>;
    case "revoked":
      return <Badge variant="destructive">Revoked</Badge>;
    case "expired":
      return <Badge variant="secondary">Expired</Badge>;
    default:
      return <Badge variant="outline">{status}</Badge>;
  }
}

function formatTerms(terms: Record<string, number>) {
  const parts: string[] = [];
  if (terms.profit_share_pct) parts.push(`${terms.profit_share_pct}% profit share`);
  if (terms.fixed_cost_cents)
    parts.push(`$${(terms.fixed_cost_cents / 100).toFixed(2)} fixed`);
  if (terms.revenue_share_pct) parts.push(`${terms.revenue_share_pct}% revenue share`);
  return parts.length > 0 ? parts.join(" + ") : "No cost";
}

export default function HeldLicensesPage() {
  const { data, isLoading } = useQuery({
    queryKey: ["held-licenses"],
    queryFn: () => listHeldLicenses(),
  });

  const items = data?.items ?? [];

  return (
    <div className="space-y-6 p-6">
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Scale className="h-5 w-5" />
            <CardTitle>Licenses I Hold</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-muted-foreground py-8 text-center">Loading...</p>
          ) : items.length === 0 ? (
            <p className="text-muted-foreground py-8 text-center">
              No licenses held yet.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Content</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Licensor</TableHead>
                  <TableHead>Terms</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((item) => (
                  <TableRow key={item.issued_license_id}>
                    <TableCell>{item.content_id}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{item.content_type}</Badge>
                    </TableCell>
                    <TableCell>
                      {item.licensor_display_name || item.licensor_id}
                    </TableCell>
                    <TableCell className="text-sm">
                      {formatTerms(item.terms_snapshot)}
                    </TableCell>
                    <TableCell>{statusBadge(item.status)}</TableCell>
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
