import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { getPreferenceSummary } from "@/api/endpoints/productAgent";

export default function PreferenceDashboard() {
  const { data } = useQuery({
    queryKey: ["pm-preferences"],
    queryFn: () => getPreferenceSummary(),
    staleTime: 30_000,
  });

  const prefs = data?.preferences ?? [];

  return (
    <Card data-testid="preference-dashboard">
      <CardHeader>
        <CardTitle>Preference Learning</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          {prefs.map((p) => (
            <div key={p.category} className="flex items-center gap-2">
              <span className="w-32 text-sm">{p.category}</span>
              <div className="h-3 flex-1 rounded bg-muted">
                <div
                  className="h-3 rounded bg-primary"
                  style={{ width: `${Math.round(p.approval_rate * 100)}%` }}
                  data-testid={`pref-bar-${p.category}`}
                />
              </div>
              <span className="w-12 text-right text-xs">
                {Math.round(p.approval_rate * 100)}%
              </span>
            </div>
          ))}
        </div>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Category</TableHead>
              <TableHead>Suggested</TableHead>
              <TableHead>Approved</TableHead>
              <TableHead>Rejected</TableHead>
              <TableHead>Approval Rate</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {prefs.map((p) => (
              <TableRow key={p.category} data-testid={`pref-row-${p.category}`}>
                <TableCell>{p.category}</TableCell>
                <TableCell>{p.total_suggested}</TableCell>
                <TableCell>{p.total_approved}</TableCell>
                <TableCell>{p.total_rejected}</TableCell>
                <TableCell>{(p.approval_rate * 100).toFixed(1)}%</TableCell>
              </TableRow>
            ))}
            {prefs.length === 0 && (
              <TableRow>
                <TableCell colSpan={5} className="text-center text-sm text-muted-foreground">
                  No preference data yet.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}
