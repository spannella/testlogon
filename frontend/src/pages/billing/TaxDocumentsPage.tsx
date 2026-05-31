import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { FileText, Download, TrendingUp, TrendingDown, RefreshCw } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import {
  Table,
  TableHeader,
  TableBody,
  TableHead,
  TableRow,
  TableCell,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { PageHeader } from "@/components/shared/PageHeader";
import {
  getSpendingSummary,
  getYearComparison,
  getDocumentHistory,
  generateTaxDocument,
  downloadSummaryPdf,
} from "@/api/endpoints/taxDocuments";

const CURRENT_YEAR = new Date().getUTCFullYear();
const YEAR_PRESETS = [CURRENT_YEAR, CURRENT_YEAR - 1, CURRENT_YEAR - 2].filter((y) => y >= 2024);

const CATEGORY_LABELS: Record<string, string> = {
  subscriptions: "Subscriptions",
  tips: "Tips",
  unlocks: "Unlocks",
  vod_purchases: "VOD Purchases",
  other: "Other",
};

function fmtCents(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

export default function TaxDocumentsPage() {
  const [year, setYear] = useState<number>(YEAR_PRESETS[0] ?? CURRENT_YEAR);
  const qc = useQueryClient();

  const summaryQuery = useQuery({
    queryKey: ["tax-documents", "summary", year],
    queryFn: () => getSpendingSummary({ year }),
  });

  const comparisonQuery = useQuery({
    queryKey: ["tax-documents", "comparison", year],
    queryFn: () => getYearComparison(year),
  });

  const historyQuery = useQuery({
    queryKey: ["tax-documents", "history"],
    queryFn: () => getDocumentHistory(),
  });

  const generateMut = useMutation({
    mutationFn: () => generateTaxDocument(year, true),
    onSuccess: () => {
      toast.success("Tax document generated");
      qc.invalidateQueries({ queryKey: ["tax-documents", "history"] });
    },
    onError: (err: any) => {
      const detail = err?.detail?.message || err?.message || "Failed to generate document";
      toast.error(detail);
    },
  });

  const summary = summaryQuery.data;
  const comparison = comparisonQuery.data;
  const changePct = comparison?.change_pct ?? 0;

  return (
    <div className="flex flex-col gap-6 p-4 sm:p-6">
      <PageHeader
        title="Tax Documents"
        description="Annual earnings summaries for tax reporting and record-keeping."
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              onClick={() => downloadSummaryPdf({ year }).catch((e) => toast.error(e.message))}
            >
              <Download className="mr-2 h-4 w-4" />
              Download Summary PDF
            </Button>
            <Button onClick={() => generateMut.mutate()} disabled={generateMut.isPending}>
              <RefreshCw className="mr-2 h-4 w-4" />
              {generateMut.isPending ? "Generating…" : "Generate Document"}
            </Button>
          </div>
        }
      />

      <div className="flex flex-wrap gap-2" data-testid="year-presets">
        {YEAR_PRESETS.map((y) => (
          <Button
            key={y}
            variant={y === year ? "default" : "outline"}
            size="sm"
            onClick={() => setYear(y)}
          >
            {y}
          </Button>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            Earnings Summary — {year}
          </CardTitle>
          <CardDescription>Credited earnings grouped by category.</CardDescription>
        </CardHeader>
        <CardContent>
          {summaryQuery.isLoading ? (
            <Skeleton className="h-40 w-full" />
          ) : summary ? (
            <div className="flex flex-col gap-4">
              <div className="flex items-baseline gap-3">
                <span className="text-3xl font-bold" data-testid="grand-total">
                  {fmtCents(summary.grand_total_cents)}
                </span>
                <span className="text-sm text-muted-foreground">
                  {summary.transaction_count} transactions
                </span>
              </div>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Category</TableHead>
                    <TableHead className="text-right">Count</TableHead>
                    <TableHead className="text-right">Total</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {summary.categories.map((c) => (
                    <TableRow key={c.category}>
                      <TableCell>{CATEGORY_LABELS[c.category] ?? c.category}</TableCell>
                      <TableCell className="text-right">{c.transaction_count}</TableCell>
                      <TableCell className="text-right">{fmtCents(c.total_cents)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <EmptyState title="No data" description="No earnings found for this period." />
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Year-over-Year Comparison</CardTitle>
        </CardHeader>
        <CardContent>
          {comparisonQuery.isLoading ? (
            <Skeleton className="h-20 w-full" />
          ) : comparison ? (
            <div className="flex flex-col gap-2">
              <div className="flex items-center gap-6">
                <div>
                  <div className="text-sm text-muted-foreground">{comparison.current_year}</div>
                  <div className="text-xl font-semibold">
                    {fmtCents(comparison.current_summary.grand_total_cents)}
                  </div>
                </div>
                <div>
                  <div className="text-sm text-muted-foreground">{comparison.previous_year}</div>
                  <div className="text-xl font-semibold">
                    {fmtCents(comparison.previous_summary.grand_total_cents)}
                  </div>
                </div>
                <div
                  className={`flex items-center gap-1 font-medium ${
                    changePct >= 0 ? "text-green-600" : "text-red-600"
                  }`}
                  data-testid="change-pct"
                >
                  {changePct >= 0 ? (
                    <TrendingUp className="h-4 w-4" />
                  ) : (
                    <TrendingDown className="h-4 w-4" />
                  )}
                  {changePct.toFixed(1)}%
                </div>
              </div>
            </div>
          ) : (
            <EmptyState title="No comparison" description="Not enough data to compare." />
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Document History</CardTitle>
          <CardDescription>Previously generated tax documents.</CardDescription>
        </CardHeader>
        <CardContent>
          {historyQuery.isLoading ? (
            <Skeleton className="h-20 w-full" />
          ) : historyQuery.data && historyQuery.data.documents.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Year</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead className="text-right">Total</TableHead>
                  <TableHead className="text-right">Transactions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {historyQuery.data.documents.map((d) => (
                  <TableRow key={d.doc_id} data-testid="history-row">
                    <TableCell>{d.year ?? "—"}</TableCell>
                    <TableCell>{d.doc_type}</TableCell>
                    <TableCell className="text-right">{fmtCents(d.grand_total_cents)}</TableCell>
                    <TableCell className="text-right">{d.transaction_count}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <EmptyState title="No documents generated yet" description="" />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
