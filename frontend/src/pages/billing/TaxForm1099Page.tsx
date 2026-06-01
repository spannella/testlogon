import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { FileText, Download } from "lucide-react";
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
  listMy1099s,
  generateMy1099,
  downloadMy1099,
} from "@/api/endpoints/taxForm1099";
import type { TaxForm1099 } from "@/api/types";

const CURRENT_YEAR = new Date().getUTCFullYear();
const YEAR_PRESETS = [CURRENT_YEAR - 1, CURRENT_YEAR - 2, CURRENT_YEAR - 3].filter(
  (y) => y >= 2024,
);

function fmtCents(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

export default function TaxForm1099Page() {
  const [year, setYear] = useState<number>(YEAR_PRESETS[0] ?? CURRENT_YEAR - 1);
  const qc = useQueryClient();

  const formsQuery = useQuery({
    queryKey: ["tax-form-1099", "list"],
    queryFn: () => listMy1099s(),
  });

  const generateMut = useMutation({
    mutationFn: () => generateMy1099(year),
    onSuccess: () => {
      toast.success(`1099 generated for ${year}`);
      qc.invalidateQueries({ queryKey: ["tax-form-1099", "list"] });
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : "Failed to generate 1099";
      toast.error(msg);
    },
  });

  const downloadMut = useMutation({
    mutationFn: (taxYear: number) => downloadMy1099(taxYear),
    onSuccess: (res) => {
      if (res.download_url) {
        window.open(res.download_url, "_blank");
      }
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : "1099 not found";
      toast.error(msg);
    },
  });

  const forms: TaxForm1099[] = formsQuery.data?.items ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Tax Forms (1099-NEC)"
        description="Your annual 1099-NEC nonemployee compensation forms."
      />

      <Card>
        <CardHeader>
          <CardTitle>Generate a 1099-NEC</CardTitle>
          <CardDescription>
            1099-NEC forms are issued for creators earning $600 or more in a tax year.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex items-end gap-3">
          <div className="flex flex-col gap-1">
            <label htmlFor="tax-year-select" className="text-sm font-medium">
              Tax Year
            </label>
            <select
              id="tax-year-select"
              className="h-9 rounded-md border bg-background px-3 text-sm"
              value={year}
              onChange={(e) => setYear(Number(e.target.value))}
            >
              {YEAR_PRESETS.map((y) => (
                <option key={y} value={y}>
                  {y}
                </option>
              ))}
            </select>
          </div>
          <Button
            onClick={() => generateMut.mutate()}
            disabled={generateMut.isPending}
          >
            <FileText className="mr-2 h-4 w-4" />
            Generate 1099
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Your 1099 Forms</CardTitle>
        </CardHeader>
        <CardContent>
          {formsQuery.isLoading ? (
            <Skeleton className="h-24 w-full" />
          ) : forms.length === 0 ? (
            <EmptyState
              icon={<FileText className="h-8 w-8" />}
              title="No 1099 forms yet"
              description="1099-NEC forms appear here once generated for a tax year."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Tax Year</TableHead>
                  <TableHead>Earnings</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Download</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {forms.map((f) => (
                  <TableRow key={f.form_id || f.tax_year}>
                    <TableCell>{f.tax_year}</TableCell>
                    <TableCell>{fmtCents(f.total_earnings_cents)}</TableCell>
                    <TableCell className="capitalize">{f.status}</TableCell>
                    <TableCell className="text-right">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => downloadMut.mutate(f.tax_year)}
                        disabled={downloadMut.isPending}
                      >
                        <Download className="mr-2 h-4 w-4" />
                        PDF
                      </Button>
                    </TableCell>
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
