import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { FileStack, RefreshCw } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
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
  adminBatchGenerate1099s,
  adminListYear1099s,
  adminCorrect1099,
} from "@/api/endpoints/taxForm1099";
import type { TaxForm1099 } from "@/api/types";

const CURRENT_YEAR = new Date().getUTCFullYear();

function fmtCents(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

export default function TaxForm1099AdminPage() {
  const [year, setYear] = useState<number>(CURRENT_YEAR - 1);
  const qc = useQueryClient();

  const yearQuery = useQuery({
    queryKey: ["tax-form-1099", "admin-year", year],
    queryFn: () => adminListYear1099s(year),
  });

  const batchMut = useMutation({
    mutationFn: () => adminBatchGenerate1099s(year),
    onSuccess: (res) => {
      toast.success(
        `Batch complete: ${res.generated} generated, ${res.qualifying} qualifying, ${res.errors} errors`,
      );
      qc.invalidateQueries({ queryKey: ["tax-form-1099", "admin-year", year] });
    },
    onError: (err: unknown) => {
      const msg =
        err instanceof Error ? err.message : "Batch generation failed";
      toast.error(msg);
    },
  });

  const correctMut = useMutation({
    mutationFn: (userSub: string) => adminCorrect1099(year, userSub),
    onSuccess: () => {
      toast.success("1099 corrected");
      qc.invalidateQueries({ queryKey: ["tax-form-1099", "admin-year", year] });
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : "Correction failed";
      toast.error(msg);
    },
  });

  const forms: TaxForm1099[] = yearQuery.data?.items ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="1099 Batch Generation"
        description="Generate 1099-NEC forms across all eligible creators for a tax year."
      />

      <Card>
        <CardHeader>
          <CardTitle>Batch Generate</CardTitle>
          <CardDescription>
            Only creators earning above the reportable threshold ($600) are included.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex items-end gap-3">
          <div className="flex flex-col gap-1">
            <label htmlFor="admin-tax-year" className="text-sm font-medium">
              Tax Year
            </label>
            <Input
              id="admin-tax-year"
              type="number"
              className="w-32"
              value={year}
              onChange={(e) => setYear(Number(e.target.value))}
            />
          </div>
          <Button onClick={() => batchMut.mutate()} disabled={batchMut.isPending}>
            <FileStack className="mr-2 h-4 w-4" />
            Run Batch
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Generated Forms — {year}</CardTitle>
        </CardHeader>
        <CardContent>
          {yearQuery.isLoading ? (
            <Skeleton className="h-24 w-full" />
          ) : forms.length === 0 ? (
            <EmptyState
              icon={<FileStack className="h-8 w-8" />}
              title="No forms for this year"
              description="Run a batch generation to issue 1099 forms."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Creator</TableHead>
                  <TableHead>Earnings</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Corrections</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {forms.map((f) => (
                  <TableRow key={f.form_id || f.user_sub}>
                    <TableCell className="font-mono text-xs">{f.user_sub}</TableCell>
                    <TableCell>{fmtCents(f.total_earnings_cents)}</TableCell>
                    <TableCell className="capitalize">{f.status}</TableCell>
                    <TableCell>{f.correction_count}</TableCell>
                    <TableCell className="text-right">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => correctMut.mutate(f.user_sub)}
                        disabled={correctMut.isPending}
                      >
                        <RefreshCw className="mr-2 h-4 w-4" />
                        Correct
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
