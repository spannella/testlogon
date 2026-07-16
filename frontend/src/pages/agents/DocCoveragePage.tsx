import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  getDocCoverage,
  listDocCoverageDetails,
  triggerFreshnessCheck,
} from "@/api/endpoints/docsAgent";
import type { DocTypeSummary } from "@/api/types";
import StaleDocsPanel from "@/pages/agents/StaleDocsPanel";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { BookOpen, RefreshCw, FileWarning, FileCheck2 } from "lucide-react";

function StatCard({
  label,
  value,
  accent,
}: {
  label: string;
  value: string | number;
  accent?: "red" | "green";
}) {
  const color =
    accent === "red" ? "text-red-500" : accent === "green" ? "text-green-500" : "text-foreground";
  return (
    <Card>
      <CardContent className="p-4">
        <div className="text-sm text-muted-foreground">{label}</div>
        <div className={`mt-1 text-2xl font-semibold ${color}`}>{value}</div>
      </CardContent>
    </Card>
  );
}

function pct(n: number): string {
  return `${Math.round((n || 0) * 100)}%`;
}

export default function DocCoveragePage() {
  const queryClient = useQueryClient();
  const [typeFilter, setTypeFilter] = useState<string>("all");

  const { data: summary } = useQuery({
    queryKey: ["doc-coverage"],
    queryFn: () =>
      getDocCoverage().catch(() => ({
        overall_coverage: 0,
        total_docs: 0,
        stale_docs: 0,
        by_type: {},
      })),
  });

  const { data: details } = useQuery({
    queryKey: ["doc-details", typeFilter],
    queryFn: () =>
      listDocCoverageDetails(typeFilter === "all" ? undefined : typeFilter).catch(() => ({
        docs: [],
        count: 0,
      })),
  });

  const freshnessMut = useMutation({
    mutationFn: () => triggerFreshnessCheck(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["doc-coverage"] });
      queryClient.invalidateQueries({ queryKey: ["doc-details"] });
      queryClient.invalidateQueries({ queryKey: ["doc-stale"] });
    },
  });

  const total = summary?.total_docs ?? 0;
  const stale = summary?.stale_docs ?? 0;
  const fresh = total - stale;
  const byType: Record<string, DocTypeSummary> = summary?.by_type ?? {};

  return (
    <div data-testid="doc-coverage-page" className="space-y-6 p-4">
      <div className="flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-2xl font-semibold">
          <BookOpen className="h-6 w-6" /> Documentation Coverage
        </h1>
        <div className="flex gap-2">
          <Button asChild variant="outline" size="sm">
            <Link to="/agents/docs/templates">Templates</Link>
          </Button>
          <Button
            size="sm"
            onClick={() => freshnessMut.mutate()}
            disabled={freshnessMut.isPending}
          >
            <RefreshCw className="mr-1 h-4 w-4" /> Run Freshness Check
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Overall Coverage" value={pct(summary?.overall_coverage ?? 0)} />
        <StatCard label="Total Docs" value={total} />
        <StatCard label="Stale Docs" value={stale} accent={stale > 0 ? "red" : undefined} />
        <StatCard label="Fresh Docs" value={fresh} accent="green" />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Coverage by Type</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {Object.keys(byType).length === 0 ? (
            <div className="text-sm text-muted-foreground">No documentation tracked yet</div>
          ) : (
            Object.entries(byType).map(([dt, info]) => (
              <div key={dt} className="space-y-1">
                <div className="flex items-center justify-between text-sm">
                  <span className="font-medium">{dt}</span>
                  <span className="text-muted-foreground">
                    {pct(info.avg_coverage)} · {info.count} docs · {info.stale_count} stale
                  </span>
                </div>
                <Progress value={(info.avg_coverage || 0) * 100} />
              </div>
            ))
          )}
        </CardContent>
      </Card>

      <Tabs defaultValue="all">
        <TabsList>
          <TabsTrigger value="all">
            <FileCheck2 className="mr-1 h-4 w-4" /> All Docs
          </TabsTrigger>
          <TabsTrigger value="stale">
            <FileWarning className="mr-1 h-4 w-4" /> Stale Only
          </TabsTrigger>
        </TabsList>

        <TabsContent value="all" className="space-y-3">
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">Filter by type:</span>
            <Select value={typeFilter} onValueChange={setTypeFilter}>
              <SelectTrigger className="w-48">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All types</SelectItem>
                <SelectItem value="api">api</SelectItem>
                <SelectItem value="architecture">architecture</SelectItem>
                <SelectItem value="user_guide">user_guide</SelectItem>
                <SelectItem value="adr">adr</SelectItem>
                <SelectItem value="readme">readme</SelectItem>
                <SelectItem value="inline">inline</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <Card>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Doc Path</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Coverage</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(details?.docs ?? []).length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={4} className="text-center text-muted-foreground">
                      No tracked docs
                    </TableCell>
                  </TableRow>
                ) : (
                  (details?.docs ?? []).map((doc) => (
                    <TableRow key={doc.doc_path}>
                      <TableCell className="font-mono text-xs">{doc.doc_path}</TableCell>
                      <TableCell>{doc.doc_type}</TableCell>
                      <TableCell className="w-40">
                        <div className="flex items-center gap-2">
                          <Progress value={doc.coverage_score * 100} className="w-24" />
                          <span className="text-xs">{pct(doc.coverage_score)}</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        {doc.is_stale ? (
                          <Badge variant="destructive">Stale</Badge>
                        ) : (
                          <Badge className="bg-green-600 hover:bg-green-600">Fresh</Badge>
                        )}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </Card>
        </TabsContent>

        <TabsContent value="stale">
          <StaleDocsPanel />
        </TabsContent>
      </Tabs>
    </div>
  );
}
