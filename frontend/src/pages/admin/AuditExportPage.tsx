import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ScrollText, Download, Loader2 } from "lucide-react";
import {
  createAuditExport,
  listAuditExports,
} from "@/api/endpoints/audit-export";
import type { AuditExportOut } from "@/api/endpoints/audit-export";

const CATEGORIES = ["auth", "moderation", "broadcast", "admin", "billing"];

function StatusBadge({ status }: { status: string }) {
  const variant =
    status === "completed"
      ? "default"
      : status === "failed"
        ? "destructive"
        : "secondary";
  return <Badge variant={variant}>{status}</Badge>;
}

export default function AuditExportPage() {
  const queryClient = useQueryClient();
  const [selectedCategories, setSelectedCategories] = useState<string[]>([
    "auth",
  ]);
  const [format, setFormat] = useState("ndjson");
  const [fromDate] = useState<number>(
    Math.floor(Date.now() / 1000) - 30 * 86400,
  );
  const [toDate] = useState<number>(Math.floor(Date.now() / 1000));

  const exportsQ = useQuery({
    queryKey: ["audit", "exports"],
    queryFn: () => listAuditExports(),
  });

  const createMut = useMutation({
    mutationFn: createAuditExport,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["audit", "exports"] });
    },
  });

  const toggleCategory = (cat: string) => {
    setSelectedCategories((prev) =>
      prev.includes(cat) ? prev.filter((c) => c !== cat) : [...prev, cat],
    );
  };

  const handleExport = () => {
    if (selectedCategories.length === 0) return;
    createMut.mutate({
      categories: selectedCategories,
      format,
      from_date: fromDate,
      to_date: toDate,
    });
  };

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center gap-3">
        <ScrollText className="w-8 h-8" />
        <h1 className="text-2xl font-bold">Audit Log Export</h1>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Export Filters</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-4 items-end">
          <div className="space-y-1">
            <label className="text-sm font-medium">Categories</label>
            <div className="flex gap-2 flex-wrap">
              {CATEGORIES.map((cat) => (
                <Button
                  key={cat}
                  size="sm"
                  variant={
                    selectedCategories.includes(cat) ? "default" : "outline"
                  }
                  onClick={() => toggleCategory(cat)}
                >
                  {cat}
                </Button>
              ))}
            </div>
          </div>
          <div className="space-y-1">
            <label className="text-sm font-medium">Format</label>
            <Select value={format} onValueChange={setFormat}>
              <SelectTrigger className="w-32">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ndjson">NDJSON</SelectItem>
                <SelectItem value="csv">CSV</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <Button onClick={handleExport} disabled={createMut.isPending}>
            {createMut.isPending ? (
              <Loader2 className="w-4 h-4 animate-spin mr-2" />
            ) : null}
            Export
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Export History</CardTitle>
        </CardHeader>
        <CardContent>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b">
                <th className="text-left p-2">ID</th>
                <th className="text-left p-2">Status</th>
                <th className="text-left p-2">Categories</th>
                <th className="text-left p-2">Events</th>
                <th className="text-left p-2">Created</th>
                <th className="text-left p-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {exportsQ.data?.exports?.map((exp: AuditExportOut) => (
                <tr key={exp.export_id} className="border-b">
                  <td className="p-2 font-mono text-xs">
                    {exp.export_id.slice(0, 12)}...
                  </td>
                  <td className="p-2">
                    <StatusBadge status={exp.status} />
                  </td>
                  <td className="p-2">{exp.categories.join(", ")}</td>
                  <td className="p-2">
                    {exp.event_count?.toLocaleString() ?? "-"}
                  </td>
                  <td className="p-2">
                    {new Date(exp.created_at * 1000).toLocaleDateString()}
                  </td>
                  <td className="p-2">
                    {exp.status === "completed" && (
                      <Button size="sm" variant="ghost">
                        <Download className="w-4 h-4" />
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  );
}
