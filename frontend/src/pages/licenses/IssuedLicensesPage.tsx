import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
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
import { listIssuedLicenses, revokeLicense } from "@/api/endpoints/issuedLicenses";
import { IssueLicenseDialog } from "./IssueLicenseDialog";
import { Scale } from "lucide-react";
import type { IssuedLicenseIndexItem } from "@/api/types";

const STATUS_OPTIONS = ["all", "active", "revoked"] as const;

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

function modeBadge(mode: string) {
  return mode === "blanket" ? (
    <Badge variant="outline">Blanket</Badge>
  ) : (
    <Badge variant="secondary">Per-User</Badge>
  );
}

export default function IssuedLicensesPage() {
  const queryClient = useQueryClient();
  const [statusFilter, setStatusFilter] = useState<string>("all");

  const { data, isLoading } = useQuery({
    queryKey: ["issued-licenses", statusFilter],
    queryFn: () =>
      listIssuedLicenses({
        status: statusFilter === "all" ? undefined : statusFilter,
      }),
  });

  const revokeMut = useMutation({
    mutationFn: (item: IssuedLicenseIndexItem) =>
      revokeLicense(item.issued_license_id, item.content_id, "Revoked by licensor"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["issued-licenses"] });
    },
  });

  const items = data?.items ?? [];

  return (
    <div className="space-y-6 p-6">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div className="flex items-center gap-2">
            <Scale className="h-5 w-5" />
            <CardTitle>Licenses I've Issued</CardTitle>
          </div>
          <IssueLicenseDialog />
        </CardHeader>
        <CardContent>
          <div className="mb-4">
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-40">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {STATUS_OPTIONS.map((s) => (
                  <SelectItem key={s} value={s}>
                    {s === "all" ? "All" : s.charAt(0).toUpperCase() + s.slice(1)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {isLoading ? (
            <p className="text-muted-foreground py-8 text-center">Loading...</p>
          ) : items.length === 0 ? (
            <p className="text-muted-foreground py-8 text-center">
              No licenses issued yet.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>License ID</TableHead>
                  <TableHead>Content</TableHead>
                  <TableHead>Mode</TableHead>
                  <TableHead>Licensee</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((item) => (
                  <TableRow key={item.issued_license_id}>
                    <TableCell className="font-mono text-xs">
                      {item.issued_license_id.slice(0, 12)}...
                    </TableCell>
                    <TableCell>{item.content_id}</TableCell>
                    <TableCell>{modeBadge(item.license_mode)}</TableCell>
                    <TableCell>
                      {item.licensee_id || <span className="text-muted-foreground">All</span>}
                    </TableCell>
                    <TableCell>{statusBadge(item.status)}</TableCell>
                    <TableCell>
                      {item.status === "active" && (
                        <Button
                          variant="destructive"
                          size="sm"
                          onClick={() => revokeMut.mutate(item)}
                          disabled={revokeMut.isPending}
                        >
                          Revoke
                        </Button>
                      )}
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
