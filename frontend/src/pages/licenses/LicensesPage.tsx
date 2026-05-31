import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import {
  deleteLicenseAgreement,
  listLicenseAgreements,
  setLicenseAgreementStatus,
} from "@/api/endpoints/licenseAgreements";
import type { LicenseAgreementOut } from "@/api/types";
import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { UploadAgreementDialog } from "./UploadAgreementDialog";
import { AgreementDetailDialog } from "./AgreementDetailDialog";
import { LinkContentDialog } from "./LinkContentDialog";

const STATUS_FILTERS = [
  "all",
  "active",
  "pending_review",
  "expiring_soon",
  "expired",
  "archived",
  "rejected",
] as const;

function fmt(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}

function statusVariant(
  status: string,
): "default" | "secondary" | "destructive" | "outline" {
  if (status === "active") return "default";
  if (status === "rejected" || status === "expired") return "destructive";
  return "secondary";
}

export default function LicensesPage() {
  const queryClient = useQueryClient();
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [detailId, setDetailId] = useState<string | null>(null);
  const [linkId, setLinkId] = useState<string | null>(null);

  const listQuery = useQuery({
    queryKey: ["license-agreements", statusFilter],
    queryFn: () =>
      listLicenseAgreements({
        status: statusFilter === "all" ? undefined : statusFilter,
        limit: 50,
      }),
  });

  const refresh = () =>
    queryClient.invalidateQueries({ queryKey: ["license-agreements"] });

  const deleteMut = useMutation({
    mutationFn: async (id: string) => deleteLicenseAgreement(id),
    onSuccess: () => {
      toast.success("Agreement deleted");
      refresh();
    },
    onError: (e: Error) => toast.error(e.message || "Delete failed"),
  });

  const statusMut = useMutation({
    mutationFn: async (args: { id: string; status: "active" | "archived" }) =>
      setLicenseAgreementStatus(args.id, args.status),
    onSuccess: () => {
      toast.success("Status updated");
      refresh();
    },
    onError: (e: Error) => toast.error(e.message || "Update failed"),
  });

  const items: LicenseAgreementOut[] = listQuery.data?.items ?? [];

  return (
    <div className="space-y-4">
      <PageHeader
        title="License Agreements"
        description="Upload and manage agreements proving your rights to third-party content."
        actions={<UploadAgreementDialog onCreated={refresh} />}
      />

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-2">
            <div>
              <CardTitle>My License Agreements</CardTitle>
              <CardDescription>
                {items.length} agreement{items.length === 1 ? "" : "s"}
              </CardDescription>
            </div>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-48">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {STATUS_FILTERS.map((s) => (
                  <SelectItem key={s} value={s}>
                    {s.replace(/_/g, " ")}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent>
          {items.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No license agreements yet.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Title</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead>Content</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((a) => (
                  <TableRow key={a.license_id}>
                    <TableCell className="font-medium">
                      {a.title}
                      <div className="text-xs text-muted-foreground">
                        {a.licensor_name}
                      </div>
                    </TableCell>
                    <TableCell>{a.license_type.replace(/_/g, " ")}</TableCell>
                    <TableCell>
                      <Badge variant={statusVariant(a.status)}>
                        {a.status}
                      </Badge>
                      {a.expiring_soon && (
                        <Badge variant="destructive" className="ml-1">
                          expiring
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell
                      className={a.expiring_soon ? "text-destructive" : ""}
                    >
                      {fmt(a.expires_at)}
                    </TableCell>
                    <TableCell>{a.content_count}</TableCell>
                    <TableCell className="space-x-1 text-right">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => setDetailId(a.license_id)}
                      >
                        View
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => setLinkId(a.license_id)}
                      >
                        Link
                      </Button>
                      {a.status === "active" ? (
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() =>
                            statusMut.mutate({
                              id: a.license_id,
                              status: "archived",
                            })
                          }
                        >
                          Archive
                        </Button>
                      ) : a.status === "archived" ? (
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() =>
                            statusMut.mutate({
                              id: a.license_id,
                              status: "active",
                            })
                          }
                        >
                          Activate
                        </Button>
                      ) : null}
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => {
                          if (confirm("Delete this agreement?"))
                            deleteMut.mutate(a.license_id);
                        }}
                      >
                        Delete
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <AgreementDetailDialog
        licenseId={detailId}
        open={!!detailId}
        onOpenChange={(v) => !v && setDetailId(null)}
        onChanged={refresh}
      />
      {linkId && (
        <LinkContentDialog
          licenseId={linkId}
          open={!!linkId}
          onOpenChange={(v) => !v && setLinkId(null)}
          onLinked={refresh}
        />
      )}
    </div>
  );
}
