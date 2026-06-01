import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ShieldCheck, Loader2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  adjudicateKycIdScan,
  listKycIdScansByStatus,
} from "@/api/endpoints/kycIdScanner";
import type { KycIdScannerStatus } from "@/api/types";

const STATUSES: KycIdScannerStatus[] = [
  "flagged",
  "matched",
  "rejected",
  "approved",
  "declined",
];

function statusVariant(status: string) {
  if (status === "matched" || status === "approved") return "default" as const;
  if (status === "flagged") return "secondary" as const;
  return "destructive" as const;
}

export default function KycIdScannerReviewQueuePage() {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<KycIdScannerStatus>("flagged");

  const { data, isLoading } = useQuery({
    queryKey: ["kyc-id-scans", "by-status", status],
    queryFn: () => listKycIdScansByStatus(status),
  });

  const adjudicate = useMutation({
    mutationFn: ({ scanId, decision }: { scanId: string; decision: "approve" | "decline" }) =>
      adjudicateKycIdScan(scanId, { decision }),
    onSuccess: () => {
      toast.success("Scan adjudicated");
      queryClient.invalidateQueries({ queryKey: ["kyc-id-scans", "by-status"] });
    },
    onError: () => toast.error("Adjudication failed"),
  });

  const scans = data?.scans ?? [];

  return (
    <div className="mx-auto max-w-5xl space-y-6 p-4">
      <div className="flex items-center gap-2">
        <ShieldCheck className="h-6 w-6" />
        <h1 className="text-2xl font-semibold">ID Scan Review Queue</h1>
      </div>

      <Tabs value={status} onValueChange={(v) => setStatus(v as KycIdScannerStatus)}>
        <TabsList>
          {STATUSES.map((s) => (
            <TabsTrigger key={s} value={s} data-testid={`kyc-scan-tab-${s}`}>
              {s}
            </TabsTrigger>
          ))}
        </TabsList>
      </Tabs>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">{status} scans</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-sm text-muted-foreground">Loading...</p>
          ) : scans.length === 0 ? (
            <p className="text-sm text-muted-foreground" data-testid="kyc-scan-queue-empty">
              No scans with this status.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Document</TableHead>
                  <TableHead>MRZ</TableHead>
                  <TableHead>Expiry</TableHead>
                  <TableHead>Match</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scans.map((s) => (
                  <TableRow key={s.scan_id} data-testid="kyc-scan-queue-row" data-scan-id={s.scan_id}>
                    <TableCell>
                      {s.document_type}{" "}
                      <span className="text-muted-foreground">({s.file_type})</span>
                    </TableCell>
                    <TableCell>
                      <Badge variant={s.mrz_valid ? "default" : "destructive"}>
                        {s.mrz_valid ? "valid" : "invalid"}
                      </Badge>
                    </TableCell>
                    <TableCell>{s.expiry_status ?? "—"}</TableCell>
                    <TableCell>{s.match_score != null ? `${s.match_score}%` : "—"}</TableCell>
                    <TableCell>
                      <Badge variant={statusVariant(s.status)}>{s.status}</Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={adjudicate.isPending}
                          onClick={() => adjudicate.mutate({ scanId: s.scan_id, decision: "approve" })}
                          data-testid="kyc-scan-approve"
                        >
                          Approve
                        </Button>
                        <Button
                          size="sm"
                          variant="destructive"
                          disabled={adjudicate.isPending}
                          onClick={() => adjudicate.mutate({ scanId: s.scan_id, decision: "decline" })}
                          data-testid="kyc-scan-decline"
                        >
                          {adjudicate.isPending && <Loader2 className="mr-1 h-3 w-3 animate-spin" />}
                          Decline
                        </Button>
                      </div>
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
