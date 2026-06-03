/**
 * PiiAuditLog (KYC-023) -- Root-only table showing who accessed PII on a case,
 * which fields, for what reason, and when. Reads GET /pii/audit-log.
 */
import { useQuery } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { getCaseAuditLog } from "@/api/endpoints/kyc-cases";

export interface PiiAuditLogProps {
  caseId: string;
}

function fmtTime(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

export function PiiAuditLog({ caseId }: PiiAuditLogProps) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["kyc", "pii-audit", caseId],
    queryFn: () => getCaseAuditLog(caseId, 100),
    staleTime: 60_000,
  });

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 py-4 text-sm text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" /> Loading audit log…
      </div>
    );
  }
  if (isError) {
    return (
      <p className="py-4 text-sm text-destructive">Failed to load audit log.</p>
    );
  }

  const events = data?.events ?? [];
  if (events.length === 0) {
    return (
      <p className="py-4 text-sm text-muted-foreground" data-testid="pii-audit-empty">
        No PII access recorded for this case.
      </p>
    );
  }

  return (
    <Table data-testid="pii-audit-table">
      <TableHeader>
        <TableRow>
          <TableHead>Accessor</TableHead>
          <TableHead>Action</TableHead>
          <TableHead>Fields</TableHead>
          <TableHead>Reason</TableHead>
          <TableHead>IP</TableHead>
          <TableHead>When</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {events.map((e) => (
          <TableRow key={e.event_id} data-testid={`pii-audit-row-${e.event_id}`}>
            <TableCell className="font-mono text-xs">
              {e.accessor_display_name || e.accessor_sub}
            </TableCell>
            <TableCell>{e.action}</TableCell>
            <TableCell className="text-xs">{e.fields.join(", ")}</TableCell>
            <TableCell className="max-w-[16rem] truncate text-xs">{e.reason}</TableCell>
            <TableCell className="font-mono text-xs">{e.ip_address || "—"}</TableCell>
            <TableCell className="text-xs">{fmtTime(e.created_at)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export default PiiAuditLog;
