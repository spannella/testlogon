import { ApiError } from "@/api/client";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { FileBox, ShieldAlert } from "lucide-react";
import { LINKED_RECORD_TYPES, type LinkedRecordType } from "@/api/endpoints/crmDocuments";

/** A flag-off backend returns 404; a disabled provider returns 503. */
export function isNotEnabled(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 404 || err.status === 503);
}

/**
 * Rendered when the CRM Document Library flag is OFF (404/503) or the caller
 * lacks permission. Distinguishes the two so operators get an actionable message.
 */
export function CrmDocumentsNotEnabled({ status }: { status?: number }) {
  const isPerm = status === 403;
  const isAuth = status === 401;
  return (
    <Card className="border-dashed">
      <CardHeader>
        <div className="flex items-center gap-2">
          <ShieldAlert className="h-5 w-5 text-muted-foreground" />
          <CardTitle className="text-base">
            {isPerm
              ? "Insufficient permissions"
              : isAuth
                ? "Authentication required"
                : "Document Library is not enabled"}
          </CardTitle>
        </div>
        <CardDescription>
          {isPerm
            ? "You do not have permission to manage CRM documents."
            : isAuth
              ? "Sign in to manage CRM documents."
              : "The CRM Document Library is gated behind a server flag and is currently disabled. Ask an operator to set CRM_DOCUMENT_LIBRARY_ENABLED=1."}
        </CardDescription>
      </CardHeader>
      <CardContent className="text-sm text-muted-foreground">
        {!isPerm && !isAuth && (
          <p>Once the flag is enabled on the backend, this page will load automatically.</p>
        )}
      </CardContent>
    </Card>
  );
}

/** Empty-state card for list/detail views. */
export function EmptyDocs({ message }: { message: string }) {
  return (
    <Card className="border-dashed">
      <CardContent className="flex flex-col items-center justify-center gap-2 py-12 text-center text-muted-foreground">
        <FileBox className="h-8 w-8" />
        <p className="text-sm">{message}</p>
      </CardContent>
    </Card>
  );
}

export const RECORD_TYPE_OPTIONS: readonly LinkedRecordType[] = LINKED_RECORD_TYPES;

export function fmtTs(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

export function fmtBytes(bytes?: number | null): string {
  if (bytes == null) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = bytes / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

/** A document's path is the stable id; encode it for use in a route segment. */
export function encodeDocPath(path: string): string {
  return encodeURIComponent(path);
}
export function decodeDocPath(seg: string): string {
  return decodeURIComponent(seg);
}
