/**
 * PMD-002 — Property Documents page.
 *
 * Route: /property/dashboard/documents (accessible from dashboard deep-links)
 *
 * Lists documents linked to a specific property-domain record.
 * Supports linking new documents (by doc_id) and unlinking existing ones.
 *
 * Flag-gated: PROPERTY_DASHBOARD_ENABLED (default OFF).
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { FileText, Loader2, AlertCircle, Trash2, Plus } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";

import { ApiError } from "@/api/client";
import {
  listPropertyDocuments,
  linkPropertyDocument,
  unlinkPropertyDocument,
  type PropertyDocumentRecordType,
} from "@/api/endpoints/propertyDashboard";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function fmtTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

const RECORD_TYPES: PropertyDocumentRecordType[] = ["property", "unit", "lease", "tenant"];

// ─── Feature-not-enabled guard ────────────────────────────────────────────────

function FeatureDisabled() {
  return (
    <div className="flex flex-col items-center justify-center py-20 gap-4 text-muted-foreground">
      <AlertCircle className="h-10 w-10" />
      <p className="text-lg font-medium">Property Dashboard is not enabled</p>
      <p className="text-sm">
        Enable <code>PROPERTY_DASHBOARD_ENABLED</code> to use this feature.
      </p>
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function PropertyDocumentsPage() {
  const queryClient = useQueryClient();

  const [recordType, setRecordType] = useState<PropertyDocumentRecordType>("property");
  const [recordId, setRecordId] = useState("");

  const [linkDocId, setLinkDocId] = useState("");
  const [linkFilePath, setLinkFilePath] = useState("");
  const [linkCategory, setLinkCategory] = useState("");
  const [linkDescription, setLinkDescription] = useState("");
  const [showLinkForm, setShowLinkForm] = useState(false);

  const [cursor, setCursor] = useState<string | undefined>(undefined);

  const queryKey = ["property", "documents", recordType, recordId, cursor];

  const docsQuery = useQuery({
    queryKey,
    queryFn: () => listPropertyDocuments(recordType, recordId, { limit: 20, cursor }),
    enabled: recordId.trim().length > 0,
    retry: (count, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) return false;
      return count < 2;
    },
  });

  const isDisabled =
    docsQuery.isError &&
    docsQuery.error instanceof ApiError &&
    (docsQuery.error.status === 404 || docsQuery.error.status === 503);

  const linkMut = useMutation({
    mutationFn: () =>
      linkPropertyDocument({
        record_type: recordType,
        record_id: recordId.trim(),
        doc_id: linkDocId.trim(),
        file_path: linkFilePath.trim(),
        crm_category: linkCategory.trim(),
        crm_description: linkDescription.trim(),
      }),
    onSuccess: () => {
      toast.success("Document linked");
      void queryClient.invalidateQueries({ queryKey: ["property", "documents"] });
      setLinkDocId("");
      setLinkFilePath("");
      setLinkCategory("");
      setLinkDescription("");
      setShowLinkForm(false);
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to link document"),
  });

  if (isDisabled) return <FeatureDisabled />;

  const docs = docsQuery.data?.items ?? [];
  const nextCursor = docsQuery.data?.cursor;

  return (
    <div className="p-6 space-y-6 max-w-4xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Property Documents</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Documents linked to property-domain records
        </p>
      </div>

      {/* Record selector */}
      <Card>
        <CardHeader>
          <CardTitle>Browse by Record</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="space-y-1 flex-1">
              <Label>Record Type</Label>
              <Select
                value={recordType}
                onValueChange={(v) => {
                  setRecordType(v as PropertyDocumentRecordType);
                  setCursor(undefined);
                }}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {RECORD_TYPES.map((t) => (
                    <SelectItem key={t} value={t} className="capitalize">{t}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-1 flex-1">
              <Label>Record ID</Label>
              <Input
                placeholder="Enter record ID..."
                value={recordId}
                onChange={(e) => {
                  setRecordId(e.target.value);
                  setCursor(undefined);
                }}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Document list */}
      {recordId.trim() && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                <FileText className="h-4 w-4 text-muted-foreground" />
                Linked Documents
              </CardTitle>
              <Button
                size="sm"
                variant="outline"
                onClick={() => setShowLinkForm((v) => !v)}
                className="gap-1"
              >
                <Plus className="h-4 w-4" />
                Link Document
              </Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">

            {/* Link form */}
            {showLinkForm && (
              <div className="border rounded-lg p-4 space-y-3 bg-muted/30">
                <p className="text-sm font-medium">Link a new document</p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <Label>Document ID *</Label>
                    <Input
                      placeholder="doc-id or file manager ID"
                      value={linkDocId}
                      onChange={(e) => setLinkDocId(e.target.value)}
                    />
                  </div>
                  <div className="space-y-1">
                    <Label>File Path</Label>
                    <Input
                      placeholder="/folder/filename.pdf"
                      value={linkFilePath}
                      onChange={(e) => setLinkFilePath(e.target.value)}
                    />
                  </div>
                  <div className="space-y-1">
                    <Label>Category</Label>
                    <Input
                      placeholder="e.g. lease, inspection"
                      value={linkCategory}
                      onChange={(e) => setLinkCategory(e.target.value)}
                    />
                  </div>
                  <div className="space-y-1">
                    <Label>Description</Label>
                    <Input
                      placeholder="Short description"
                      value={linkDescription}
                      onChange={(e) => setLinkDescription(e.target.value)}
                    />
                  </div>
                </div>
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    disabled={!linkDocId.trim() || linkMut.isPending}
                    onClick={() => linkMut.mutate()}
                  >
                    {linkMut.isPending && <Loader2 className="h-4 w-4 animate-spin mr-2" />}
                    Link
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => setShowLinkForm(false)}
                  >
                    Cancel
                  </Button>
                </div>
              </div>
            )}

            {/* Loading */}
            {docsQuery.isLoading && (
              <div className="space-y-2">
                {[1, 2, 3].map((i) => <Skeleton key={i} className="h-14 w-full" />)}
              </div>
            )}

            {/* Error (non-404) */}
            {docsQuery.isError && !isDisabled && (
              <p className="text-sm text-destructive py-4 text-center">
                Failed to load documents
              </p>
            )}

            {/* Empty */}
            {!docsQuery.isLoading && !docsQuery.isError && docs.length === 0 && (
              <p className="text-sm text-muted-foreground py-8 text-center">
                No documents linked to this record yet.
              </p>
            )}

            {/* Document rows */}
            {docs.length > 0 && (
              <div className="space-y-2">
                {docs.map((doc) => (
                  <div
                    key={doc.doc_id}
                    className="flex items-start justify-between rounded-lg border p-3 gap-3"
                  >
                    <div className="flex items-start gap-3 min-w-0">
                      <FileText className="h-5 w-5 text-muted-foreground shrink-0 mt-0.5" />
                      <div className="min-w-0">
                        <p className="text-sm font-medium truncate">{doc.file_path || doc.doc_id}</p>
                        <p className="text-xs text-muted-foreground font-mono">{doc.doc_id}</p>
                        {doc.crm_category && (
                          <Badge variant="secondary" className="mt-1 text-xs">
                            {doc.crm_category}
                          </Badge>
                        )}
                        {doc.crm_description && (
                          <p className="text-xs text-muted-foreground mt-1 truncate">
                            {doc.crm_description}
                          </p>
                        )}
                      </div>
                    </div>
                    <div className="flex flex-col items-end gap-1 shrink-0">
                      <span className="text-xs text-muted-foreground">{fmtTs(doc.linked_at)}</span>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7 text-destructive hover:text-destructive"
                        title="Unlink document"
                        onClick={() => {
                          unlinkPropertyDocument({
                            record_type: doc.record_type,
                            record_id: doc.record_id,
                            doc_id: doc.doc_id,
                          }).then(() => {
                            toast.success("Document unlinked");
                            void queryClient.invalidateQueries({ queryKey: ["property", "documents"] });
                          }).catch((err: unknown) =>
                            toast.error(err instanceof Error ? err.message : "Failed to unlink")
                          );
                        }}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Pagination */}
            {(docs.length > 0 || cursor) && (
              <div className="flex justify-between pt-2">
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={!cursor}
                  onClick={() => setCursor(undefined)}
                >
                  First page
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={!nextCursor}
                  onClick={() => setCursor(nextCursor ?? undefined)}
                >
                  Next page
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
