import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { toast } from "sonner";
import { ArrowLeft, Download, FileBox, Loader2, Save, Trash2 } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import {
  fileDownloadUrl,
  getFileInfo,
  updateCrmMetadata,
  type LinkedRecordType,
} from "@/api/endpoints/crmDocuments";
import { ApiError, withApiBase } from "@/api/client";
import {
  CrmDocumentsNotEnabled,
  RECORD_TYPE_OPTIONS,
  decodeDocPath,
  fmtBytes,
  fmtTs,
  isNotEnabled,
} from "./crmDocumentsShared";

export default function CrmDocumentDetailPage() {
  const params = useParams();
  const queryClient = useQueryClient();
  const docPath = params.docPath ? decodeDocPath(params.docPath) : "";

  // File-system info (size, content type, timestamps).
  const infoQuery = useQuery({
    queryKey: ["crm-documents", "info", docPath],
    queryFn: () => getFileInfo(docPath),
    enabled: !!docPath,
    retry: false,
  });

  // CRM metadata is not in /info; the only way to read it back is crm-search.
  // We can't search without a linked record, so we keep the editable fields in
  // local state and seed them from whatever metadata is available. The PATCH
  // response returns the authoritative metadata, which we then reflect.
  const [category, setCategory] = useState("");
  const [description, setDescription] = useState("");
  const [linkType, setLinkType] = useState<LinkedRecordType | "">("");
  const [linkId, setLinkId] = useState("");
  const [seeded, setSeeded] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  // Seed local fields once info has loaded (info confirms the node exists).
  useEffect(() => {
    if (infoQuery.data && !seeded) {
      setSeeded(true);
    }
  }, [infoQuery.data, seeded]);

  const saveMut = useMutation({
    mutationFn: async () => {
      const hasLink = linkType !== "" && linkId.trim() !== "";
      if ((linkType !== "") !== (linkId.trim() !== "")) {
        throw new ApiError(400, "Provide both a record type and ID, or neither.");
      }
      return updateCrmMetadata(docPath, {
        crm_category: category.trim() || null,
        crm_description: description.trim() || null,
        linked_record_type: hasLink ? (linkType as string) : null,
        linked_record_id: hasLink ? linkId.trim() : null,
      });
    },
    onSuccess: (meta) => {
      toast.success("Metadata saved");
      setCategory(meta.crm_category ?? "");
      setDescription(meta.crm_description ?? "");
      setLinkType((meta.linked_record_type as LinkedRecordType) ?? "");
      setLinkId(meta.linked_record_id ?? "");
      setLastUpdated(meta.crm_metadata_updated_at ?? null);
      // Invalidate any open search for the linked record so list views refresh.
      if (meta.linked_record_type && meta.linked_record_id) {
        queryClient.invalidateQueries({ queryKey: ["crm-documents", "search"] });
      }
    },
    onError: (err) => {
      toast.error(err instanceof ApiError ? err.detail : "Failed to save metadata");
    },
  });

  const clearLinkMut = useMutation({
    mutationFn: () =>
      updateCrmMetadata(docPath, {
        crm_category: category.trim() || null,
        crm_description: description.trim() || null,
        linked_record_type: null,
        linked_record_id: null,
      }),
    onSuccess: (meta) => {
      toast.success("Record link cleared");
      setLinkType("");
      setLinkId("");
      setLastUpdated(meta.crm_metadata_updated_at ?? null);
      queryClient.invalidateQueries({ queryKey: ["crm-documents", "search"] });
    },
    onError: (err) => {
      toast.error(err instanceof ApiError ? err.detail : "Failed to clear link");
    },
  });

  const status = (infoQuery.error as ApiError | undefined)?.status;

  if (!docPath) {
    return (
      <div className="space-y-6">
        <PageHeader title="Document" />
        <CrmDocumentsNotEnabled status={404} />
      </div>
    );
  }

  const info = infoQuery.data;
  const name = docPath.split("/").filter(Boolean).pop() || docPath;

  return (
    <div className="space-y-6">
      <PageHeader
        title={name}
        description={docPath}
        actions={
          <div className="flex gap-2">
            <Button asChild variant="outline">
              <Link to="/crm/documents">
                <ArrowLeft className="mr-2 h-4 w-4" />
                Back
              </Link>
            </Button>
            {info && (
              <Button asChild variant="outline">
                <a href={withApiBase(fileDownloadUrl(docPath))} target="_blank" rel="noreferrer">
                  <Download className="mr-2 h-4 w-4" />
                  Download
                </a>
              </Button>
            )}
          </div>
        }
      />

      {isNotEnabled(infoQuery.error) || status === 403 || status === 401 ? (
        <CrmDocumentsNotEnabled status={status} />
      ) : infoQuery.isLoading ? (
        <Skeleton className="h-40 w-full" />
      ) : infoQuery.isError ? (
        <Card className="border-dashed">
          <CardContent className="py-10 text-center text-muted-foreground">
            <FileBox className="mx-auto mb-2 h-8 w-8" />
            <p>Document not found.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-6 lg:grid-cols-3">
          <Card className="lg:col-span-1">
            <CardHeader>
              <CardTitle className="text-base">File details</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              <Row label="Name" value={info?.name ?? name} />
              <Row label="Type" value={info?.content_type ?? info?.type ?? "—"} />
              <Row label="Size" value={fmtBytes(info?.size)} />
              <Separator />
              <Row label="Uploaded" value={fmtTs(info?.upload_at ?? info?.created_at)} />
              <Row label="Updated" value={fmtTs(info?.updated_at)} />
              <Row label="Last download" value={fmtTs(info?.last_download_at)} />
              {info?.shared && <Badge variant="secondary">Shared</Badge>}
            </CardContent>
          </Card>

          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle className="text-base">CRM metadata</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-1">
                <Label htmlFor="d-category">Category</Label>
                <Input
                  id="d-category"
                  value={category}
                  onChange={(e) => setCategory(e.target.value)}
                  maxLength={200}
                  placeholder="e.g. Contracts"
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="d-description">Description</Label>
                <Textarea
                  id="d-description"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  maxLength={2000}
                  rows={3}
                />
                <p className="text-xs text-muted-foreground">{description.length}/2000</p>
              </div>
              <div className="flex flex-col gap-3 sm:flex-row">
                <div className="space-y-1">
                  <Label htmlFor="d-link-type">Linked record type</Label>
                  <Select
                    value={linkType}
                    onValueChange={(v) => setLinkType(v as LinkedRecordType)}
                  >
                    <SelectTrigger id="d-link-type" className="w-[180px]">
                      <SelectValue placeholder="None" />
                    </SelectTrigger>
                    <SelectContent>
                      {RECORD_TYPE_OPTIONS.map((t) => (
                        <SelectItem key={t} value={t}>
                          {t.charAt(0).toUpperCase() + t.slice(1)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex-1 space-y-1">
                  <Label htmlFor="d-link-id">Linked record ID</Label>
                  <Input
                    id="d-link-id"
                    value={linkId}
                    onChange={(e) => setLinkId(e.target.value)}
                    maxLength={200}
                    placeholder="e.g. contact_abc123"
                  />
                </div>
              </div>

              <p className="rounded-md bg-muted p-2 text-xs text-muted-foreground">
                Saving writes exactly the fields shown here — empty fields are cleared on the
                document. Last metadata update: {fmtTs(lastUpdated)}
              </p>

              <div className="flex flex-wrap justify-end gap-2">
                <Button
                  variant="outline"
                  onClick={() => clearLinkMut.mutate()}
                  disabled={clearLinkMut.isPending || (!linkType && !linkId)}
                >
                  <Trash2 className="mr-2 h-4 w-4" />
                  Clear link
                </Button>
                <Button onClick={() => saveMut.mutate()} disabled={saveMut.isPending}>
                  {saveMut.isPending ? (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  ) : (
                    <Save className="mr-2 h-4 w-4" />
                  )}
                  Save metadata
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="text-muted-foreground">{label}</span>
      <span className="text-right font-medium">{value}</span>
    </div>
  );
}
