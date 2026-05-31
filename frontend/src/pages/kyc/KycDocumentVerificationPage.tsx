import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Loader2, FileCheck2, AlertTriangle, RefreshCw } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  extractKycDocument,
  listMyKycDocuments,
  uploadKycDocument,
} from "@/api/endpoints/kycDocuments";
import type {
  KycDocumentConfidence,
  KycDocumentOut,
  KycDocumentType,
} from "@/api/types";

function confidenceVariant(c?: KycDocumentConfidence | null) {
  if (c === "high") return "default" as const;
  if (c === "medium") return "secondary" as const;
  return "destructive" as const;
}

function statusVariant(status: string) {
  if (status === "extracted" || status === "approved") return "default" as const;
  if (status === "pending") return "secondary" as const;
  return "destructive" as const;
}

function DocumentCard({ doc }: { doc: KycDocumentOut }) {
  const queryClient = useQueryClient();
  const reExtract = useMutation({
    mutationFn: () => extractKycDocument(doc.document_id),
    onSuccess: () => {
      toast.success("Re-extraction complete");
      queryClient.invalidateQueries({ queryKey: ["kyc-documents", "mine"] });
    },
    onError: () => toast.error("Re-extraction failed"),
  });

  return (
    <Card data-testid="kyc-document-card" data-document-id={doc.document_id}>
      <CardHeader className="flex flex-row items-start justify-between gap-2">
        <div>
          <CardTitle className="text-base">{doc.document_type}</CardTitle>
          <CardDescription className="break-all">{doc.file_name}</CardDescription>
        </div>
        <div className="flex flex-col items-end gap-1">
          <Badge variant={statusVariant(doc.status)} data-testid="kyc-doc-status">
            {doc.status}
          </Badge>
          {doc.overall_confidence && (
            <Badge
              variant={confidenceVariant(doc.overall_confidence)}
              data-testid="kyc-doc-confidence"
            >
              {doc.overall_confidence} confidence
            </Badge>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {doc.status === "failed" ? (
          <div className="flex items-center gap-2 text-sm text-destructive" data-testid="kyc-doc-failed">
            <AlertTriangle className="h-4 w-4" />
            Extraction failed for this document.
          </div>
        ) : doc.status === "pending" ? (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            Extracting document data...
          </div>
        ) : (
          <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
            {Object.entries(doc.extracted_fields).map(([k, v]) => (
              <div key={k} className="contents">
                <dt className="text-muted-foreground">{k.replace(/_/g, " ")}</dt>
                <dd className="font-medium">{v}</dd>
              </div>
            ))}
          </dl>
        )}
        <Button
          size="sm"
          variant="outline"
          onClick={() => reExtract.mutate()}
          disabled={reExtract.isPending}
          data-testid="kyc-doc-reextract"
        >
          {reExtract.isPending ? (
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
          ) : (
            <RefreshCw className="mr-2 h-4 w-4" />
          )}
          Re-extract
        </Button>
      </CardContent>
    </Card>
  );
}

export default function KycDocumentVerificationPage() {
  const queryClient = useQueryClient();
  const [docType, setDocType] = useState<KycDocumentType>("id_front");
  const [fileName, setFileName] = useState("");

  const { data, isLoading } = useQuery({
    queryKey: ["kyc-documents", "mine"],
    queryFn: () => listMyKycDocuments(),
  });

  const upload = useMutation({
    mutationFn: () =>
      uploadKycDocument({ document_type: docType, file_name: fileName.trim() }),
    onSuccess: () => {
      toast.success("Document uploaded");
      setFileName("");
      queryClient.invalidateQueries({ queryKey: ["kyc-documents", "mine"] });
    },
    onError: () => toast.error("Upload failed"),
  });

  const documents = data?.documents ?? [];

  return (
    <div className="mx-auto max-w-3xl space-y-6 p-4">
      <div className="flex items-center gap-2">
        <FileCheck2 className="h-6 w-6" />
        <h1 className="text-2xl font-semibold">Identity Document Verification</h1>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Upload identity document</CardTitle>
          <CardDescription>
            Upload the front and back of your government-issued ID. We extract and
            verify the details automatically.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3 sm:flex-row sm:items-end">
          <div className="flex-1 space-y-1">
            <label className="text-sm text-muted-foreground">Document type</label>
            <Select value={docType} onValueChange={(v) => setDocType(v as KycDocumentType)}>
              <SelectTrigger data-testid="kyc-doc-type-select">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="id_front">ID Front</SelectItem>
                <SelectItem value="id_back">ID Back</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="flex-1 space-y-1">
            <label className="text-sm text-muted-foreground">File name</label>
            <Input
              value={fileName}
              onChange={(e) => setFileName(e.target.value)}
              placeholder="my_id_front.jpg"
              data-testid="kyc-doc-filename"
            />
          </div>
          <Button
            onClick={() => upload.mutate()}
            disabled={!fileName.trim() || upload.isPending}
            data-testid="kyc-doc-upload"
          >
            {upload.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Upload
          </Button>
        </CardContent>
      </Card>

      <div className="space-y-3">
        <h2 className="text-lg font-medium">Your documents</h2>
        {isLoading ? (
          <p className="text-sm text-muted-foreground">Loading...</p>
        ) : documents.length === 0 ? (
          <p className="text-sm text-muted-foreground" data-testid="kyc-doc-empty">
            No documents uploaded yet.
          </p>
        ) : (
          documents.map((doc) => <DocumentCard key={doc.document_id} doc={doc} />)
        )}
      </div>
    </div>
  );
}
